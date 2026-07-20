"""Step: SandboxPrepare — build a project-specific sandbox image.

Deterministic: install/verify commands picked by environment + meta files.
No LLM. Raises if no recognised meta file found for the language.

The host repository is normalized into an immutable tar snapshot and streamed
into /code. Build scripts can mutate only the disposable build container.
Hunter containers start from the committed image with a read-only root.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from ..core.events import EventBus
from ..core.run_store import RunStore
from ..sandbox import ContainerExecutor, base_image_for, language_of
from .registry import Step, register


INSTALL_TIMEOUT = 1800   # 30 min — large Java repos need it
VERIFY_TIMEOUT = 60

_C_SANITIZER_FLAGS = (
    "-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined"
)


def _ripgrep_install_cmd() -> str:
    return (
        "if ! command -v rg >/dev/null 2>&1; then "
        "apt-get update && apt-get install -y --no-install-recommends ripgrep "
        "&& rm -rf /var/lib/apt/lists/*; fi"
    )


def _c_install_cmds(repo: Path) -> list[str]:
    toolchain = (
        "apt-get update && apt-get install -y --no-install-recommends "
        "cmake ninja-build meson flex bison autoconf automake libtool pkg-config "
        "&& rm -rf /var/lib/apt/lists/*"
    )
    flags = _C_SANITIZER_FLAGS

    if (repo / "CMakeLists.txt").exists():
        return [
            toolchain,
            "cmake -S /code -B /opt/vulnhunt/build "
            "-DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF "
            f"-DCMAKE_C_FLAGS='{flags}'",
            "cmake --build /opt/vulnhunt/build --parallel 2",
        ]
    if (repo / "meson.build").exists():
        return [
            toolchain,
            "meson setup /opt/vulnhunt/build /code "
            "--buildtype=debug --default-library=static "
            f"-Dc_args='{flags}'",
            "meson compile -C /opt/vulnhunt/build -j 2",
        ]
    if (repo / "configure").exists() or (repo / "configure.ac").exists():
        bootstrap = (
            "if [ ! -x /code/configure ]; then cd /code && autoreconf -fi; fi; "
            "mkdir -p /opt/vulnhunt/build && cd /opt/vulnhunt/build && "
            f"CFLAGS='{flags}' /code/configure --disable-shared --enable-static"
        )
        return [toolchain, bootstrap, "make -C /opt/vulnhunt/build -j2"]
    if (repo / "Makefile").exists() or (repo / "GNUmakefile").exists():
        return [
            toolchain,
            f"make -C /code -j2 CFLAGS='{flags}'",
        ]
    raise RuntimeError(
        "c repo has no CMakeLists.txt / meson.build / configure(.ac) / Makefile"
    )


def _install_cmds(repo: Path, env: str) -> list[str]:
    lang = language_of(env)
    if lang == "python":
        # Some build backends (hatch + uv-dynamic-versioning, setuptools-scm)
        # need git to read version from tags — install git unconditionally.
        git_cmd = (
            "if ! command -v git >/dev/null 2>&1; then "
            "apt-get update && apt-get install -y --no-install-recommends git "
            "&& rm -rf /var/lib/apt/lists/*; fi"
        )
        if (repo / "pyproject.toml").exists() or (repo / "setup.py").exists():
            return [git_cmd, "pip install --no-cache-dir -e /code"]
        if (repo / "requirements.txt").exists():
            return [git_cmd, "pip install --no-cache-dir -r /code/requirements.txt"]
        raise RuntimeError(
            "python repo has no pyproject.toml / setup.py / requirements.txt"
        )
    if lang == "java":
        if (repo / "pom.xml").exists():
            # Common opt-outs that don't change build artifacts but prevent
            # enforcer / docs / signing failures unrelated to security analysis:
            mvn_opts = (
                "-DskipTests "
                "-Denforcer.skip=true "
                "-Dcheckstyle.skip=true "
                "-Dspotbugs.skip=true "
                "-Dmaven.javadoc.skip=true "
                "-Dgpg.skip=true"
            )
            return [
                # git is needed by buildnumber-maven-plugin (jenkins etc).
                "apt-get update && apt-get install -y --no-install-recommends maven git "
                "&& rm -rf /var/lib/apt/lists/*",
                # `install` builds every module and registers them in the local
                # ~/.m2 repo so siblings see each other (multi-module repos like
                # jenkins fail otherwise on dependency:copy-dependencies).
                f"mvn -f /code -B {mvn_opts} install",
                # Now collect transitive jars into /workspace/lib for hunters.
                f"mvn -f /code -B -q {mvn_opts} dependency:copy-dependencies "
                "-DoutputDirectory=/workspace/lib",
            ]
        raise RuntimeError("java repo has no pom.xml (Gradle not yet supported)")
    if lang == "node":
        if (repo / "package-lock.json").exists():
            return ["npm ci --prefix /code"]
        if (repo / "package.json").exists():
            return ["npm install --prefix /code"]
        raise RuntimeError("node repo has no package.json")
    if lang == "c":
        return _c_install_cmds(repo)
    raise RuntimeError(f"unsupported language: {lang}")


def _verify_cmds(env: str) -> list[str]:
    return {
        "python": ["python --version"],
        "java":   ["javac -version"],
        "node":   ["node --version"],
        "c":      ["cc --version"],
    }[language_of(env)]


def _image_tag(repo: Path) -> str:
    h = hashlib.sha1(str(repo.resolve()).encode()).hexdigest()[:8]
    return f"scanner/prepared:{repo.name}-{h}"


async def run_prepare(store: RunStore, bus: EventBus) -> None:
    cfg = store.load_config() or {}
    repo = Path(cfg["repo_path"])
    env = cfg["environment"]

    bus.emit("step_start", step="sandbox_prepare", repo=str(repo), env=env)

    if (cfg.get("prepare_mode") or "auto") == "custom":
        custom = (cfg.get("custom_image") or "").strip()
        if not custom:
            raise RuntimeError("prepare_mode=custom but custom_image is empty")
        store.save_step("sandbox_prepare", {
            "status": "ready",
            "image": custom,
            "environment": env,
            "install_log": [],
            "verify_log": [],
            "error": "",
            "source": "custom",
        })
        bus.emit("step_done", step="sandbox_prepare", status="ready",
                 image=custom, source="custom")
        return

    install_cmds = [_ripgrep_install_cmd()] + _install_cmds(repo, env)
    verify_cmds = _verify_cmds(env)
    bus.emit("prepare_plan", install=len(install_cmds), verify=len(verify_cmds))

    base = base_image_for(env)
    sandbox = ContainerExecutor(
        repo=repo, image=base,
        network="bridge", code_writable=True,
    )
    image_tag = _image_tag(repo)
    install_log: list[dict] = []
    verify_log: list[dict] = []
    status = "ready"
    error = ""

    try:
        await sandbox.start()
        bus.emit("prepare_container_up", name=sandbox.name)

        for cmd in install_cmds:
            bus.emit("prepare_install_cmd", cmd=cmd)
            r = await sandbox.exec(cmd, timeout=INSTALL_TIMEOUT)
            install_log.append({"cmd": cmd, "exit": r.exit_code,
                                "stdout": r.stdout[-200_000:], "stderr": r.stderr[-200_000:]})
            if r.exit_code != 0:
                status = "install_failed"
                error = f"install cmd failed: {cmd}"
                break

        if status == "ready":
            for cmd in verify_cmds:
                bus.emit("prepare_verify_cmd", cmd=cmd)
                r = await sandbox.exec(cmd, timeout=VERIFY_TIMEOUT)
                verify_log.append({"cmd": cmd, "exit": r.exit_code,
                                   "stdout": r.stdout[-2000:], "stderr": r.stderr[-2000:]})
                if r.exit_code != 0:
                    status = "verify_failed"
                    error = f"verify cmd failed: {cmd}"
                    break

        if status == "ready":
            bus.emit("prepare_commit", image=image_tag)
            await sandbox.commit(image_tag)
    finally:
        await sandbox.stop()

    result = {
        "status": status,
        "image": image_tag if status == "ready" else "",
        "environment": env,
        "install_log": install_log,
        "verify_log": verify_log,
        "error": error,
    }
    store.save_step("sandbox_prepare", result)
    bus.emit("step_done", step="sandbox_prepare", status=status, image=result["image"])


register(Step(
    name="sandbox_prepare",
    title="5. Sandbox Prepare",
    fn=run_prepare,
    depends_on=[],
))
