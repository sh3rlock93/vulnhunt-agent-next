"""Step: SandboxPrepare — build a project-specific sandbox image.

Deterministic: install/verify commands picked by environment + meta files.
No LLM. Raises if no recognised meta file found for the language.

The host repository is normalized into an immutable tar snapshot and streamed
into /code. Build scripts can mutate only the disposable build container.
Hunter containers start from the committed image with a read-only root.
"""
from __future__ import annotations

import hashlib
import shlex
from pathlib import Path

from ..core.events import EventBus
from ..core.run_store import RunStore
from ..core.v2_run import advance_run, source_snapshot_path
from ..domain.states import RunState
from ..sandbox import ContainerExecutor, base_image_for, language_of
from ..sandbox.prepared_build import (
    C_TOOLCHAIN_COMMAND,
    PACKAGE_LOCK_PATH,
    RIPGREP_INSTALL_COMMAND,
    PreparedBuildFailureCode,
    PreparedBuildPlan,
    PreparedBuildReceipt,
    PreparedBuildVerificationError,
    PreparedCommandResult,
    artifact_inventory_command,
    create_c_prepared_build_plan,
    parse_artifact_inventory,
    parse_package_lock,
    select_c_build,
)
from ..sandbox.base import ExecResult
from .registry import Step, register


INSTALL_TIMEOUT = 1800   # 30 min — large Java repos need it
VERIFY_TIMEOUT = 60
ARTIFACT_TIMEOUT = 300

def _ripgrep_install_cmd() -> str:
    return RIPGREP_INSTALL_COMMAND


def _c_install_cmds(repo: Path) -> list[str]:
    selection = select_c_build(repo)
    if not selection.supported:
        raise RuntimeError(
            "c repo has no CMakeLists.txt / meson.build / configure(.ac) / Makefile "
            f"({selection.unsupported_reason.value})"
        )
    return [C_TOOLCHAIN_COMMAND, *selection.install_commands]


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
    source_archive = source_snapshot_path(store)
    advance_run(store, RunState.BUILDING, reason="sandbox preparation started")

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
        advance_run(
            store,
            RunState.HUNTING,
            reason="custom sandbox image registered",
        )
        bus.emit("step_done", step="sandbox_prepare", status="ready",
                 image=custom, source="custom")
        return

    base = base_image_for(env)
    if language_of(env) == "c":
        snapshot_digest = "sha256:" + _sha256_file(source_archive)
        build_plan = create_c_prepared_build_plan(
            repo,
            source_snapshot_sha256=snapshot_digest,
            base_image=base,
        )
        store.save_step("prepared_build_plan", build_plan.to_dict())
        if not build_plan.supported:
            raise RuntimeError(
                "c repo has no CMakeLists.txt / meson.build / configure(.ac) / Makefile "
                f"({build_plan.unsupported_reason.value})"
            )
        install_cmds = list(build_plan.support_commands + build_plan.install_commands)
        verify_cmds = list(build_plan.verify_commands)
        image_tag = build_plan.image_tag
        bus.emit(
            "prepare_plan",
            install=len(install_cmds),
            verify=len(verify_cmds),
            policy=build_plan.policy_version,
            plan_sha256=build_plan.plan_sha256,
            build_system=build_plan.build_system.value,
        )
        await _run_verified_c_prepare(
            store=store,
            bus=bus,
            repo=repo,
            env=env,
            base=base,
            source_archive=source_archive,
            build_plan=build_plan,
        )
        return
    else:
        build_plan = None
        install_cmds = [_ripgrep_install_cmd()] + _install_cmds(repo, env)
        verify_cmds = _verify_cmds(env)
        image_tag = _image_tag(repo)
        bus.emit("prepare_plan", install=len(install_cmds), verify=len(verify_cmds))

    sandbox = ContainerExecutor(
        repo=repo, image=base,
        network="bridge", code_writable=True,
        source_archive=source_archive,
    )
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
        "build_plan_sha256": build_plan.plan_sha256 if build_plan else "",
    }
    store.save_step("sandbox_prepare", result)
    advance_run(
        store,
        RunState.HUNTING,
        reason=f"sandbox preparation finished with status {status}",
    )
    bus.emit("step_done", step="sandbox_prepare", status=status, image=result["image"])


async def _run_verified_c_prepare(
    *,
    store: RunStore,
    bus: EventBus,
    repo: Path,
    env: str,
    base: str,
    source_archive: Path,
    build_plan: PreparedBuildPlan,
) -> None:
    sandbox = ContainerExecutor(
        repo=repo,
        image=base,
        network="bridge",
        code_writable=True,
        source_archive=source_archive,
    )
    command_results: list[PreparedCommandResult] = []
    test_results: list[PreparedCommandResult] = []
    install_log: list[dict] = []
    test_log: list[dict] = []
    verify_log: list[dict] = []
    final_digest = ""

    try:
        try:
            base_digest = await sandbox.image_digest()
        except RuntimeError as exc:
            raise PreparedBuildVerificationError(
                PreparedBuildFailureCode.IMAGE_DIGEST_UNAVAILABLE,
                f"base image digest unavailable: {exc}",
            ) from exc
        await sandbox.start()
        bus.emit("prepare_container_up", name=sandbox.name)

        for command in build_plan.support_commands:
            result = await _execute_prepared_command(
                sandbox, command, phase="package_install", timeout=INSTALL_TIMEOUT
            )
            command_results.append(result)
            install_log.append(_legacy_log(command, result, limit=200_000))
            if result.exit_code != 0:
                raise PreparedBuildVerificationError(
                    PreparedBuildFailureCode.PACKAGE_INSTALL_FAILED,
                    f"pinned package installation failed: {command}",
                )

        try:
            await sandbox.disconnect_network()
        except RuntimeError as exc:
            raise PreparedBuildVerificationError(
                PreparedBuildFailureCode.NETWORK_ISOLATION_FAILED,
                f"could not isolate preparation network: {exc}",
            ) from exc
        bus.emit("prepare_network_isolated", before="build")

        lock_result = await sandbox.exec(
            f"cat -- {shlex.quote(PACKAGE_LOCK_PATH)}", timeout=VERIFY_TIMEOUT
        )
        if lock_result.exit_code != 0:
            raise PreparedBuildVerificationError(
                PreparedBuildFailureCode.PACKAGE_LOCK_MISSING,
                "pinned package lock is not readable after installation",
            )
        package_entries = parse_package_lock(lock_result.stdout)
        package_lock_sha256 = _sha256_text(lock_result.stdout)

        for command in build_plan.install_commands:
            bus.emit("prepare_install_cmd", cmd=command, network="none")
            result = await _execute_prepared_command(
                sandbox, command, phase="build", timeout=INSTALL_TIMEOUT
            )
            command_results.append(result)
            install_log.append(_legacy_log(command, result, limit=200_000))
            if result.exit_code != 0:
                raise PreparedBuildVerificationError(
                    PreparedBuildFailureCode.BUILD_COMMAND_FAILED,
                    f"offline build command failed: {command}",
                )

        for command in build_plan.test_commands:
            bus.emit("prepare_test_cmd", cmd=command, network="none")
            result = await _execute_prepared_command(
                sandbox,
                command,
                phase="test",
                timeout=INSTALL_TIMEOUT,
                infer_test_outcome=True,
            )
            test_results.append(result)
            test_log.append(_legacy_log(command, result, limit=200_000))
            if result.exit_code != 0:
                raise PreparedBuildVerificationError(
                    PreparedBuildFailureCode.TEST_COMMAND_FAILED,
                    f"offline test command failed: {command}",
                )

        compiler_version = ""
        for command in build_plan.verify_commands:
            bus.emit("prepare_verify_cmd", cmd=command, network="none")
            result = await _execute_prepared_command(
                sandbox, command, phase="verify", timeout=VERIFY_TIMEOUT
            )
            command_results.append(result)
            verify_log.append(_legacy_log(command, result, limit=2_000))
            if result.exit_code != 0:
                raise PreparedBuildVerificationError(
                    PreparedBuildFailureCode.VERIFY_COMMAND_FAILED,
                    f"offline verification command failed: {command}",
                )
            if command == "cc --version":
                compiler_version = (result.stdout or result.stderr).strip()
        if not compiler_version:
            raise PreparedBuildVerificationError(
                PreparedBuildFailureCode.VERIFY_COMMAND_FAILED,
                "compiler verification produced no version provenance",
            )

        for root in build_plan.expected_artifact_roots:
            root_command = f"test -d {shlex.quote(root)}"
            root_result = await _execute_prepared_command(
                sandbox, root_command, phase="artifact_verification", timeout=VERIFY_TIMEOUT
            )
            command_results.append(root_result)
            if root_result.exit_code != 0:
                raise PreparedBuildVerificationError(
                    PreparedBuildFailureCode.ARTIFACT_ROOT_MISSING,
                    f"expected artifact root is missing: {root}",
                )

        inventory_command = artifact_inventory_command(
            build_plan.expected_artifact_roots
        )
        inventory_result = await sandbox.exec(inventory_command, timeout=ARTIFACT_TIMEOUT)
        command_results.append(_command_result(
            phase="artifact_verification",
            command=inventory_command,
            result=inventory_result,
        ))
        if inventory_result.exit_code != 0:
            raise PreparedBuildVerificationError(
                PreparedBuildFailureCode.ARTIFACT_MISSING,
                "native artifact inventory command failed",
            )
        artifacts = parse_artifact_inventory(inventory_result.stdout)

        bus.emit("prepare_commit", image=build_plan.image_tag, network="none")
        try:
            final_digest = await sandbox.commit(build_plan.image_tag)
        except RuntimeError as exc:
            raise PreparedBuildVerificationError(
                PreparedBuildFailureCode.IMAGE_DIGEST_UNAVAILABLE,
                f"final image digest unavailable: {exc}",
            ) from exc

        receipt = PreparedBuildReceipt(
            source_snapshot_sha256=build_plan.source_snapshot_sha256,
            plan_sha256=build_plan.plan_sha256,
            build_system=build_plan.build_system,
            base_image=base,
            base_image_digest=base_digest,
            final_image=build_plan.image_tag,
            final_image_digest=final_digest,
            package_lock_entries=package_entries,
            package_lock_sha256=package_lock_sha256,
            compiler_version=compiler_version,
            command_results=tuple(command_results),
            test_results=tuple(test_results),
            artifacts=artifacts,
        )
        store.save_step("prepared_build_receipt", receipt.to_dict())
        prepare_result = {
            "status": "ready",
            "image": build_plan.image_tag,
            "image_digest": final_digest,
            "environment": env,
            "install_log": install_log,
            "test_log": test_log,
            "verify_log": verify_log,
            "error": "",
            "error_code": "",
            "build_plan_sha256": build_plan.plan_sha256,
            "build_receipt_sha256": receipt.receipt_sha256,
            "build_equivalence_sha256": receipt.equivalence_sha256,
        }
        store.save_step("sandbox_prepare", prepare_result)
        advance_run(
            store,
            RunState.HUNTING,
            reason="verified native sandbox preparation finished",
        )
        bus.emit(
            "step_done",
            step="sandbox_prepare",
            status="ready",
            image=prepare_result["image"],
            receipt_sha256=receipt.receipt_sha256,
        )
    except PreparedBuildVerificationError as exc:
        store.save_step("sandbox_prepare", {
            "status": "failed",
            "image": "",
            "image_digest": final_digest,
            "environment": env,
            "install_log": install_log,
            "test_log": test_log,
            "verify_log": verify_log,
            "error": str(exc),
            "error_code": exc.code.value,
            "build_plan_sha256": build_plan.plan_sha256,
            "build_receipt_sha256": "",
            "build_equivalence_sha256": "",
        })
        bus.emit(
            "step_done",
            step="sandbox_prepare",
            status="failed",
            error_code=exc.code.value,
        )
        raise
    finally:
        await sandbox.stop()


async def _execute_prepared_command(
    sandbox: ContainerExecutor,
    command: str,
    *,
    phase: str,
    timeout: int,
    infer_test_outcome: bool = False,
) -> PreparedCommandResult:
    result = await sandbox.exec(command, timeout=timeout)
    outcome = "passed"
    if infer_test_outcome and "VULNHUNT_TESTS_NOT_DECLARED" in result.stdout:
        outcome = "not_declared"
    return _command_result(
        phase=phase,
        command=command,
        result=result,
        outcome=outcome,
    )


def _command_result(
    *,
    phase: str,
    command: str,
    result: ExecResult,
    outcome: str = "passed",
) -> PreparedCommandResult:
    return PreparedCommandResult(
        phase=phase,
        command=command,
        exit_code=result.exit_code,
        timed_out=result.timed_out,
        duration_ms=result.duration_ms,
        stdout_sha256=_sha256_text(result.stdout),
        stderr_sha256=_sha256_text(result.stderr),
        outcome=outcome,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def _legacy_log(command: str, result: PreparedCommandResult, *, limit: int) -> dict:
    return {
        "cmd": command,
        "exit": result.exit_code,
        "stdout": result.stdout[-limit:],
        "stderr": result.stderr[-limit:],
    }


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


register(Step(
    name="sandbox_prepare",
    title="6. Sandbox Prepare",
    fn=run_prepare,
    depends_on=["source_snapshot"],
))
