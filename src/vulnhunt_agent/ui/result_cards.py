"""Per-step result cards. Visual summaries of each step's output."""
from __future__ import annotations

from datetime import datetime

import streamlit as st

from ..core.events import EventBus
from ..core.run_store import RunStore


def render_result_card(store: RunStore, step_name: str) -> None:
    data = store.load_step(step_name)
    if data is None:
        return
    renderer = _RENDERERS.get(step_name)
    if renderer:
        renderer(store, data)


# ---------- per-step renderers ----------

def _filter(store: RunStore, d: dict) -> None:
    kept = len(d.get("source_files", []))
    excluded = d.get("test_files_excluded", 0)
    total = kept + excluded
    exts = d.get("extensions", [])

    c1, c2, c3 = st.columns(3)
    c1.metric("Kept", f"{kept:,}", help="Source files passing filter")
    c2.metric("Excluded (tests)", f"{excluded:,}")
    c3.metric("Extensions", ", ".join(exts) if exts else "—")

    if total > 0:
        st.progress(kept / total, text=f"{kept}/{total} files kept")


def _source_snapshot(store: RunStore, d: dict) -> None:
    c1, c2 = st.columns(2)
    c1.metric("Files", f"{d.get('file_count', 0):,}")
    c2.metric("Bytes", f"{d.get('total_bytes', 0):,}")
    st.caption(f"Snapshot: `{d.get('snapshot_artifact', '—')}`")


def _rank(store: RunStore, d: dict) -> None:
    ranked = d.get("all") or []
    if not ranked:
        st.caption("no ranked files")
        return
    st.metric("Total ranked", f"{len(ranked):,}",
              help="LLM-scored files. Use File Selector to pick which to hunt.")


def _analysis_graph(store: RunStore, d: dict) -> None:
    summary = d.get("summary") or {}
    if d.get("language") != "c":
        st.caption("C graph analysis is not applicable to this environment.")
        return
    cols = st.columns(5)
    for col, key, label in zip(
        cols,
        ("nodes", "edges", "entrypoints", "critical_sinks", "slices"),
        ("Nodes", "Edges", "Entrypoints", "Critical sinks", "Slices"),
    ):
        col.metric(label, summary.get(key, 0))
    if summary.get("coverage_complete"):
        st.success(
            f"Coverage complete · {summary.get('selected_files', 0)} files planned"
        )
    else:
        st.error("Coverage plan has unresolved entrypoints or critical sinks.")


def _selector(store: RunStore, d: dict) -> None:
    files = d.get("files") or []
    selected = d.get("selected") or []
    has_scores = any(f.get("score", 0) > 0 for f in files)

    c1, c2, c3 = st.columns(3)
    c1.metric("📌 Selected", f"{len(selected):,}", help="Files queued for hunt")
    c2.metric("Candidates", f"{len(files):,}")
    c3.metric("Scored", "yes" if has_scores else "no",
              help="Run File Ranker to populate scores (optional).")
    coverage = d.get("coverage_selected") or []
    st.caption(
        f"Analysis coverage selected {len(coverage)} file(s)"
        + (" · complete" if d.get("coverage_complete") else " · incomplete")
    )


def _prepare(store: RunStore, d: dict) -> None:
    status = d.get("status", "?")
    image = d.get("image", "") or "—"
    env = d.get("environment", "") or "—"
    source = d.get("source", "auto")
    error = (d.get("error") or "").strip()
    install_log = d.get("install_log", [])
    verify_log = d.get("verify_log", [])

    if status == "ready":
        suffix = "  ·  custom image" if source == "custom" else ""
        st.markdown(f":green-background[**✓ ready**]  ·  `{image}`{suffix}")
    else:
        st.markdown(f":red-background[**✗ {status}**]")

    c1, c2, c3 = st.columns(3)
    c1.metric("Environment", env)
    c2.metric("Install commands", len(install_log))
    c3.metric("Verify commands", len(verify_log))

    if verify_log:
        st.caption("**Verified:**")
        for v in verify_log:
            ok = "✓" if v.get("exit") == 0 else "✗"
            st.caption(f"  {ok} `{v.get('cmd', '')}`")

    if error:
        st.error(error)


def _hunt(store: RunStore, d: dict) -> None:
    pass


def _verify(store: RunStore, d: dict) -> None:
    c1, c2, c3 = st.columns(3)
    c1.metric("Candidates", d.get("candidates", 0))
    c2.metric("Accepted recipes", d.get("recipes_accepted", 0))
    c3.metric("Strict reports", d.get("reports", 0))
    states = d.get("states") or {}
    if states:
        st.caption(" · ".join(f"{key}: {value}" for key, value in states.items()))
    errors = d.get("errors") or []
    if errors:
        st.warning(f"{len(errors)} candidate operation(s) need attention.")


# ---------- prepare settings (always shown) ----------

def render_prepare_settings(store: RunStore) -> None:
    """Mode toggle + custom-image input. Saved into config.json."""
    cfg = store.load_config() or {}
    current_mode = cfg.get("prepare_mode") or "auto"
    current_image = cfg.get("custom_image") or ""

    st.markdown(
        "- **Auto**: deterministic prepare (pip / mvn / npm / native build) from meta files.\n"
        "- **Use existing image**: skip install, reuse your prebuilt image. "
        "Handy when auto fails (multi-module Maven, custom builds). "
        "Image needs the language toolchain + ripgrep."
    )

    mode = st.radio(
        "Prepare mode",
        ["auto", "custom"],
        index=0 if current_mode == "auto" else 1,
        format_func=lambda m: "Auto (deterministic install)" if m == "auto" else "Use existing image",
        key="prepare_mode_radio",
        horizontal=True,
        label_visibility="collapsed",
    )

    image = current_image
    if mode == "custom":
        image = st.text_input(
            "Image tag",
            current_image,
            placeholder="e.g. my-org/jenkins-env:latest",
            key="prepare_custom_image",
            help="Tag must exist locally (`docker images` to list).",
        )
        with st.expander("How to build a custom image", expanded=False):
            st.markdown(
                "Image must contain: **language toolchain** (jdk/python/node/C), "
                "**ripgrep**, and **target deps already resolved offline** "
                "(hunt step has no network)."
            )
            tabs = st.tabs(["Python", "Java", "Node", "C"])
            with tabs[0]:
                st.code(
                    "FROM python:3.12-slim\n"
                    "RUN apt-get update \\\n"
                    " && apt-get install -y --no-install-recommends ripgrep \\\n"
                    " && rm -rf /var/lib/apt/lists/*\n"
                    "# Install target + its deps so hunt can import offline.\n"
                    "COPY <repo-path> /seed\n"
                    "RUN pip install --no-cache-dir -e /seed",
                    language="dockerfile",
                )
                st.code("docker build -t my-py-env:latest -f Dockerfile.py .",
                        language="bash")
            with tabs[1]:
                st.code(
                    "FROM eclipse-temurin:21-jdk\n"
                    "RUN apt-get update \\\n"
                    " && apt-get install -y --no-install-recommends maven git ripgrep \\\n"
                    " && rm -rf /var/lib/apt/lists/*\n"
                    "# Pre-resolve deps so hunt can compile PoCs offline.\n"
                    "COPY <repo-path> /seed\n"
                    "RUN cd /seed && mvn -B -DskipTests -Denforcer.skip install -pl core -am || true\n"
                    "RUN rm -rf /seed   # source is mounted at /code at hunt time",
                    language="dockerfile",
                )
                st.code("docker build -t my-jenkins-env:latest -f Dockerfile.jenkins .",
                        language="bash")
            with tabs[2]:
                st.code(
                    "FROM node:22-slim\n"
                    "RUN apt-get update \\\n"
                    " && apt-get install -y --no-install-recommends ripgrep \\\n"
                    " && rm -rf /var/lib/apt/lists/*\n"
                    "# Install node_modules so hunt can require() offline.\n"
                    "COPY <repo-path> /seed\n"
                    "RUN cd /seed && npm ci || npm install\n"
                    "# Keep node_modules; source is mounted at /code at hunt time.\n"
                    "RUN mv /seed/node_modules /opt/node_modules && rm -rf /seed",
                    language="dockerfile",
                )
                st.code("docker build -t my-node-env:latest -f Dockerfile.node .",
                        language="bash")
                st.caption(
                    "After hunt mounts your repo at /code, point NODE_PATH to "
                    "/opt/node_modules or symlink it into /code."
                )
            with tabs[3]:
                st.code(
                    "FROM gcc:13-bookworm\n"
                    "RUN apt-get update \\\n"
                    " && apt-get install -y --no-install-recommends \\\n"
                    "      ripgrep cmake ninja-build meson flex bison \\\n"
                    "      autoconf automake libtool pkg-config \\\n"
                    " && rm -rf /var/lib/apt/lists/*\n"
                    "# Bake sanitizer-built target artifacts into the image.\n"
                    "COPY <repo-path> /code\n"
                    "RUN cmake -S /code -B /opt/vulnhunt/build \\\n"
                    "      -DBUILD_SHARED_LIBS=OFF \\\n"
                    "      -DCMAKE_C_FLAGS='-O1 -g -fno-omit-frame-pointer "
                    "-fsanitize=address,undefined' \\\n"
                    " && cmake --build /opt/vulnhunt/build --parallel 2",
                    language="dockerfile",
                )
                st.code("docker build -t my-c-asan-env:latest -f Dockerfile.c .",
                        language="bash")

    if mode != current_mode or image != current_image:
        cfg["prepare_mode"] = mode
        cfg["custom_image"] = image
        store.save_config(cfg)


# ---------- live progress (running steps) ----------

def render_prepare_progress(store: RunStore) -> None:
    """Live view while sandbox_prepare runs in the background."""
    st.divider()
    c1, c2 = st.columns([5, 1])
    c1.markdown("**Progress**")
    if c2.button("🔄 Refresh", key="prepare_refresh", use_container_width=True):
        st.rerun()

    events = _prepare_events(store)
    if not events:
        st.caption("waiting for first event — click Refresh in a moment")
        return

    started = _ts(events[0])
    elapsed = _elapsed_seconds(started)
    st.caption(f"⏱ elapsed: {elapsed}")

    current = _current_install_cmd(events)
    if current:
        st.markdown(f"**▶ Running:** `{current[:140]}`")

    completed = _completed_install_cmds(events)
    if completed:
        st.caption("**Completed install steps:**")
        for cmd, dur in completed:
            st.caption(f"  ✓ `{cmd[:120]}`  ·  {dur}")


def _prepare_events(store: RunStore) -> list[dict]:
    bus = EventBus(store.dir / "events.jsonl")
    all_events = bus.read_all()
    last_start = None
    for i, e in enumerate(all_events):
        if e.get("type") == "step_start" and e.get("step") == "sandbox_prepare":
            last_start = i
    if last_start is None:
        return []
    return all_events[last_start:]


def _current_install_cmd(events: list[dict]) -> str:
    """The most recent prepare_install_cmd / prepare_verify_cmd that doesn't have a step_done after it."""
    for e in reversed(events):
        if e.get("type") == "step_done":
            return ""
        if e.get("type") in ("prepare_install_cmd", "prepare_verify_cmd"):
            return e.get("cmd", "")
    return ""


def _completed_install_cmds(events: list[dict]) -> list[tuple[str, str]]:
    """Pairs of (cmd, duration_str) for install/verify cmds that have a *next* cmd or step_done after them."""
    out: list[tuple[str, str]] = []
    starts = [(i, e) for i, e in enumerate(events)
              if e.get("type") in ("prepare_install_cmd", "prepare_verify_cmd")]
    for idx, (i, e) in enumerate(starts):
        next_ts = None
        if idx + 1 < len(starts):
            next_ts = _ts(starts[idx + 1][1])
        else:
            for after in events[i + 1:]:
                if after.get("type") == "step_done":
                    next_ts = _ts(after)
                    break
        if next_ts is None:
            continue
        dur = _duration(_ts(e), next_ts)
        out.append((e.get("cmd", ""), dur))
    return out


def _ts(event: dict) -> datetime:
    return datetime.fromisoformat(event["ts"])


def _elapsed_seconds(start: datetime) -> str:
    return _duration(start, datetime.now())


def _duration(start: datetime, end: datetime) -> str:
    sec = int((end - start).total_seconds())
    if sec < 60:
        return f"{sec}s"
    return f"{sec // 60}m {sec % 60}s"


_RENDERERS = {
    "source_snapshot": _source_snapshot,
    "filtered_files":  _filter,
    "analysis_graph":  _analysis_graph,
    "ranked_files":    _rank,
    "file_selector":   _selector,
    "sandbox_prepare": _prepare,
    "hunt":            _hunt,
    "verify":          _verify,
}
