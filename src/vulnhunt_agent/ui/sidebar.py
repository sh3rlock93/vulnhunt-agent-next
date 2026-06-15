"""Sidebar: pick or create a run, then edit its settings inline."""
from __future__ import annotations

import json

import streamlit as st

from ..core import settings as app_settings
from ..core.run_store import RUNS_ROOT, RunStore, new_run_id
from ..repo import fetch as repo_fetch
from ..sandbox import ENVIRONMENTS


def sidebar() -> RunStore | None:
    """Render sidebar; return the selected run's store, or None for <new run>."""
    st.sidebar.header("Run")

    runs = RunStore.list_runs()
    choices = ["<new run>"] + runs
    url_run = st.query_params.get("run")
    default_idx = choices.index(url_run) if url_run in runs else 0

    selected = st.sidebar.selectbox(
        "Select run", choices, index=default_idx,
        format_func=lambda r: "<new run>" if r == "<new run>" else _label(r),
    )

    if selected == "<new run>":
        st.query_params.clear()
        return _new_run_form()

    if st.query_params.get("run") != selected:
        st.query_params["run"] = selected

    store = RunStore(RUNS_ROOT / selected)
    _settings_form(store)
    return store


def default_config() -> dict:
    return {
        "model_id": app_settings.DEFAULT_MODEL.model_id,           # hunter
        "model_id_reviewer": app_settings.DEFAULT_MODEL.model_id,  # cluster + verdict + report
        "model_id_ranker": app_settings.DEFAULT_MODEL.model_id,    # ranker only
        "environment": ENVIRONMENTS[0],
        "repo_source": "",
        "repo_path": "",
        "note": "",
        "max_tokens": app_settings.MAX_TOKENS,
        "max_hunters_parallel": 3,
        "hunter_max_iterations": 100,
    }


def _label(run_id: str) -> str:
    cfg_path = RUNS_ROOT / run_id / "config.json"
    if not cfg_path.exists():
        return run_id
    try:
        note = json.loads(cfg_path.read_text()).get("note", "").strip()
    except Exception:
        return run_id
    return f"{run_id}  ·  {note}" if note else run_id


def _new_run_form() -> None:
    new_id = st.sidebar.text_input("New run ID", value=new_run_id())
    new_note = st.sidebar.text_input(
        "Note (label)", value="", help="Free-form label, e.g. 'litellm kimi'",
    )
    if st.sidebar.button("Create"):
        store = RunStore.create(new_id)
        store.save_config({**default_config(), "note": new_note})
        st.query_params["run"] = new_id
        st.rerun()
    return None


# ---------- settings (sidebar) ----------

def _settings_form(store: RunStore) -> None:
    st.sidebar.divider()
    st.sidebar.header("Settings")

    cfg = {**default_config(), **(store.load_config() or {})}

    repo_source = st.sidebar.text_input(
        "Repo (git URL or local path)", cfg["repo_source"],
        help="https://github.com/foo/bar  or  /abs/path. Resolved on Save.",
    )

    env_default = cfg.get("environment") or ENVIRONMENTS[0]
    env_idx = ENVIRONMENTS.index(env_default) if env_default in ENVIRONMENTS else 0
    environment = st.sidebar.selectbox(
        "Environment", ENVIRONMENTS, index=env_idx,
        help="Language + runtime version. Picks base Docker image and install plan.",
    )

    model_id_ranker = _model_picker(
        "Model (Ranker)",
        cfg.get("model_id_ranker") or cfg["model_id"],
        "model_ranker",
        help="Scores files 1..5 for security relevance.",
    )
    model_id = _model_picker(
        "Model (Hunter)", cfg["model_id"], "model",
        help="Used by hunter agents — finds vulnerabilities. The expensive step.",
    )
    model_id_reviewer = _model_picker(
        "Model (Reviewer)",
        cfg.get("model_id_reviewer") or cfg["model_id"],
        "model_reviewer",
        help="Clusters similar findings, decides verdicts with CVSS, writes the report.",
    )

    max_par = st.sidebar.number_input(
        "Parallel hunters", 1, 20, cfg["max_hunters_parallel"],
    )
    max_iter = st.sidebar.number_input(
        "Max iter / hunter", 5, 500, cfg["hunter_max_iterations"],
    )

    new_cfg = {
        **cfg,
        "environment": environment,
        "model_id": model_id,
        "model_id_reviewer": model_id_reviewer,
        "model_id_ranker": model_id_ranker,
        "repo_source": repo_source,
        "max_hunters_parallel": int(max_par),
        "hunter_max_iterations": int(max_iter),
    }

    if st.sidebar.button("Save", type="primary", use_container_width=True):
        _save(store, new_cfg)

    if cfg.get("repo_path"):
        st.sidebar.success(f"📁 `{cfg['repo_path']}`")
    elif cfg.get("repo_source"):
        st.sidebar.warning("⚠️ Not resolved yet — click Save")


def _save(store: RunStore, cfg: dict) -> None:
    """Save config; resolve repo source if set so 'Save' = 'save + prepare'."""
    if cfg.get("repo_source"):
        try:
            with st.spinner("resolving repo..."):
                local = repo_fetch.resolve(cfg["repo_source"])
            cfg["repo_path"] = str(local)
        except Exception as e:
            st.sidebar.error(f"❌ Repo resolve failed: {e}")
            return
    store.save_config(cfg)
    st.rerun()


def _model_picker(label: str, current_id: str, key: str, help: str = "") -> str:
    lbls = [m.label for m in app_settings.MODELS]
    current = app_settings.by_id(current_id)
    if current is None and current_id:
        opts = [f"custom ({current_id})"] + lbls
        idx = 0
    elif current is not None:
        opts = lbls
        idx = opts.index(current.label)
    else:
        opts = lbls
        idx = 0

    picked = st.sidebar.selectbox(label, opts, index=idx, key=key, help=help or None)
    if picked.startswith("custom ("):
        return current_id
    return app_settings.by_label(picked).model_id
