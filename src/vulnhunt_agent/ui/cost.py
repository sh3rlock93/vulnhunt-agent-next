"""Token usage and cost summary across pipeline steps + per-hunter dirs.

Three scopes:
  - ranker:   rank step                                → priced at model_id_ranker
  - hunter:   hunter agent calls                       → priced at model_id
  - reviewer: clusterer + reviewer agent calls         → priced at model_id_reviewer
"""
from __future__ import annotations

import json

import streamlit as st

from ..core import settings as app_settings
from ..core.run_store import RunStore

SCOPES = ("ranker", "hunter", "reviewer")


def render_cost_block(store: RunStore) -> None:
    usage = _collect_usage(store)
    specs = _specs(store)
    prices = {k: _prices(specs[k]) for k in specs}

    costs = {k: _cost(usage[k], prices[k]) for k in usage}
    total = sum(costs.values())
    no_cache = sum(_cost_no_cache(usage[k], prices[k]) for k in usage)
    saved = no_cache - total
    saved_pct = (saved / no_cache * 100) if no_cache else 0
    total_tokens = sum(sum(u.values()) for u in usage.values())

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total cost", f"${total:,.2f}")
    c2.metric("w/o cache", f"${no_cache:,.2f}")
    c3.metric("saved", f"${saved:,.2f}", f"-{saved_pct:.0f}%")
    c4.metric("tokens", f"{total_tokens / 1_000_000:.2f}M")

    distinct = {specs[k].model_id for k in specs}
    if len(distinct) > 1:
        st.caption("  ·  ".join(
            f"{k.title()}={specs[k].label} (${costs[k]:.2f})" for k in SCOPES
        ))

    with st.expander("Token breakdown", expanded=False):
        rows: list[dict] = []
        for k in SCOPES:
            rows += _breakdown_rows(k, usage[k], prices[k], specs[k])
        st.dataframe(rows, use_container_width=True, hide_index=True)


def _specs(store: RunStore) -> dict[str, app_settings.ModelSpec]:
    cfg = store.load_config() or {}
    hunter = app_settings.by_id(cfg.get("model_id", "")) or app_settings.DEFAULT_MODEL
    reviewer = app_settings.by_id(cfg.get("model_id_reviewer") or "") or hunter
    ranker = app_settings.by_id(cfg.get("model_id_ranker") or "") or hunter
    return {"ranker": ranker, "hunter": hunter, "reviewer": reviewer}


def _prices(spec: app_settings.ModelSpec) -> dict:
    return {
        "input":       spec.input_per_m       / 1_000_000,
        "output":      spec.output_per_m      / 1_000_000,
        "cache_read":  spec.cache_read_per_m  / 1_000_000,
        "cache_write": spec.cache_write_per_m / 1_000_000,
    }


def _empty_usage() -> dict:
    return {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}


def _add(into: dict, src: dict) -> None:
    for k in into:
        into[k] += src.get(k, 0)


def _usage_from(d: dict | None) -> dict:
    d = d or {}
    return {
        "input":       d.get("input_tokens", 0),
        "output":      d.get("output_tokens", 0),
        "cache_read":  d.get("cache_read_tokens", 0),
        "cache_write": d.get("cache_write_tokens", 0),
    }


def _collect_usage(store: RunStore) -> dict[str, dict]:
    """Walk step outputs + per-file hunter dirs, summing tokens by scope."""
    out = {k: _empty_usage() for k in SCOPES}

    d = store.load_step("ranked_files") or {}
    _add(out["ranker"], _usage_from(d.get("_usage")))

    hunters_dir = store.dir / "hunters"
    if not hunters_dir.exists():
        return out

    for file_dir in hunters_dir.iterdir():
        if not file_dir.is_dir():
            continue
        # hunter findings: hunts/<cat>/findings.json
        hunts = file_dir / "hunts"
        if hunts.exists():
            for cat_dir in hunts.iterdir():
                _accumulate(cat_dir / "findings.json", out["hunter"])
        # clusterer runs on the reviewer model — fold its tokens into reviewer scope
        _accumulate(file_dir / "clusters.json", out["reviewer"])
        # reviews: reviews/<gid>/review.json
        reviews = file_dir / "reviews"
        if reviews.exists():
            for g_dir in reviews.iterdir():
                _accumulate(g_dir / "review.json", out["reviewer"])
    return out


def _accumulate(path, into: dict) -> None:
    if not path.exists():
        return
    try:
        _add(into, _usage_from(json.loads(path.read_text())))
    except Exception:
        pass


def _cost(u: dict, p: dict) -> float:
    return (
        u["input"]       * p["input"]
        + u["output"]      * p["output"]
        + u["cache_read"]  * p["cache_read"]
        + u["cache_write"] * p["cache_write"]
    )


def _cost_no_cache(u: dict, p: dict) -> float:
    eff_input = u["input"] + u["cache_read"] + u["cache_write"]
    return eff_input * p["input"] + u["output"] * p["output"]


def _breakdown_rows(label: str, u: dict, p: dict, spec: app_settings.ModelSpec) -> list[dict]:
    return [
        {
            "scope": label,
            "model": spec.label,
            "kind": k,
            "tokens": f"{u[k]:,}",
            "cost": f"${u[k] * p[k]:.2f}",
        }
        for k in ("input", "output", "cache_read", "cache_write")
    ]
