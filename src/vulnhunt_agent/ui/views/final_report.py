"""Final report view: reviewed findings sorted by CVSS, click to expand."""
from __future__ import annotations

import json

import streamlit as st

from ...core.run_store import RunStore


_SEVERITY_BADGE = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}


def render_final_report(store: RunStore) -> None:
    hunt = store.load_step("hunt") or {}
    outcome = hunt.get("outcome")
    outcome_detail = hunt.get("run_outcome") or {}
    if outcome == "invalid_execution":
        st.error(
            "This run is invalid and cannot be presented as a clean scan: "
            + str(outcome_detail.get("reason") or "execution setup failed")
        )
    elif outcome == "interrupted":
        st.warning("This run was interrupted and has resumable unfinished work.")
    elif outcome == "valid_budget_limited":
        st.warning(
            outcome_detail.get("zero_finding_label")
            or "This valid run is incomplete because declared work was deferred."
        )
    scan_scope = hunt.get("scan_scope") or {}
    target_completion = hunt.get("target_completion") or {}
    outcome_work = outcome_detail.get("work") or {}
    st.caption(
        "Scope accounting · "
        f"mode: {scan_scope.get('mode', 'full')} · "
        f"selected files: {len(scan_scope.get('selected_files', []))} · "
        "scope-deferred critical targets: "
        f"{len(scan_scope.get('scope_deferred_critical_sink_ids', []))} · "
        "unadmitted budget-deferred work: "
        f"{int(outcome_work.get('unadmitted_budget_deferred', 0) or 0)} · "
        "admitted deferred work: "
        f"{int(outcome_work.get('admitted_deferred', 0) or 0)} · "
        f"deferred targets: {int(target_completion.get('deferred', 0) or 0)}"
    )
    if scan_scope.get("mode", "full") != "full":
        st.warning(
            f"This is a bounded {scan_scope.get('mode')} result, not a repository-wide "
            f"result. {len(scan_scope.get('scope_deferred_critical_sink_ids', []))} "
            "critical signal(s) were outside scope."
        )
    deferred = hunt.get("unanalysed_work_ids") or []
    if deferred:
        st.warning(
            f"Analysis is incomplete: {len(deferred)} Hunter work item(s) were "
            "deferred by the configured hard budget."
        )
    hunters_dir = store.dir / "hunters"
    verified_dir = store.dir / "verified"
    if not hunters_dir.exists() and not verified_dir.exists():
        return

    entries = list(_collect_verified_entries(verified_dir))
    if not entries and hunters_dir.exists():
        entries = list(_collect_entries(hunters_dir))

    st.divider()
    st.header("Final Report")
    if not entries:
        if hunt.get("zero_findings") and hunt.get("zero_finding_label"):
            st.info(hunt["zero_finding_label"])
        elif outcome in {"invalid_execution", "interrupted"}:
            st.error("No trustworthy zero-finding conclusion is available.")
        else:
            st.info(
                "No strict reports yet — findings require two clean reproductions "
                "and evidence-aware review."
            )
        return

    entries.sort(key=lambda e: (-e["score"], e["finished_at"] or "9999"))
    st.caption(
        f"{len(entries)} finding(s) from {len({e['file'] for e in entries})} file(s), "
        f"sorted by CVSS."
    )

    table = [
        {
            "CVSS": f"{_SEVERITY_BADGE.get(e['severity'], '⚪')} "
                    f"{e['score']:.1f} ({e['severity']})",
            "File": e["file"],
            "Title": e["title"],
        }
        for e in entries
    ]
    event = st.dataframe(
        table,
        use_container_width=True, hide_index=True,
        on_select="rerun", selection_mode="single-row",
        column_config={"CVSS": st.column_config.TextColumn(width="small")},
    )

    selected_rows = event.selection.rows if event and event.selection else []
    if not selected_rows:
        st.caption("👆 Select a row to view the full report.")
        return

    _render_detail(entries[selected_rows[0]])


def _collect_verified_entries(verified_dir):
    reports_dir = verified_dir / "reports"
    if not reports_dir.exists():
        return
    for report_dir in sorted(reports_dir.iterdir()):
        json_path = report_dir / "report.json"
        markdown_path = report_dir / "report.md"
        if not json_path.is_file() or not markdown_path.is_file():
            continue
        report = json.loads(json_path.read_text())
        finding = report["finding"]
        classification = report["classification"]
        yield {
            "score": float(classification["cvss_score"]),
            "severity": classification["severity"],
            "title": finding["title"],
            "notes": "; ".join(
                item["notes"] for item in report.get("reviews", [])
            ),
            "file": finding["entrypoint"]["path"],
            "finished_at": "",
            "md": markdown_path.read_text(),
        }


def _collect_entries(hunters_dir):
    """Yield finding dicts from hunters/<file>/reviews/<gid>/review.json."""
    for file_dir in hunters_dir.iterdir():
        if not file_dir.is_dir():
            continue
        task_path = file_dir / "task.json"
        reviews_dir = file_dir / "reviews"
        if not task_path.exists() or not reviews_dir.exists():
            continue
        task = json.loads(task_path.read_text())
        for g_dir in sorted(reviews_dir.iterdir()):
            review_path = g_dir / "review.json"
            if not review_path.exists():
                continue
            review = json.loads(review_path.read_text())
            reports = review.get("reports", [])
            reviewed = review.get("reviewed", [])
            for r in reports:
                idx = r.get("finding_idx", -1)
                v = reviewed[idx] if 0 <= idx < len(reviewed) else {}
                yield {
                    "score": float(v.get("cvss_score") or 0),
                    "severity": v.get("severity") or "none",
                    "title": v.get("title", "?"),
                    "notes": v.get("notes", ""),
                    "file": task.get("file", ""),
                    "finished_at": task.get("finished_at", ""),
                    "md": r.get("markdown", ""),
                }


def _render_detail(entry: dict) -> None:
    ts = entry["finished_at"].replace("T", " ") if entry["finished_at"] else "—"
    badge = _SEVERITY_BADGE.get(entry["severity"], "⚪")
    st.divider()
    st.subheader(f"{badge} {entry['title']}")
    st.caption(
        f"📄 `{entry['file']}`  ·  CVSS {entry['score']:.1f} ({entry['severity']})  ·  🕑 {ts}"
    )
    if entry["notes"]:
        st.info(f"**Reviewer notes:** {entry['notes']}")
    st.markdown(entry["md"])
