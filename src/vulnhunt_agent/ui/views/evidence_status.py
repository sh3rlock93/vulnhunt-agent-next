"""Read-only Streamlit view of V2 evidence and consensus state."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

import streamlit as st

from ...core.run_store import RunStore
from ...infrastructure.sqlite_repository import SqliteRepository
from ...reviewing.consensus import decide_consensus

_STATE_ORDER = {
    "hypothesis": 0,
    "statically_supported": 1,
    "poc_ready": 2,
    "reproduction_pending": 3,
    "reproduced": 4,
    "reviewer_verified": 5,
    "reportable": 6,
}


def render_evidence_status(store: RunStore) -> None:
    config = store.load_config() or {}
    configured = config.get("v2_db_path")
    db_path = Path(configured).expanduser() if configured else store.dir / "state.db"
    if not db_path.is_file():
        return

    with SqliteRepository(db_path, read_only=True) as repository:
        runs = repository.list_runs()
        if not runs:
            return
        with st.expander("Evidence review and report state", expanded=True):
            for run in runs:
                findings = repository.list_candidates(run.run_id)
                counts = Counter(item.state.value for item in findings)
                progress = sum(
                    _STATE_ORDER.get(item.state.value, 0) for item in findings
                )
                maximum = max(1, len(findings) * max(_STATE_ORDER.values()))
                st.markdown(f"#### Run `{run.run_id}` · `{run.state.value}`")
                st.progress(progress / maximum)
                st.caption(
                    " · ".join(
                        f"{state}: {count}" for state, count in sorted(counts.items())
                    ) or "No candidates"
                )
                tasks = repository.list_tasks(run.run_id)
                if tasks:
                    st.markdown("##### Durable tasks")
                    st.dataframe(
                        [{
                            "Type": task["task_type"],
                            "Key": task["task_key"],
                            "Status": task["status"],
                            "Attempt": task["attempt"],
                            "Worker": task["lease_owner"] or "",
                            "Lease expires": task["lease_expires_at"] or "",
                            "Last error": task["last_error"] or "",
                        } for task in tasks],
                        hide_index=True,
                        use_container_width=True,
                    )
                rows = []
                for finding in findings:
                    evidence = repository.list_candidate_evidence(finding.candidate_id)
                    verdicts = repository.list_verdicts(finding.candidate_id)
                    consensus = decide_consensus(finding, verdicts, evidence)
                    rows.append({
                        "Candidate": finding.candidate_id,
                        "State": finding.state.value,
                        "Evidence": len(evidence),
                        "Reviewers": len(verdicts),
                        "Consensus": consensus.status.value,
                        "Title": finding.title,
                    })
                if rows:
                    st.dataframe(rows, hide_index=True, use_container_width=True)
            st.caption(
                "This panel is read-only. Only the Reproducer, consensus policy, "
                "and strict exporter can advance V2 finding states."
            )
