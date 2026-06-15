"""Post-review finalization: CVSS scoring, report layout."""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..agents.reviewer import ReviewResult
from ..core import cvss


def rewrite_poc_paths(findings: list[dict]) -> None:
    """Strip /workspace/ prefix; what remains is relative to the per-hunter PoC dir."""
    for f in findings:
        p = f.get("poc_file") or ""
        if p.startswith("/workspace/"):
            f["poc_file"] = p[len("/workspace/"):]


def enrich_with_cvss(review: ReviewResult) -> None:
    """Compute CVSS base score from each verdict's vector, then substitute the
    score/severity placeholders inside report markdown."""
    for r in review.reviewed:
        v = (r.get("cvss_vector") or "").strip()
        if r.get("verdict") == "real" and v:
            score = cvss.base_score(v)
            r["cvss_score"] = score
            r["severity"] = cvss.severity(score)
        else:
            r["cvss_score"] = 0.0
            r["severity"] = "none"

    for rep in review.reports:
        idx = rep.get("finding_idx")
        if not isinstance(idx, int) or idx < 0 or idx >= len(review.reviewed):
            continue
        r = review.reviewed[idx]
        md = rep.get("markdown", "")
        md = md.replace("{{cvss_score}}", f"{r['cvss_score']:.1f}")
        md = md.replace("{{severity}}", r["severity"])
        md = md.replace("{{cvss_vector}}", r.get("cvss_vector", ""))
        rep["markdown"] = md


def materialize_reports(review_dir: Path, review: ReviewResult) -> None:
    """Drop reports/<NN>_<slug>/report.md per reportable item under the group's review_dir."""
    reports_root = review_dir / "reports"
    reports_root.mkdir(parents=True, exist_ok=True)
    for i, rep in enumerate(review.reports):
        idx = rep.get("finding_idx")
        title = ""
        if isinstance(idx, int) and 0 <= idx < len(review.reviewed):
            title = review.reviewed[idx].get("title") or ""
        slug = _slugify_title(title or f"report-{i+1}")
        rdir = reports_root / f"{i+1:02d}_{slug}"
        rdir.mkdir(parents=True, exist_ok=True)
        (rdir / "report.md").write_text(rep.get("markdown", ""))


_READY_HINTS = {
    "python": (
        "Skip `pip install` — go straight to writing the PoC. "
        "Import the target directly."
    ),
    "java": (
        "Deps are at /opt/lib/*.jar (transitive deps + project jars). "
        "Compiled classes (when available) are at /opt/sec-classes. "
        "Compile a PoC: `javac -cp '/opt/lib/*' /workspace/Poc.java -d /workspace`. "
        "Run: `java -cp '/workspace:/opt/lib/*:/opt/sec-classes' Poc`. "
        "If a class isn't found, list /opt/lib to confirm the jar exists. "
        "Note: /workspace is tmpfs (writable, ~256MB); /opt is read-only baked into the image."
    ),
    "node": (
        "node_modules is installed at /code/node_modules. "
        "Run PoC from /code with `node /workspace/poc.js` "
        "or set `NODE_PATH=/code/node_modules`."
    ),
}

_FAILED_HINTS = {
    "python": (
        "Network is disabled. Use `sys.path.insert(0, '/code')` to import the "
        "target without installing — external deps may still be missing."
    ),
    "java": (
        "Network is disabled. `javac` is available; you can compile individual "
        "/code source files manually, but external deps may be missing."
    ),
    "node": (
        "Network is disabled. `node` is available but external packages may be "
        "missing without node_modules."
    ),
}


def sandbox_info(prepare: dict, language: str) -> str:
    """Tell the Hunter what's already installed so it doesn't reinstall."""
    if prepare.get("status") == "ready":
        verifies = [v.get("cmd", "") for v in prepare.get("verify_log", [])]
        verify_lines = "\n".join(f"  - {v}" for v in verifies) or "  - (none recorded)"
        return (
            "Target is installed/buildable. Network is disabled.\n"
            f"Verified by:\n{verify_lines}\n"
            + _READY_HINTS[language]
        )
    return (
        "Sandbox prepare did NOT complete successfully.\n"
        + _FAILED_HINTS[language]
    )


def write_group_input(review_dir: Path, group: dict, findings: list[dict]) -> None:
    """Save the input that the reviewer saw — useful for debugging cluster decisions."""
    review_dir.mkdir(parents=True, exist_ok=True)
    (review_dir / "group.json").write_text(json.dumps(
        {"reason": group.get("reason", ""),
         "finding_ids": group.get("finding_ids", []),
         "findings": findings},
        indent=2, ensure_ascii=False,
    ))


def _slugify_title(title: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return s[:50] or "finding"
