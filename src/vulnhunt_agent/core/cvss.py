"""CVSS 3.1 base score from a vector string. No external deps.

Spec: https://www.first.org/cvss/v3.1/specification-document
We compute Base only (Temporal/Environmental are out of scope here).
"""
from __future__ import annotations

import math

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},   # Scope unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},    # Scope changed
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def parse_vector(vector: str) -> dict:
    """'CVSS:3.1/AV:N/AC:L/...' → {'AV': 'N', 'AC': 'L', ...}"""
    parts = [p for p in vector.strip().split("/") if ":" in p and not p.startswith("CVSS:")]
    return {k: v for k, v in (p.split(":", 1) for p in parts)}


def base_score(vector: str) -> float:
    m = parse_vector(vector)
    av = _W["AV"][m["AV"]]
    ac = _W["AC"][m["AC"]]
    ui = _W["UI"][m["UI"]]
    scope = m["S"]
    pr = _W["PR_C" if scope == "C" else "PR_U"][m["PR"]]
    c, i, a = _W["CIA"][m["C"]], _W["CIA"][m["I"]], _W["CIA"][m["A"]]

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploit = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    raw = (impact + exploit) if scope == "U" else 1.08 * (impact + exploit)
    return _roundup(min(raw, 10.0))


def severity(score: float) -> str:
    if score == 0:    return "none"
    if score < 4.0:   return "low"
    if score < 7.0:   return "medium"
    if score < 9.0:   return "high"
    return "critical"


def _roundup(x: float) -> float:
    """CVSS 3.1 'roundUp' — to nearest 0.1, away from zero."""
    return math.ceil(x * 10) / 10.0
