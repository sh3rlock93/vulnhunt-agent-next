"""Deterministic, machine-readable success oracles."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys

from ..domain.schemas import OracleResult, OracleSpec, OracleType
from ..sandbox.base import ExecResult

_REGEX_INPUT_LIMIT = 200_000
_REGEX_TIMEOUT_SECONDS = 0.5
_REGEX_WORKER = (
    "import json,re,sys;"
    "p,t=json.loads(sys.stdin.read());"
    "sys.exit(0 if re.search(p,t) is not None else 1)"
)


def evaluate_oracle(spec: OracleSpec, execution: ExecResult) -> OracleResult:
    expression = _expression(spec)
    if execution.timed_out:
        return OracleResult(type=spec.type.value, expression=expression, result="failed")

    passed = False
    if spec.type is OracleType.EXIT_CODE:
        passed = execution.exit_code == spec.expected_exit_code
    elif spec.type is OracleType.STDOUT_REGEX:
        passed = _safe_regex_search(spec.pattern or "", execution.stdout)
    elif spec.type is OracleType.STDERR_REGEX:
        passed = _safe_regex_search(spec.pattern or "", execution.stderr)
    elif spec.type is OracleType.COMBINED_REGEX:
        passed = _safe_regex_search(
            spec.pattern or "", execution.stdout + "\n" + execution.stderr
        )
    elif spec.type is OracleType.FILE_SHA256:
        content = (execution.captured_files or {}).get(spec.path or "")
        if content is not None:
            passed = "sha256:" + hashlib.sha256(content).hexdigest() == spec.expected_sha256

    return OracleResult(
        type=spec.type.value,
        expression=expression,
        result="passed" if passed else "failed",
    )


def _safe_regex_search(pattern: str, text: str) -> bool:
    payload = json.dumps([pattern, text[:_REGEX_INPUT_LIMIT]])
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-c", _REGEX_WORKER],
            input=payload,
            capture_output=True,
            text=True,
            timeout=_REGEX_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def _expression(spec: OracleSpec) -> str:
    if spec.type is OracleType.EXIT_CODE:
        return f"exit_code == {spec.expected_exit_code}"
    if spec.type is OracleType.FILE_SHA256:
        return f"sha256({spec.path}) == {spec.expected_sha256}"
    return spec.pattern or ""
