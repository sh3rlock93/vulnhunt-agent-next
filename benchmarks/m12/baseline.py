"""M12 baseline freeze, protected-contract, and oracle-leakage checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.detection_registry import DetectionBaseline, load_detection_registry
from benchmarks.run_detection_release_matrix import (
    RECEIPT_POLICY,
    ReleaseGate,
    validate_release_contract,
)
from benchmarks.run_libtiff_blind_benchmark import BenchmarkContractError

BASELINE_POLICY = "m12-baseline-freeze-v1"
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class FrozenFile:
    path: str
    sha256: str


@dataclass(frozen=True)
class FrozenProtectedDetection:
    baseline_id: str
    detection_contract_sha256: str
    release_gate_sha256: str
    ci_check_name: str
    ci_job_id: int
    result: str
    authenticated_receipt: str = ""
    receipt_contract_sha256: str = ""
    oracle_tokens: tuple[str, ...] = ()


@dataclass(frozen=True)
class M12Baseline:
    implementation_commit: str
    implementation_tree: str
    action_run_id: int
    action_run_url: str
    release_matrix_job_id: int
    release_matrix_result: str
    files: tuple[FrozenFile, ...]
    protected: tuple[FrozenProtectedDetection, ...]


def load_m12_baseline(path: Path) -> M12Baseline:
    """Load the closed M11.7 snapshot contract."""
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise BenchmarkContractError("M12 baseline is unreadable") from exc
    allowed_root = {"baseline", "file", "protected"}
    if set(payload) != allowed_root:
        raise BenchmarkContractError("M12 baseline has unknown or missing sections")
    metadata = payload["baseline"]
    required_metadata = {
        "schema_version",
        "policy_version",
        "implementation_commit",
        "implementation_tree",
        "action_run_id",
        "action_run_url",
        "release_matrix_job_id",
        "release_matrix_result",
        "protected_count",
    }
    if not isinstance(metadata, dict) or set(metadata) != required_metadata:
        raise BenchmarkContractError("M12 baseline metadata is not closed")
    if metadata["schema_version"] != 1 or metadata["policy_version"] != BASELINE_POLICY:
        raise BenchmarkContractError("unsupported M12 baseline policy")
    for key in ("implementation_commit", "implementation_tree"):
        if not isinstance(metadata[key], str) or COMMIT_PATTERN.fullmatch(metadata[key]) is None:
            raise BenchmarkContractError(f"invalid M12 baseline {key}")
    for key in ("action_run_id", "release_matrix_job_id", "protected_count"):
        if not isinstance(metadata[key], int) or isinstance(metadata[key], bool) or metadata[key] < 1:
            raise BenchmarkContractError(f"invalid M12 baseline {key}")
    if metadata["release_matrix_result"] != "success":
        raise BenchmarkContractError("frozen release matrix was not successful")
    action_run_url = str(metadata["action_run_url"])
    if not action_run_url.endswith(f"/actions/runs/{metadata['action_run_id']}"):
        raise BenchmarkContractError("M12 baseline action run URL mismatch")

    raw_files = payload["file"]
    if not isinstance(raw_files, list) or not raw_files:
        raise BenchmarkContractError("M12 baseline requires frozen files")
    files = tuple(_parse_file(item) for item in raw_files)
    file_paths = [item.path for item in files]
    if len(file_paths) != len(set(file_paths)):
        raise BenchmarkContractError("M12 baseline contains duplicate frozen files")

    raw_protected = payload["protected"]
    if not isinstance(raw_protected, list) or not raw_protected:
        raise BenchmarkContractError("M12 baseline requires protected detections")
    protected = tuple(_parse_protected(item) for item in raw_protected)
    protected_ids = [item.baseline_id for item in protected]
    if len(protected_ids) != len(set(protected_ids)):
        raise BenchmarkContractError("M12 baseline contains duplicate protected detections")
    if len(protected) != metadata["protected_count"]:
        raise BenchmarkContractError("M12 baseline protected count mismatch")
    return M12Baseline(
        implementation_commit=metadata["implementation_commit"],
        implementation_tree=metadata["implementation_tree"],
        action_run_id=metadata["action_run_id"],
        action_run_url=action_run_url,
        release_matrix_job_id=metadata["release_matrix_job_id"],
        release_matrix_result=metadata["release_matrix_result"],
        files=files,
        protected=protected,
    )


def validate_m12_baseline(
    baseline_path: Path,
    registry_path: Path,
    matrix_path: Path,
    receipts_path: Path,
    *,
    repository_root: Path,
) -> dict[str, Any]:
    """Verify frozen provenance and prevent protected-contract weakening."""
    root = repository_root.resolve()
    baseline = load_m12_baseline(baseline_path)
    _verify_git_snapshot(root, baseline)
    detections = load_detection_registry(registry_path)
    gates = validate_release_contract(registry_path, matrix_path, receipts_path)
    receipts = _load_receipts(receipts_path)
    assert_frozen_protected_contracts(baseline, detections, gates, receipts)
    assert_no_production_leakage(baseline, root / "src" / "vulnhunt_agent")
    return {
        "schema_version": 1,
        "policy_version": BASELINE_POLICY,
        "passed": True,
        "implementation_commit": baseline.implementation_commit,
        "implementation_tree": baseline.implementation_tree,
        "action_run_id": baseline.action_run_id,
        "release_matrix_job_id": baseline.release_matrix_job_id,
        "protected_detection_ids": sorted(item.baseline_id for item in baseline.protected),
        "frozen_files": [asdict(item) for item in sorted(baseline.files, key=lambda item: item.path)],
    }


def assert_frozen_protected_contracts(
    baseline: M12Baseline,
    detections: tuple[DetectionBaseline, ...],
    gates: tuple[ReleaseGate, ...],
    receipts: dict[str, dict[str, Any]],
) -> None:
    """Allow new entries but reject changes to the six frozen M11.7 gates."""
    by_detection = {item.baseline_id: item for item in detections}
    by_gate = {item.baseline_id: item for item in gates}
    for frozen in baseline.protected:
        detection = by_detection.get(frozen.baseline_id)
        if detection is None:
            raise BenchmarkContractError(f"frozen protected detection was removed: {frozen.baseline_id}")
        if detection.status != "must_detect":
            raise BenchmarkContractError(f"frozen protected detection was demoted: {frozen.baseline_id}")
        if contract_sha256(asdict(detection)) != frozen.detection_contract_sha256:
            raise BenchmarkContractError(f"frozen detection contract changed: {frozen.baseline_id}")
        gate = by_gate.get(frozen.baseline_id)
        if gate is None or contract_sha256(asdict(gate)) != frozen.release_gate_sha256:
            raise BenchmarkContractError(f"frozen release gate changed: {frozen.baseline_id}")
        if frozen.result != "success" or frozen.ci_job_id < 1 or not frozen.ci_check_name:
            raise BenchmarkContractError(f"frozen result is not successful: {frozen.baseline_id}")
        if frozen.authenticated_receipt:
            receipt = receipts.get(frozen.authenticated_receipt)
            if receipt is None:
                raise BenchmarkContractError(
                    f"frozen authenticated receipt was removed: {frozen.baseline_id}"
                )
            if contract_sha256(receipt) != frozen.receipt_contract_sha256:
                raise BenchmarkContractError(
                    f"frozen authenticated receipt changed: {frozen.baseline_id}"
                )
        elif frozen.receipt_contract_sha256:
            raise BenchmarkContractError(
                f"receipt digest has no receipt ID: {frozen.baseline_id}"
            )


def assert_no_production_leakage(baseline: M12Baseline, production_root: Path) -> None:
    """Reject frozen repository/oracle identifiers in production discovery code."""
    if not production_root.is_dir():
        raise BenchmarkContractError("production source root does not exist")
    tokens = sorted({token for item in baseline.protected for token in item.oracle_tokens})
    for token in tokens:
        if len(token) < 12:
            raise BenchmarkContractError("oracle leakage token is too short")
    for path in sorted(production_root.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        folded = text.casefold()
        for token in tokens:
            if token.casefold() in folded:
                relative = path.relative_to(production_root).as_posix()
                raise BenchmarkContractError(
                    f"protected oracle token leaked into production source: {relative}"
                )


def contract_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _verify_git_snapshot(root: Path, baseline: M12Baseline) -> None:
    actual_tree = _git(root, "rev-parse", f"{baseline.implementation_commit}^{{tree}}")
    if actual_tree != baseline.implementation_tree:
        raise BenchmarkContractError("M12 baseline implementation tree mismatch")
    for frozen in baseline.files:
        completed = subprocess.run(
            ["git", "-C", str(root), "show", f"{baseline.implementation_commit}:{frozen.path}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            raise BenchmarkContractError(f"frozen baseline file is unavailable: {frozen.path}")
        actual = "sha256:" + hashlib.sha256(completed.stdout).hexdigest()
        if actual != frozen.sha256:
            raise BenchmarkContractError(f"frozen baseline file hash mismatch: {frozen.path}")


def _load_receipts(path: Path) -> dict[str, dict[str, Any]]:
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    metadata = payload.get("receipts") or {}
    if metadata.get("schema_version") != 1 or metadata.get("policy_version") != RECEIPT_POLICY:
        raise BenchmarkContractError("unsupported authenticated receipt contract")
    runs = payload.get("run")
    if not isinstance(runs, list):
        raise BenchmarkContractError("authenticated receipt runs must be a list")
    receipts: dict[str, dict[str, Any]] = {}
    for raw in runs:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
            raise BenchmarkContractError("invalid authenticated receipt")
        run_id = raw["id"]
        if run_id in receipts:
            raise BenchmarkContractError(f"duplicate authenticated receipt: {run_id}")
        receipts[run_id] = raw
    return receipts


def _parse_file(raw: Any) -> FrozenFile:
    if not isinstance(raw, dict) or set(raw) != {"path", "sha256"}:
        raise BenchmarkContractError("invalid frozen file record")
    path = str(raw["path"])
    if not path or path.startswith("/") or ".." in Path(path).parts or "\\" in path:
        raise BenchmarkContractError("frozen file path must be repository-relative")
    sha256 = str(raw["sha256"])
    if SHA256_PATTERN.fullmatch(sha256) is None:
        raise BenchmarkContractError("invalid frozen file SHA-256")
    return FrozenFile(path, sha256)


def _parse_protected(raw: Any) -> FrozenProtectedDetection:
    required = {
        "id",
        "detection_contract_sha256",
        "release_gate_sha256",
        "ci_check_name",
        "ci_job_id",
        "result",
        "oracle_tokens",
    }
    optional = {"authenticated_receipt", "receipt_contract_sha256"}
    if not isinstance(raw, dict) or not required.issubset(raw) or set(raw) - required - optional:
        raise BenchmarkContractError("invalid frozen protected detection record")
    for key in ("detection_contract_sha256", "release_gate_sha256"):
        if SHA256_PATTERN.fullmatch(str(raw[key])) is None:
            raise BenchmarkContractError(f"invalid protected {key}")
    receipt_sha = str(raw.get("receipt_contract_sha256") or "")
    if receipt_sha and SHA256_PATTERN.fullmatch(receipt_sha) is None:
        raise BenchmarkContractError("invalid protected receipt contract SHA-256")
    tokens = raw["oracle_tokens"]
    if not isinstance(tokens, list) or not tokens or not all(isinstance(item, str) for item in tokens):
        raise BenchmarkContractError("protected detection requires oracle leakage tokens")
    job_id = raw["ci_job_id"]
    if not isinstance(job_id, int) or isinstance(job_id, bool) or job_id < 1:
        raise BenchmarkContractError("invalid protected CI job ID")
    return FrozenProtectedDetection(
        baseline_id=str(raw["id"]),
        detection_contract_sha256=str(raw["detection_contract_sha256"]),
        release_gate_sha256=str(raw["release_gate_sha256"]),
        ci_check_name=str(raw["ci_check_name"]),
        ci_job_id=job_id,
        result=str(raw["result"]),
        authenticated_receipt=str(raw.get("authenticated_receipt") or ""),
        receipt_contract_sha256=receipt_sha,
        oracle_tokens=tuple(tokens),
    )


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise BenchmarkContractError(f"git {' '.join(args)} failed")
    return completed.stdout.strip()


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, default=root / "benchmarks/m12/m11-7-baseline.toml")
    parser.add_argument("--registry", type=Path, default=root / "benchmarks/historical-detections.toml")
    parser.add_argument("--matrix", type=Path, default=root / "benchmarks/detection-release-matrix.toml")
    parser.add_argument(
        "--receipts",
        type=Path,
        default=root / "benchmarks/authenticated-detection-receipts.toml",
    )
    parser.add_argument("--repository-root", type=Path, default=root)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = validate_m12_baseline(
        args.baseline,
        args.registry,
        args.matrix,
        args.receipts,
        repository_root=args.repository_root,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
