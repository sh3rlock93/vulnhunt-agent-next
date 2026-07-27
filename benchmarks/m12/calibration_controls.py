"""Paired vulnerable/fixed controls for the M12.2 recovery cohort."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import tarfile
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Any, Awaitable, Callable, Iterable, Mapping, Sequence

from jsonschema import Draft202012Validator

if __package__ in {None, ""}:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.m12.calibration import (
    DEFAULT_CATALOG,
    PROJECT_ROOT,
    CalibrationCatalog,
)
from benchmarks.m12.calibration_cohort import open_evaluation
from benchmarks.m12.prepared_build import load_verified_prepared_run
from benchmarks.run_libtiff_blind_benchmark import (
    BenchmarkContractError,
    verify_source_pin,
)
from vulnhunt_agent.sandbox import ContainerExecutor

CONTROL_POLICY = "calibration-differential-controls-v1"
CONTROL_SCHEMA = Path(__file__).with_name("schemas") / f"{CONTROL_POLICY}.schema.json"

VariantRunner = Callable[
    [Path, str, Mapping[str, Any], bytes | None, int],
    Awaitable[dict[str, Any]],
]
PreparedLoader = Callable[[Path], dict[str, Any]]
SourceVerifier = Callable[[Path, dict[str, Any]], Any]


async def execute_differential_controls(
    plan_path: Path,
    *,
    vulnerable_repositories: Mapping[str, Path],
    fixed_repositories: Mapping[str, Path],
    vulnerable_prepared_runs: Mapping[str, Path],
    fixed_prepared_runs: Mapping[str, Path],
    reproduction_inputs: Mapping[str, Path] | None = None,
    catalog_path: Path = DEFAULT_CATALOG,
    repository_root: Path = PROJECT_ROOT,
    output: Path | None = None,
    id_factory: Callable[[], str] | None = None,
    variant_runner: VariantRunner | None = None,
    prepared_loader: PreparedLoader = load_verified_prepared_run,
    source_verifier: SourceVerifier = verify_source_pin,
) -> dict[str, Any]:
    """Run immutable paired controls only after all discovery roots are frozen."""
    plan_path = plan_path.resolve()
    cohort_root = plan_path.parent
    catalog = open_evaluation(
        plan_path,
        catalog_path,
        repository_root=repository_root,
    )
    case_ids = {item.case.case_id for item in catalog.definitions}
    mappings = (
        vulnerable_repositories,
        fixed_repositories,
        vulnerable_prepared_runs,
        fixed_prepared_runs,
    )
    if any(set(mapping) != case_ids for mapping in mappings):
        raise BenchmarkContractError(
            "differential control repository and prepared-run maps must cover every case"
        )
    unexpected_inputs = set(reproduction_inputs or {}) - case_ids
    if unexpected_inputs:
        raise BenchmarkContractError("differential control input map has unknown cases")

    target = (output or cohort_root / "differential-controls.json").resolve()
    if not target.is_relative_to(cohort_root) or target == cohort_root:
        raise BenchmarkContractError("differential control output must stay inside the cohort")
    if target.exists():
        raise BenchmarkContractError("differential control output is immutable")
    make_id = id_factory or _random_id
    runner = variant_runner or _run_variant
    seen_ids: set[str] = set()
    records: list[dict[str, Any]] = []
    for definition in catalog.definitions:
        case_id = definition.case.case_id
        reproduction = definition.oracle["reproduction"]
        payload = _reproduction_payload(
            reproduction,
            (reproduction_inputs or {}).get(case_id),
        )
        variants = (
            (
                "vulnerable",
                vulnerable_repositories[case_id].resolve(),
                vulnerable_prepared_runs[case_id].resolve(),
                asdict(definition.case.source),
            ),
            (
                "fixed",
                fixed_repositories[case_id].resolve(),
                fixed_prepared_runs[case_id].resolve(),
                dict(definition.oracle["fixed_source"]),
            ),
        )
        for variant, repo, prepared_run, expected_source in variants:
            source_verifier(repo, expected_source)
            prepared = prepared_loader(prepared_run)
            run_id = "control_" + _normalized_id(make_id())
            if run_id in seen_ids:
                raise BenchmarkContractError("differential control run ID is duplicated")
            seen_ids.add(run_id)
            attempts = [
                await runner(
                    repo,
                    str(prepared["image"]),
                    reproduction,
                    payload,
                    attempt,
                )
                for attempt in range(1, int(reproduction["attempts"]) + 1)
            ]
            records.append({
                "run_id": run_id,
                "case_id": case_id,
                "variant": variant,
                "source": expected_source,
                "image_digest": str(prepared["image_digest"]),
                "oracle_sha256": definition.case.evaluation.sha256,
                "attempt": attempts,
                "passed": _variant_passed(variant, reproduction, attempts),
            })

    result = {
        "schema_version": 1,
        "policy_version": CONTROL_POLICY,
        "cohort_id": _load_json(plan_path, "calibration cohort plan")["cohort_id"],
        "plan_sha256": _sha256(plan_path),
        "catalog_sha256": catalog.sha256,
        "run": sorted(records, key=lambda item: item["run_id"]),
    }
    _validate(result)
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_json(target, result)
    return result


def load_differential_controls(
    path: Path,
    *,
    cohort_id: str,
    plan_path: Path,
    catalog: CalibrationCatalog,
) -> dict[str, Any]:
    payload = _load_json(path, "differential controls")
    _validate(payload)
    if (
        payload["cohort_id"] != cohort_id
        or payload["plan_sha256"] != _sha256(plan_path)
        or payload["catalog_sha256"] != catalog.sha256
    ):
        raise BenchmarkContractError("differential controls are linked to another cohort")
    definitions = {item.case.case_id: item for item in catalog.definitions}
    for item in payload["run"]:
        definition = definitions.get(str(item["case_id"]))
        if definition is None:
            raise BenchmarkContractError("differential control case is not in the catalog")
        expected_source = (
            asdict(definition.case.source)
            if item["variant"] == "vulnerable"
            else dict(definition.oracle["fixed_source"])
        )
        if (
            item["source"] != expected_source
            or item["oracle_sha256"] != definition.case.evaluation.sha256
            or item["passed"]
            != _variant_passed(
                str(item["variant"]),
                definition.oracle["reproduction"],
                item["attempt"],
            )
        ):
            raise BenchmarkContractError(
                "differential control evidence does not match its sealed case"
            )
    return payload


def assess_differential_controls(
    controls: Mapping[str, Any] | None,
    *,
    case_ids: Iterable[str],
) -> dict[str, Any]:
    required = sorted(set(case_ids))
    if controls is None:
        return {
            "passed": False,
            "required": required,
            "vulnerable_passed": [],
            "fixed_passed": [],
            "missing": required,
        }
    vulnerable = sorted(
        str(item["case_id"])
        for item in controls["run"]
        if item["variant"] == "vulnerable" and item["passed"] is True
    )
    fixed = sorted(
        str(item["case_id"])
        for item in controls["run"]
        if item["variant"] == "fixed" and item["passed"] is True
    )
    complete = sorted(set(vulnerable) & set(fixed))
    return {
        "passed": vulnerable == required and fixed == required,
        "required": required,
        "vulnerable_passed": vulnerable,
        "fixed_passed": fixed,
        "missing": sorted(set(required) - set(complete)),
    }


async def _run_variant(
    repo: Path,
    image: str,
    spec: Mapping[str, Any],
    input_payload: bytes | None,
    attempt: int,
) -> dict[str, Any]:
    sandbox = ContainerExecutor(
        repo=repo,
        image=image,
        network="none",
        source_baked=True,
    )
    try:
        await sandbox.start()
        artifact = await _resolve_artifact(sandbox, str(spec["artifact_glob"]))
        substitutions = {
            "artifact": artifact,
            "source": "/workspace/control.c",
            "executable": "/workspace/exec/control",
            "input": "/workspace/input.bin",
        }
        if spec["kind"] == "compiled-driver":
            await sandbox.write_file("control.c", str(spec["source"]))
            compile_argv = _substitute(spec["compile_argv"], substitutions)
            compiled = await sandbox.exec_argv(compile_argv)
            if compiled.exit_code != 0:
                raise BenchmarkContractError(
                    "differential control compilation failed: " + compiled.stderr
                )
        elif input_payload is not None:
            await sandbox.write_bytes("input.bin", input_payload)
        argv = (
            "env",
            "ASAN_OPTIONS=detect_leaks=0:abort_on_error=1",
            "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1",
            *_substitute(spec["run_argv"], substitutions),
        )
        executed = await sandbox.exec_argv(
            argv,
            timeout=int(spec["timeout_seconds"]),
        )
        evidence = (executed.stdout + "\n" + executed.stderr).strip()
        return {
            "attempt": attempt,
            "exit_code": executed.exit_code,
            "timed_out": executed.timed_out,
            "sanitizer_failure": (
                executed.exit_code != 0
                and (
                    "AddressSanitizer" in evidence
                    or "runtime error:" in evidence
                )
            ),
            "expected_sanitizer_present": str(
                spec["expected_vulnerable_sanitizer"]
            ).casefold() in evidence.casefold(),
            "target_frame_present": str(
                spec["expected_vulnerable_frame"]
            ) in evidence,
            "fixed_stdout_present": str(
                spec["expected_fixed_stdout"]
            ).casefold() in evidence.casefold(),
            "evidence_sha256": "sha256:" + hashlib.sha256(
                evidence.encode("utf-8")
            ).hexdigest(),
        }
    finally:
        await sandbox.stop()


async def _resolve_artifact(sandbox: ContainerExecutor, pattern: str) -> str:
    name_pattern = PurePosixPath(pattern).name
    if not name_pattern or "/" in name_pattern:
        raise BenchmarkContractError("differential control artifact glob is invalid")
    result = await sandbox.exec_argv((
        "find",
        "/opt/vulnhunt/build",
        "-type",
        "f",
        "-name",
        name_pattern,
    ))
    if result.exit_code != 0:
        raise BenchmarkContractError("differential control artifact lookup failed")
    matches = sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})
    if len(matches) != 1:
        raise BenchmarkContractError(
            f"differential control artifact is ambiguous ({len(matches)} matches)"
        )
    return matches[0]


def _variant_passed(
    variant: str,
    spec: Mapping[str, Any],
    attempts: Sequence[Mapping[str, Any]],
) -> bool:
    required_attempts = int(spec["attempts"])
    if len(attempts) != required_attempts or required_attempts < 2:
        return False
    if variant == "vulnerable":
        return all(
            item["sanitizer_failure"]
            and item["expected_sanitizer_present"]
            and item["target_frame_present"]
            and not item["timed_out"]
            for item in attempts
        )
    return all(
        not item["sanitizer_failure"]
        and item["fixed_stdout_present"]
        and not item["timed_out"]
        for item in attempts
    )


def _reproduction_payload(
    spec: Mapping[str, Any],
    archive_path: Path | None,
) -> bytes | None:
    if spec["kind"] != "upstream-input":
        if archive_path is not None:
            raise BenchmarkContractError("compiled control received an unused input")
        return None
    if archive_path is None:
        raise BenchmarkContractError("upstream-input control requires a pinned input")
    archive_path = archive_path.resolve()
    if archive_path.stat().st_size != int(spec["input_size"]):
        raise BenchmarkContractError("differential control input size mismatch")
    if _sha256(archive_path) != str(spec["input_sha256"]):
        raise BenchmarkContractError("differential control input hash mismatch")
    member_name = str(spec["archive_member"])
    member_path = PurePosixPath(member_name)
    if member_path.is_absolute() or ".." in member_path.parts:
        raise BenchmarkContractError("differential control archive member is unsafe")
    try:
        with tarfile.open(archive_path, "r:*") as archive:
            member = archive.getmember(member_name)
            if not member.isfile():
                raise BenchmarkContractError(
                    "differential control archive member is not a file"
                )
            extracted = archive.extractfile(member)
            if extracted is None:
                raise BenchmarkContractError(
                    "differential control archive member is unreadable"
                )
            return extracted.read()
    except (OSError, tarfile.TarError, KeyError) as exc:
        raise BenchmarkContractError("differential control input archive is invalid") from exc


def _substitute(values: Iterable[str], substitutions: Mapping[str, str]) -> tuple[str, ...]:
    out = []
    for raw in values:
        value = str(raw)
        for key, replacement in substitutions.items():
            value = value.replace("{" + key + "}", replacement)
        if re.search(r"\{[a-z_]+\}", value):
            raise BenchmarkContractError("differential control has an unknown placeholder")
        out.append(value)
    return tuple(out)


def _validate(payload: Any) -> None:
    try:
        schema = _load_json(CONTROL_SCHEMA, "differential control schema")
    except BenchmarkContractError:
        raise
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda error: list(error.path),
    )
    if errors:
        location = ".".join(str(item) for item in errors[0].path) or "<root>"
        raise BenchmarkContractError(
            f"{CONTROL_POLICY} validation failed at {location}: {errors[0].message}"
        )
    runs = payload["run"]
    run_ids = [str(item["run_id"]) for item in runs]
    pairs = [
        (str(item["case_id"]), str(item["variant"]))
        for item in runs
    ]
    cases = {case_id for case_id, _variant in pairs}
    if len(run_ids) != len(set(run_ids)) or len(pairs) != len(set(pairs)):
        raise BenchmarkContractError("differential control identities are duplicated")
    if len(cases) != 4 or any(
        {variant for case_id, variant in pairs if case_id == current}
        != {"vulnerable", "fixed"}
        for current in cases
    ):
        raise BenchmarkContractError("differential controls are not a closed four-pair set")
    for item in runs:
        attempts = [int(attempt["attempt"]) for attempt in item["attempt"]]
        if attempts != list(range(1, len(attempts) + 1)):
            raise BenchmarkContractError(
                "differential control attempt sequence is invalid"
            )


def _normalized_id(value: str) -> str:
    normalized = str(value).strip().lower()
    if re.fullmatch(r"[0-9a-f]{16}", normalized) is None:
        raise BenchmarkContractError("differential control ID is invalid")
    return normalized


def _random_id() -> str:
    import uuid

    return uuid.uuid4().hex[:16]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BenchmarkContractError(f"{label} is unreadable") from exc


def _write_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _keyed_paths(values: Iterable[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        case_id, separator, path = value.partition("=")
        if not separator or not case_id or not path or case_id in result:
            raise BenchmarkContractError("expected unique CASE_ID=PATH mapping")
        result[case_id] = Path(path)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run M12.2 paired differential controls")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--output", type=Path, required=True)
    for name in (
        "vulnerable-repo",
        "fixed-repo",
        "vulnerable-prepare-run",
        "fixed-prepare-run",
        "input",
    ):
        parser.add_argument(f"--{name}", action="append", default=[])
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = asyncio.run(execute_differential_controls(
            args.plan,
            vulnerable_repositories=_keyed_paths(args.vulnerable_repo),
            fixed_repositories=_keyed_paths(args.fixed_repo),
            vulnerable_prepared_runs=_keyed_paths(args.vulnerable_prepare_run),
            fixed_prepared_runs=_keyed_paths(args.fixed_prepare_run),
            reproduction_inputs=_keyed_paths(args.input),
            catalog_path=args.catalog,
            output=args.output,
        ))
    except (BenchmarkContractError, OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
