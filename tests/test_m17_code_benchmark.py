from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnhunt_agent.macos.binary_analysis.benchmark import (
    BlindBenchmarkOracle,
    BlindRegressionGateResult,
    freeze_blind_benchmark,
    run_blind_binary_regression_gate,
)
from vulnhunt_agent.macos.binary_analysis.code_benchmark import (
    M17BlindBenchmarkManifest,
    M17BlindAnalyzer,
    M17BlindCase,
    M17BlindCaseObservation,
    M17BlindCohort,
    M17BlindExpectedOutcome,
    M17BlindGateFailure,
    M17BlindGateStatus,
    M17BlindHunterOutcome,
    M17BlindOracle,
    M17BlindStageDigest,
    M17BlindTargetRole,
    M17EffectivenessBlocker,
    freeze_m17_blind_benchmark,
    make_m17_blind_oracle,
    make_m17_case_observation,
    run_m17_blind_code_gate,
)
from vulnhunt_agent.macos.binary_analysis.code_reviewer import (
    StaticReportabilityStatus,
)

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
STAGES = (
    "decompilation",
    "normalization",
    "discovery",
    "analysis",
    "ranking",
    "admission",
    "capsule",
    "hunter",
    "context",
    "reviewer",
    "reportability",
)


@pytest.fixture(scope="module")
def m15_gate() -> BlindRegressionGateResult:
    root = Path(__file__).resolve().parents[1] / "benchmarks" / "m15_blind"
    exports = root / "exports"
    cases: dict[str, tuple[Path, str]] = {}
    for path in sorted(exports.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        cases[path.stem] = (path, str(payload["snapshot_sha256"]))
    manifest = freeze_blind_benchmark(cases)
    oracle_payload = json.loads((root / "oracles.json").read_text(encoding="utf-8"))
    oracles = tuple(BlindBenchmarkOracle.model_validate(item) for item in oracle_payload)
    result = run_blind_binary_regression_gate(
        manifest,
        export_directory=exports,
        oracle_loader=lambda: oracles,
    )
    assert result.passed
    return result


def _outcomes(*, include_history: bool = False) -> tuple[M17BlindExpectedOutcome, ...]:
    values = [
        (
            "case-001",
            M17BlindCohort.M16_COMPOSITE_RANGE,
            M17BlindTargetRole.FIXTURE_POSITIVE,
            True,
            True,
            False,
            True,
        ),
        (
            "case-002",
            M17BlindCohort.M16_COMPOSITE_RANGE,
            M17BlindTargetRole.SAFE_CONTROL,
            False,
            False,
            False,
            True,
        ),
        (
            "case-003",
            M17BlindCohort.M16_PARTIAL_INITIALIZATION,
            M17BlindTargetRole.FIXTURE_POSITIVE,
            True,
            True,
            False,
            True,
        ),
        (
            "case-004",
            M17BlindCohort.M16_PARTIAL_INITIALIZATION,
            M17BlindTargetRole.SAFE_CONTROL,
            False,
            False,
            False,
            True,
        ),
        (
            "case-005",
            M17BlindCohort.CODE_FIRST,
            M17BlindTargetRole.FIXTURE_POSITIVE,
            True,
            True,
            False,
            False,
        ),
        (
            "case-006",
            M17BlindCohort.CODE_FIRST,
            M17BlindTargetRole.FIXTURE_POSITIVE,
            True,
            True,
            False,
            False,
        ),
        (
            "case-007",
            M17BlindCohort.CODE_FIRST,
            M17BlindTargetRole.SAFE_CONTROL,
            False,
            False,
            False,
            False,
        ),
        (
            "case-008",
            M17BlindCohort.CODE_FIRST,
            M17BlindTargetRole.SAFE_CONTROL,
            False,
            False,
            False,
            False,
        ),
    ]
    if include_history:
        values.extend(
            [
                (
                    "case-009",
                    M17BlindCohort.HISTORICAL_IMAGEIO,
                    M17BlindTargetRole.HISTORICAL_VULNERABLE,
                    True,
                    True,
                    True,
                    True,
                ),
                (
                    "case-010",
                    M17BlindCohort.HISTORICAL_IMAGEIO,
                    M17BlindTargetRole.HISTORICAL_PATCHED,
                    False,
                    False,
                    False,
                    True,
                ),
                (
                    "case-011",
                    M17BlindCohort.HISTORICAL_IMAGEIO,
                    M17BlindTargetRole.CURRENT_BUILD,
                    False,
                    False,
                    False,
                    True,
                ),
            ]
        )
    return tuple(
        M17BlindExpectedOutcome(
            case_id=case_id,
            cohort=cohort,
            target_role=role,
            expected_admitted=admitted,
            expected_code_hypothesis=hypothesis,
            expected_reportable_static=reportable,
            deterministic_finding_visible=visible,
        )
        for case_id, cohort, role, admitted, hypothesis, reportable, visible in values
    )


def _freeze(
    tmp_path: Path, outcomes: tuple[M17BlindExpectedOutcome, ...]
) -> tuple[M17BlindBenchmarkManifest, Path]:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    artifacts: dict[str, tuple[Path, str]] = {}
    for ordinal, outcome in enumerate(outcomes, start=1):
        path = corpus / f"{outcome.case_id}.json"
        path.write_text(json.dumps({"opaque": ordinal}), encoding="utf-8")
        artifacts[outcome.case_id] = (path, "sha256:" + f"{ordinal:064x}")
    manifest = freeze_m17_blind_benchmark(
        artifacts,
        coverage_policy_sha256=SHA_A,
        hunter_prompt_sha256=SHA_B,
        reviewer_prompt_sha256=SHA_C,
        model_id="opaque-model-build",
    )
    return manifest, corpus


def _observation(
    case: M17BlindCase,
    expected: M17BlindExpectedOutcome,
    ordinal: int,
    *,
    false_positive: bool = False,
    unstable_positive: bool = False,
    hunter_sessions: int = 1,
) -> M17BlindCaseObservation:
    has_hypothesis = expected.expected_code_hypothesis
    if unstable_positive and ordinal == 2:
        has_hypothesis = False
    if false_positive and expected.target_role is M17BlindTargetRole.SAFE_CONTROL:
        has_hypothesis = True
    reportable = expected.expected_reportable_static
    if false_positive and expected.target_role is M17BlindTargetRole.SAFE_CONTROL:
        reportable = True
    hypothesis = (f"sha256:{int(case.case_id.split('-')[1]):064x}",) if has_hypothesis else ()
    statuses = (
        (StaticReportabilityStatus.REPORTABLE_STATIC,)
        if reportable
        else (StaticReportabilityStatus.REVIEWER_INCONCLUSIVE,)
        if has_hypothesis
        else ()
    )
    return make_m17_case_observation(
        case_id=case.case_id,
        artifact_sha256=case.artifact_sha256,
        stages=tuple(
            M17BlindStageDigest(
                stage=stage,
                artifact_sha256="sha256:" + f"{index + int(case.case_id[-3:]):064x}",
            )
            for index, stage in enumerate(STAGES)
        ),
        admitted=expected.expected_admitted,
        omission_reason="ranked outside frozen budget prefix"
        if not expected.expected_admitted
        else "",
        deterministic_finding_count=1 if expected.deterministic_finding_visible else 0,
        hunter_outcome=(
            M17BlindHunterOutcome.CODE_HYPOTHESIS
            if has_hypothesis
            else M17BlindHunterOutcome.INCONCLUSIVE
        ),
        hypothesis_fingerprints=hypothesis,
        context_response_sha256s=(),
        reportability_statuses=statuses,
        hunter_sessions=hunter_sessions,
        continuation_roots=0,
        hunter_continuation_calls=0,
        reviewer_sessions=1 if has_hypothesis else 0,
        reviewer_context_calls=0,
        model_calls=hunter_sessions + (1 if has_hypothesis else 0),
        input_tokens=1000,
        output_tokens=100,
        wall_clock_seconds=0.5,
        image_executions=0,
        generated_inputs=0,
        fuzzer_invocations=0,
        vm_boots=0,
        dynamic_experiments=0,
    )


def _analyzer(
    outcomes: tuple[M17BlindExpectedOutcome, ...],
    *,
    false_positive: bool = False,
    unstable_positive: bool = False,
    hunter_sessions: int = 1,
) -> tuple[M17BlindAnalyzer, list[tuple[str, int]]]:
    expected_by_id = {item.case_id: item for item in outcomes}
    calls: list[tuple[str, int]] = []

    async def analyze(case: M17BlindCase, _path: Path, ordinal: int) -> M17BlindCaseObservation:
        calls.append((case.case_id, ordinal))
        return _observation(
            case,
            expected_by_id[case.case_id],
            ordinal,
            false_positive=false_positive,
            unstable_positive=unstable_positive,
            hunter_sessions=hunter_sessions,
        )

    return analyze, calls


@pytest.mark.asyncio
async def test_blind_gate_seals_both_runs_before_oracle_and_blocks_effectiveness_without_history(
    tmp_path: Path,
    m15_gate: BlindRegressionGateResult,
) -> None:
    outcomes = _outcomes()
    manifest, corpus = _freeze(tmp_path, outcomes)
    output = tmp_path / "private-output"
    output.mkdir()
    analyze, calls = _analyzer(outcomes)

    def load_oracle() -> M17BlindOracle:
        assert len(calls) == len(outcomes) * 2
        assert (output / "sealed-run-01.json").is_file()
        assert (output / "sealed-run-02.json").is_file()
        return make_m17_blind_oracle(outcomes)

    result = await run_m17_blind_code_gate(
        manifest,
        artifact_directory=corpus,
        output_directory=output,
        analyze_case=analyze,
        oracle_loader=load_oracle,
        m15_gate=m15_gate,
    )

    assert result.implementation_passed is True
    assert result.effectiveness_complete is False
    assert result.status is M17BlindGateStatus.IMPLEMENTATION_PASSED_EFFECTIVENESS_BLOCKED
    assert result.effectiveness_blockers == (
        M17EffectivenessBlocker.HISTORICAL_IMAGEIO_COHORT_UNAVAILABLE,
    )
    assert result.failures == ()
    public_manifest = manifest.model_dump(mode="json")
    rendered = json.dumps(public_manifest, sort_keys=True)
    assert all(label not in rendered for label in ("vulnerable", "patched", "safe_control"))
    assert [item.build_id for item in manifest.cases] == [
        f"build-{ordinal:03d}" for ordinal in range(1, len(outcomes) + 1)
    ]


@pytest.mark.asyncio
async def test_complete_historical_cohort_passes(
    tmp_path: Path,
    m15_gate: BlindRegressionGateResult,
) -> None:
    outcomes = _outcomes(include_history=True)
    manifest, corpus = _freeze(tmp_path, outcomes)
    output = tmp_path / "private-output"
    output.mkdir()
    analyze, _calls = _analyzer(outcomes)
    result = await run_m17_blind_code_gate(
        manifest,
        artifact_directory=corpus,
        output_directory=output,
        analyze_case=analyze,
        oracle_loader=lambda: make_m17_blind_oracle(outcomes),
        m15_gate=m15_gate,
    )
    assert result.status is M17BlindGateStatus.PASSED
    assert result.implementation_passed is True
    assert result.effectiveness_complete is True


@pytest.mark.asyncio
async def test_safe_reportable_result_fails_closed(
    tmp_path: Path,
    m15_gate: BlindRegressionGateResult,
) -> None:
    outcomes = _outcomes()
    manifest, corpus = _freeze(tmp_path, outcomes)
    output = tmp_path / "private-output"
    output.mkdir()
    analyze, _calls = _analyzer(outcomes, false_positive=True)
    result = await run_m17_blind_code_gate(
        manifest,
        artifact_directory=corpus,
        output_directory=output,
        analyze_case=analyze,
        oracle_loader=lambda: make_m17_blind_oracle(outcomes),
        m15_gate=m15_gate,
    )
    assert result.status is M17BlindGateStatus.FAILED
    assert M17BlindGateFailure.SAFE_OR_PATCHED_REPORTABLE in result.failures


@pytest.mark.asyncio
async def test_positive_seen_in_only_one_run_fails_stability(
    tmp_path: Path,
    m15_gate: BlindRegressionGateResult,
) -> None:
    outcomes = _outcomes()
    manifest, corpus = _freeze(tmp_path, outcomes)
    output = tmp_path / "private-output"
    output.mkdir()
    analyze, _calls = _analyzer(outcomes, unstable_positive=True)
    result = await run_m17_blind_code_gate(
        manifest,
        artifact_directory=corpus,
        output_directory=output,
        analyze_case=analyze,
        oracle_loader=lambda: make_m17_blind_oracle(outcomes),
        m15_gate=m15_gate,
    )
    assert M17BlindGateFailure.MODEL_OUTCOME_INSTABILITY in result.failures
    assert M17BlindGateFailure.CODE_FIRST_HYPOTHESIS_MISSING in result.failures


@pytest.mark.asyncio
async def test_frozen_artifact_change_aborts_before_oracle(
    tmp_path: Path,
    m15_gate: BlindRegressionGateResult,
) -> None:
    outcomes = _outcomes()
    manifest, corpus = _freeze(tmp_path, outcomes)
    (corpus / "case-001.json").write_text("changed", encoding="utf-8")
    output = tmp_path / "private-output"
    output.mkdir()
    analyze, _calls = _analyzer(outcomes)
    loaded = False

    def load_oracle() -> M17BlindOracle:
        nonlocal loaded
        loaded = True
        return make_m17_blind_oracle(outcomes)

    with pytest.raises(ValueError, match="frozen input changed"):
        await run_m17_blind_code_gate(
            manifest,
            artifact_directory=corpus,
            output_directory=output,
            analyze_case=analyze,
            oracle_loader=load_oracle,
            m15_gate=m15_gate,
        )
    assert loaded is False


@pytest.mark.asyncio
async def test_aggregate_cost_ceiling_is_enforced(
    tmp_path: Path,
    m15_gate: BlindRegressionGateResult,
) -> None:
    outcomes = _outcomes()
    manifest, corpus = _freeze(tmp_path, outcomes)
    output = tmp_path / "private-output"
    output.mkdir()
    analyze, _calls = _analyzer(outcomes, hunter_sessions=3)
    result = await run_m17_blind_code_gate(
        manifest,
        artifact_directory=corpus,
        output_directory=output,
        analyze_case=analyze,
        oracle_loader=lambda: make_m17_blind_oracle(outcomes),
        m15_gate=m15_gate,
    )
    assert M17BlindGateFailure.COST_CEILING_EXCEEDED in result.failures


def test_dynamic_execution_counters_are_literal_zero() -> None:
    with pytest.raises(ValidationError):
        make_m17_case_observation(
            case_id="case-001",
            artifact_sha256=SHA_A,
            stages=tuple(
                M17BlindStageDigest(stage=stage, artifact_sha256=SHA_B) for stage in STAGES
            ),
            admitted=False,
            omission_reason="not admitted",
            deterministic_finding_count=0,
            hunter_outcome=M17BlindHunterOutcome.NOT_RUN,
            hunter_sessions=0,
            continuation_roots=0,
            hunter_continuation_calls=0,
            reviewer_sessions=0,
            reviewer_context_calls=0,
            model_calls=0,
            input_tokens=0,
            output_tokens=0,
            wall_clock_seconds=0,
            dynamic_experiments=1,
        )


def test_code_first_safe_control_is_valid_but_positive_requires_hypothesis() -> None:
    M17BlindExpectedOutcome(
        case_id="case-001",
        cohort=M17BlindCohort.CODE_FIRST,
        target_role=M17BlindTargetRole.SAFE_CONTROL,
        expected_admitted=False,
        expected_code_hypothesis=False,
        expected_reportable_static=False,
        deterministic_finding_visible=False,
    )
    with pytest.raises(ValidationError, match="must expect a code hypothesis"):
        M17BlindExpectedOutcome(
            case_id="case-002",
            cohort=M17BlindCohort.CODE_FIRST,
            target_role=M17BlindTargetRole.FIXTURE_POSITIVE,
            expected_admitted=True,
            expected_code_hypothesis=False,
            expected_reportable_static=False,
            deterministic_finding_visible=False,
        )


def test_manifest_rejects_nonopaque_artifact_name(tmp_path: Path) -> None:
    artifact = tmp_path / "historical-vulnerable.json"
    artifact.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="opaque case-ID names"):
        freeze_m17_blind_benchmark(
            {"case-001": (artifact, SHA_A)},
            coverage_policy_sha256=SHA_A,
            hunter_prompt_sha256=SHA_B,
            reviewer_prompt_sha256=SHA_C,
            model_id="opaque-model-build",
        )
