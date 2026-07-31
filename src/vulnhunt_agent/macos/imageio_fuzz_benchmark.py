"""Evidence-based merge gate for the ImageIO fuzz-depth recovery series."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from ..domain.schemas import DomainModel
from .imageio_fuzzer import (
    ImageIODecodeStage,
    ImageIOFuzzBudget,
    ImageIOFuzzCampaignSummary,
    ImageIOFuzzCaseResult,
    ImageIOFuzzClassification,
)

_REQUIRED_PIXEL_TAGS = frozenset(
    {
        "0028,0002",  # Samples per Pixel
        "0028,0010",  # Rows
        "0028,0011",  # Columns
        "0028,0100",  # Bits Allocated
        "0028,0101",  # Bits Stored
        "0028,0102",  # High Bit
        "0028,0103",  # Pixel Representation
        "7FE0,0010",  # Pixel Data
    }
)


class ImageIOFuzzBenchmarkStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"


class ImageIOFuzzBenchmarkAssessment(DomainModel):
    schema_version: Literal["imageio-fuzz-benchmark-v1"] = "imageio-fuzz-benchmark-v1"
    status: ImageIOFuzzBenchmarkStatus
    campaign_id: str
    seed_pixel_qualified: bool
    generated_cases: int = Field(ge=0)
    executed_cases: int = Field(ge=0)
    unique_executed_inputs: int = Field(ge=0)
    unique_executed_input_ratio: float = Field(ge=0.0, le=1.0)
    covered_pixel_tags: tuple[str, ...]
    missing_pixel_tags: tuple[str, ...]
    pixel_rendered_case_count: int = Field(ge=0)
    crash_candidate_count: int = Field(ge=0)
    execution_count: int = Field(ge=0)
    execution_budget: int = Field(ge=4)
    host_execution_count: Literal[0] = 0
    disposable_clone_cleanup_verified: bool
    failures: tuple[str, ...]

    @model_validator(mode="after")
    def validate_status(self) -> "ImageIOFuzzBenchmarkAssessment":
        expected = (
            ImageIOFuzzBenchmarkStatus.FAILED
            if self.failures
            else ImageIOFuzzBenchmarkStatus.PASSED
        )
        if self.status is not expected:
            raise ValueError("benchmark status does not match its failures")
        return self

    @property
    def ready_for_crash_triage(self) -> bool:
        return self.status is ImageIOFuzzBenchmarkStatus.PASSED


def assess_imageio_fuzz_benchmark(
    *,
    store_root: Path,
    summary: ImageIOFuzzCampaignSummary,
    budget: ImageIOFuzzBudget,
    disposable_clone_cleanup_verified: bool,
) -> ImageIOFuzzBenchmarkAssessment:
    """Require useful decoder reachability and a real crash before merge."""

    cases = _load_case_results(store_root)
    hashes = {result.case.input_sha256 for result in cases}
    covered_tags = {
        tag
        for result in cases
        for tag in (result.case.target_tag, *result.case.related_tags)
        if tag in _REQUIRED_PIXEL_TAGS
    }
    pixel_rendered_cases = sum(
        any(
            execution.behavior is not None
            and execution.behavior.decode_stage is ImageIODecodeStage.PIXELS_RENDERED
            for execution in result.executions
        )
        for result in cases
    )
    crash_candidates = sum(
        any(
            execution.classification is ImageIOFuzzClassification.CRASH_CANDIDATE
            for execution in result.executions
        )
        for result in cases
    )
    seed_pixel_qualified = (
        summary.seed_qualification is not None
        and summary.seed_qualification.deepest_stage is ImageIODecodeStage.PIXELS_RENDERED
    )
    ratio = len(hashes) / len(cases) if cases else 0.0
    missing_tags = _REQUIRED_PIXEL_TAGS - covered_tags
    failures: list[str] = []
    if not seed_pixel_qualified:
        failures.append("seed did not render pixels on both qualified decode routes")
    if len(cases) != summary.executed_cases:
        failures.append("private case records do not match the executed-case count")
    if ratio != 1.0:
        failures.append("executed payloads were not globally unique inside the campaign")
    if missing_tags:
        failures.append("high-value pixel-layout tag coverage is incomplete")
    if pixel_rendered_cases == 0:
        failures.append("no mutated case reached pixel rendering")
    if summary.execution_count > budget.max_executions:
        failures.append("campaign exceeded its execution budget")
    if not disposable_clone_cleanup_verified:
        failures.append("disposable clone cleanup was not verified")
    if crash_candidates == 0:
        failures.append("campaign produced no actual crash candidate")
    status = (
        ImageIOFuzzBenchmarkStatus.FAILED
        if failures
        else ImageIOFuzzBenchmarkStatus.PASSED
    )
    return ImageIOFuzzBenchmarkAssessment(
        status=status,
        campaign_id=summary.campaign_id,
        seed_pixel_qualified=seed_pixel_qualified,
        generated_cases=summary.generated_cases,
        executed_cases=summary.executed_cases,
        unique_executed_inputs=len(hashes),
        unique_executed_input_ratio=ratio,
        covered_pixel_tags=tuple(sorted(covered_tags)),
        missing_pixel_tags=tuple(sorted(missing_tags)),
        pixel_rendered_case_count=pixel_rendered_cases,
        crash_candidate_count=crash_candidates,
        execution_count=summary.execution_count,
        execution_budget=budget.max_executions,
        disposable_clone_cleanup_verified=disposable_clone_cleanup_verified,
        failures=tuple(failures),
    )


def _load_case_results(store_root: Path) -> tuple[ImageIOFuzzCaseResult, ...]:
    cases = store_root.expanduser().resolve() / "cases"
    if not cases.is_dir():
        return ()
    return tuple(
        ImageIOFuzzCaseResult.model_validate_json(path.read_bytes())
        for path in sorted(cases.glob("case-*.json"))
    )
