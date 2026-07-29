"""Evidence gate for Apple CVE submission candidates.

This policy is intentionally stricter than the generic ``reportable`` gate.  It
does not decide whether Apple will assign a CVE or pay a bounty.  It prevents an
outdated-build crash, an AI-only hypothesis, or a nondeterministic assertion
from being packaged as an Apple submission candidate.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from pydantic import Field, model_validator

from ..domain.schemas import DomainModel, SHA256_PATTERN
from ..domain.states import FindingState

_APPLE_RELEASE_URL = r"^https://(?:developer|support|security)\.apple\.com/"
_PRODUCT_VERSION = r"^[0-9]+(?:\.[0-9]+){1,2}$"
_BUILD_VERSION = r"^[0-9A-Za-z]+$"


class AppleReleaseChannel(StrEnum):
    STABLE = "stable"
    PUBLIC_BETA = "public_beta"


class AppleCrashClass(StrEnum):
    ASSERTION = "assertion"
    NULL_DEREFERENCE = "null_dereference"
    PROCESS_DENIAL_OF_SERVICE = "process_denial_of_service"
    OUT_OF_BOUNDS_READ = "out_of_bounds_read"
    OUT_OF_BOUNDS_WRITE = "out_of_bounds_write"
    USE_AFTER_FREE = "use_after_free"
    HEAP_CORRUPTION = "heap_corruption"
    INTEGER_OVERFLOW = "integer_overflow"
    TYPE_CONFUSION = "type_confusion"
    OTHER_MEMORY_CORRUPTION = "other_memory_corruption"


class AppleExploitability(StrEnum):
    CRASH_ONLY = "crash_only"
    RELIABLE_DENIAL_OF_SERVICE = "reliable_denial_of_service"
    MEMORY_CORRUPTION = "memory_corruption"
    REGISTER_CONTROL = "register_control"
    ARBITRARY_READ = "arbitrary_read"
    ARBITRARY_WRITE = "arbitrary_write"
    CODE_EXECUTION = "code_execution"


class HumanReviewVerdict(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"


class ApplePlatformBaseline(DomainModel):
    channel: AppleReleaseChannel
    product_version: str = Field(pattern=_PRODUCT_VERSION)
    build_version: str = Field(pattern=_BUILD_VERSION)
    is_latest_public: bool
    observed_at: datetime
    official_release_url: str = Field(pattern=_APPLE_RELEASE_URL)

    @model_validator(mode="after")
    def require_aware_observation(self) -> "ApplePlatformBaseline":
        if self.observed_at.tzinfo is None:
            raise ValueError("baseline observation time must include a timezone")
        return self


class AppleReproductionAttempt(DomainModel):
    attempt: int = Field(ge=1, le=10)
    channel: AppleReleaseChannel
    product_version: str = Field(pattern=_PRODUCT_VERSION)
    build_version: str = Field(pattern=_BUILD_VERSION)
    hardware_model: str = Field(min_length=1, max_length=120)
    standard_configuration: bool
    clean_snapshot: bool
    timed_out: bool = False
    trigger_sha256: str = Field(pattern=SHA256_PATTERN)
    poc_sha256: str = Field(pattern=SHA256_PATTERN)
    crash_log_sha256: str = Field(pattern=SHA256_PATTERN)
    root_cause_fingerprint: str = Field(pattern=SHA256_PATTERN)
    crash_class: AppleCrashClass
    exploitability: AppleExploitability
    target_flag_observed: bool = False


class AppleCVEPackage(DomainModel):
    policy_version: str = "apple-cve-submission-v1"
    candidate_id: str = Field(min_length=1, max_length=200)
    finding_state: FindingState
    baselines: tuple[ApplePlatformBaseline, ...] = Field(max_length=2)
    attempts: tuple[AppleReproductionAttempt, ...] = Field(max_length=20)
    trigger_attachment_sha256: str = Field(pattern=SHA256_PATTERN)
    poc_attachment_sha256: str = Field(pattern=SHA256_PATTERN)
    expected_behavior: str = Field(min_length=1, max_length=2000)
    observed_behavior: str = Field(min_length=1, max_length=2000)
    root_cause: str = Field(min_length=1, max_length=4000)
    attack_scenario: str = Field(min_length=1, max_length=4000)
    real_world_relevance_reviewed: bool
    duplicate_and_advisory_reviewed: bool
    publicly_disclosed: bool = False
    human_review_verdict: HumanReviewVerdict = HumanReviewVerdict.PENDING
    human_reviewer: str = Field(default="", max_length=200)
    human_reviewed_at: datetime | None = None
    working_exploit_supplied: bool = False

    @model_validator(mode="after")
    def validate_human_review_timestamp(self) -> "AppleCVEPackage":
        reviewed = self.human_review_verdict is not HumanReviewVerdict.PENDING
        if reviewed != bool(self.human_reviewer and self.human_reviewed_at):
            raise ValueError(
                "completed human review requires reviewer identity and timestamp"
            )
        if self.human_reviewed_at is not None and self.human_reviewed_at.tzinfo is None:
            raise ValueError("human review time must include a timezone")
        return self


@dataclass(frozen=True)
class AppleCVEPolicyDecision:
    submission_ready: bool
    reasons: tuple[str, ...]
    bounty_evidence_gaps: tuple[str, ...]


class AppleCVEPolicy:
    """Require current stable/beta evidence before Apple submission packaging."""

    version = "apple-cve-submission-v1"
    attempts_per_channel = 3

    def evaluate(self, package: AppleCVEPackage) -> AppleCVEPolicyDecision:
        reasons: list[str] = []
        bounty_gaps: list[str] = []

        if package.finding_state is not FindingState.REPORTABLE:
            reasons.append("generic finding has not reached reportable state")
        if package.publicly_disclosed:
            reasons.append("candidate was publicly disclosed before Apple resolution")
        if package.human_review_verdict is not HumanReviewVerdict.VERIFIED:
            reasons.append("independent human review is not verified")
        if not package.real_world_relevance_reviewed:
            reasons.append("real-world attack relevance has not been reviewed")
        if not package.duplicate_and_advisory_reviewed:
            reasons.append("known-issue and Apple advisory review is incomplete")

        baseline_by_channel: dict[AppleReleaseChannel, ApplePlatformBaseline] = {}
        for baseline in package.baselines:
            if baseline.channel in baseline_by_channel:
                reasons.append(f"duplicate {baseline.channel.value} baseline")
            baseline_by_channel[baseline.channel] = baseline

        all_attempts: list[AppleReproductionAttempt] = []
        for channel in AppleReleaseChannel:
            current_baseline = baseline_by_channel.get(channel)
            if current_baseline is None:
                reasons.append(f"latest {channel.value} baseline is missing")
                continue
            if not current_baseline.is_latest_public:
                reasons.append(f"{channel.value} baseline is not marked latest public")
            matching = [
                attempt
                for attempt in package.attempts
                if attempt.channel is channel
                and attempt.product_version == current_baseline.product_version
                and attempt.build_version == current_baseline.build_version
            ]
            all_attempts.extend(matching)
            self._evaluate_channel(channel, matching, reasons)

        if len(all_attempts) != len(package.attempts):
            reasons.append("attempt evidence includes a build outside the frozen baselines")
        if all_attempts:
            self._evaluate_cross_build(package, all_attempts, reasons, bounty_gaps)

        if not package.working_exploit_supplied:
            bounty_gaps.append(
                "working exploit is not supplied; CVE review may proceed but maximum "
                "bounty evidence is incomplete"
            )

        return AppleCVEPolicyDecision(
            submission_ready=not reasons,
            reasons=tuple(dict.fromkeys(reasons)),
            bounty_evidence_gaps=tuple(dict.fromkeys(bounty_gaps)),
        )

    def _evaluate_channel(
        self,
        channel: AppleReleaseChannel,
        attempts: list[AppleReproductionAttempt],
        reasons: list[str],
    ) -> None:
        label = channel.value
        if len(attempts) < self.attempts_per_channel:
            reasons.append(
                f"{label} requires {self.attempts_per_channel} clean reproductions"
            )
            return
        numbers = {attempt.attempt for attempt in attempts}
        if numbers != set(range(1, len(attempts) + 1)):
            reasons.append(f"{label} attempt numbers are not contiguous")
        if any(not attempt.standard_configuration for attempt in attempts):
            reasons.append(f"{label} reproduction did not use a standard configuration")
        if any(not attempt.clean_snapshot for attempt in attempts):
            reasons.append(f"{label} reproduction did not start from a clean snapshot")
        if any(attempt.timed_out for attempt in attempts):
            reasons.append(f"{label} reproduction contains a timeout")

    def _evaluate_cross_build(
        self,
        package: AppleCVEPackage,
        attempts: list[AppleReproductionAttempt],
        reasons: list[str],
        bounty_gaps: list[str],
    ) -> None:
        if {attempt.trigger_sha256 for attempt in attempts} != {
            package.trigger_attachment_sha256
        }:
            reasons.append("reproductions do not use the attached trigger")
        if {attempt.poc_sha256 for attempt in attempts} != {
            package.poc_attachment_sha256
        }:
            reasons.append("reproductions do not use the attached PoC")
        if len({attempt.root_cause_fingerprint for attempt in attempts}) != 1:
            reasons.append("stable and beta evidence do not share one root cause")
        if any(
            attempt.crash_class
            in {AppleCrashClass.ASSERTION, AppleCrashClass.NULL_DEREFERENCE}
            for attempt in attempts
        ):
            reasons.append("assertion and NULL-dereference crashes are not submission-ready")
        if any(
            attempt.exploitability is AppleExploitability.CRASH_ONLY
            for attempt in attempts
        ):
            reasons.append("crash-only evidence lacks a reviewed security impact")

        controlled = {
            AppleExploitability.REGISTER_CONTROL,
            AppleExploitability.ARBITRARY_READ,
            AppleExploitability.ARBITRARY_WRITE,
            AppleExploitability.CODE_EXECUTION,
        }
        if any(attempt.exploitability in controlled for attempt in attempts) and not all(
            attempt.target_flag_observed for attempt in attempts
        ):
            bounty_gaps.append(
                "claimed attacker control is not confirmed with the applicable "
                "Apple Target Flag"
            )
