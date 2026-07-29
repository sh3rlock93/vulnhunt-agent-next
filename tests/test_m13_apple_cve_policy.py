from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from vulnhunt_agent.domain.states import FindingState
from vulnhunt_agent.reporting.apple_cve import (
    AppleCrashClass,
    AppleCVEPackage,
    AppleCVEPolicy,
    AppleExploitability,
    ApplePlatformBaseline,
    AppleReleaseChannel,
    AppleReproductionAttempt,
    HumanReviewVerdict,
)

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64
NOW = datetime(2026, 7, 29, tzinfo=UTC)


def _baseline(
    channel: AppleReleaseChannel,
    version: str,
    build: str,
    *,
    latest: bool = True,
) -> ApplePlatformBaseline:
    return ApplePlatformBaseline(
        channel=channel,
        product_version=version,
        build_version=build,
        is_latest_public=latest,
        observed_at=NOW,
        official_release_url="https://support.apple.com/en-us/128067",
    )


def _attempts(
    channel: AppleReleaseChannel,
    version: str,
    build: str,
    *,
    crash_class: AppleCrashClass = AppleCrashClass.OUT_OF_BOUNDS_WRITE,
    exploitability: AppleExploitability = AppleExploitability.MEMORY_CORRUPTION,
    target_flag: bool = False,
) -> tuple[AppleReproductionAttempt, ...]:
    return tuple(
        AppleReproductionAttempt(
            attempt=index,
            channel=channel,
            product_version=version,
            build_version=build,
            hardware_model="Mac17,8",
            standard_configuration=True,
            clean_snapshot=True,
            trigger_sha256=SHA_A,
            poc_sha256=SHA_B,
            crash_log_sha256=SHA_C,
            root_cause_fingerprint=SHA_D,
            crash_class=crash_class,
            exploitability=exploitability,
            target_flag_observed=target_flag,
        )
        for index in range(1, 4)
    )


def _package(**updates: object) -> AppleCVEPackage:
    stable = _baseline(AppleReleaseChannel.STABLE, "26.6", "25G84")
    beta = _baseline(AppleReleaseChannel.PUBLIC_BETA, "27.0", "26A5380h")
    values: dict[str, object] = {
        "candidate_id": "imageio-candidate-1",
        "finding_state": FindingState.REPORTABLE,
        "baselines": (stable, beta),
        "attempts": (
            *_attempts(AppleReleaseChannel.STABLE, "26.6", "25G84"),
            *_attempts(AppleReleaseChannel.PUBLIC_BETA, "27.0", "26A5380h"),
        ),
        "trigger_attachment_sha256": SHA_A,
        "poc_attachment_sha256": SHA_B,
        "expected_behavior": "ImageIO rejects the malformed image.",
        "observed_behavior": "ImageIO writes outside the decoded image buffer.",
        "root_cause": "A validated dimension is not used for the destination stride.",
        "attack_scenario": "A user previews an attacker-controlled image attachment.",
        "real_world_relevance_reviewed": True,
        "duplicate_and_advisory_reviewed": True,
        "human_review_verdict": HumanReviewVerdict.VERIFIED,
        "human_reviewer": "independent-reviewer",
        "human_reviewed_at": NOW,
    }
    values.update(updates)
    return AppleCVEPackage.model_validate(values)


def test_current_stable_and_beta_package_is_submission_ready() -> None:
    decision = AppleCVEPolicy().evaluate(_package())

    assert decision.submission_ready is True
    assert decision.reasons == ()
    assert decision.bounty_evidence_gaps == (
        "working exploit is not supplied; CVE review may proceed but maximum bounty "
        "evidence is incomplete",
    )


def test_outdated_host_attempt_is_not_accepted_for_current_baseline() -> None:
    package = _package(
        attempts=(
            *_attempts(AppleReleaseChannel.STABLE, "26.5.2", "25F84"),
            *_attempts(AppleReleaseChannel.PUBLIC_BETA, "27.0", "26A5380h"),
        )
    )

    decision = AppleCVEPolicy().evaluate(package)

    assert decision.submission_ready is False
    assert "stable requires 3 clean reproductions" in decision.reasons
    assert "attempt evidence includes a build outside the frozen baselines" in decision.reasons


@pytest.mark.parametrize(
    ("updates", "reason"),
    [
        ({"baselines": (_baseline(AppleReleaseChannel.STABLE, "26.6", "25G84"),)},
         "latest public_beta baseline is missing"),
        ({"finding_state": FindingState.REVIEWER_VERIFIED},
         "generic finding has not reached reportable state"),
        ({"publicly_disclosed": True},
         "candidate was publicly disclosed before Apple resolution"),
        ({"human_review_verdict": HumanReviewVerdict.REJECTED},
         "independent human review is not verified"),
        ({"duplicate_and_advisory_reviewed": False},
         "known-issue and Apple advisory review is incomplete"),
    ],
)
def test_submission_gate_rejects_incomplete_package(
    updates: dict[str, object],
    reason: str,
) -> None:
    if updates.get("human_review_verdict") is HumanReviewVerdict.REJECTED:
        updates = {
            **updates,
            "human_reviewer": "independent-reviewer",
            "human_reviewed_at": NOW,
        }
    decision = AppleCVEPolicy().evaluate(_package(**updates))

    assert decision.submission_ready is False
    assert reason in decision.reasons


@pytest.mark.parametrize(
    "crash_class",
    [AppleCrashClass.ASSERTION, AppleCrashClass.NULL_DEREFERENCE],
)
def test_assertion_and_null_crashes_are_not_submission_ready(
    crash_class: AppleCrashClass,
) -> None:
    package = _package(
        attempts=(
            *_attempts(
                AppleReleaseChannel.STABLE,
                "26.6",
                "25G84",
                crash_class=crash_class,
                exploitability=AppleExploitability.CRASH_ONLY,
            ),
            *_attempts(
                AppleReleaseChannel.PUBLIC_BETA,
                "27.0",
                "26A5380h",
                crash_class=crash_class,
                exploitability=AppleExploitability.CRASH_ONLY,
            ),
        )
    )

    decision = AppleCVEPolicy().evaluate(package)

    assert decision.submission_ready is False
    assert "assertion and NULL-dereference crashes are not submission-ready" in decision.reasons
    assert "crash-only evidence lacks a reviewed security impact" in decision.reasons


def test_claimed_control_records_target_flag_as_bounty_gap() -> None:
    package = _package(
        attempts=(
            *_attempts(
                AppleReleaseChannel.STABLE,
                "26.6",
                "25G84",
                exploitability=AppleExploitability.ARBITRARY_WRITE,
            ),
            *_attempts(
                AppleReleaseChannel.PUBLIC_BETA,
                "27.0",
                "26A5380h",
                exploitability=AppleExploitability.ARBITRARY_WRITE,
            ),
        ),
        working_exploit_supplied=True,
    )

    decision = AppleCVEPolicy().evaluate(package)

    assert decision.submission_ready is True
    assert decision.bounty_evidence_gaps == (
        "claimed attacker control is not confirmed with the applicable Apple Target Flag",
    )


def test_human_review_requires_identity_and_aware_timestamp() -> None:
    with pytest.raises(ValidationError, match="reviewer identity and timestamp"):
        _package(human_reviewer="", human_reviewed_at=None)

    with pytest.raises(ValidationError, match="include a timezone"):
        _package(human_reviewed_at=datetime(2026, 7, 29))
