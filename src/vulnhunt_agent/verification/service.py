"""End-to-end promotion from Hunter candidates to strict verified reports."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from ..domain.compat import candidate_from_legacy
from ..domain.schemas import (
    CandidateResolution,
    CandidateFinding,
    ConsensusStatus,
    FeasibilityAssessment,
    FeasibilityStatus,
    PocSpec,
    ReproductionSpec,
    ReproductionVariantRequest,
    ResolutionDisposition,
    VerificationDeferredReason,
)
from ..domain.states import RUN_SEQUENCE, FindingState, RunState
from ..infrastructure.artifacts import ArtifactStore
from ..infrastructure.sqlite_repository import SqliteRepository
from ..reporting.service import StrictReportService
from ..reproduction.service import ReproducerService, ReproductionStatus
from ..reproduction.variants import (
    LLMVariantCompiler,
    ReproductionVariantExecutor,
    VariantCompiler,
)
from ..reproduction.planning import ExperimentPlanStatus
from ..reviewing.agent import EvidenceReviewerAgent
from ..reviewing.service import EvidenceReviewCoordinator
from ..sandbox.base import SandboxBackend
from .recipe import CompiledRecipe, RecipeDecision, validate_recorded_recipe
from .feasibility import assess_native_feasibility
from .synthesis import (
    LLMRecipeSynthesizer,
    RecipeSynthesizer,
    SynthesisDecision,
)


@dataclass(frozen=True)
class _HunterFinding:
    raw: dict
    task_key: str
    recipe: RecipeDecision


@dataclass(frozen=True)
class VerificationSummary:
    candidates: int
    recipes_accepted: int
    recipes_rejected: int
    states: dict[str, int]
    reports: int
    variants_executed: int = 0
    variants_failed: int = 0
    experiment_plans: int = 0
    experiment_plans_deferred: int = 0
    automatic_rereviews: int = 0
    synthesis_attempts: int = 0
    feasibility: dict[str, int] | None = None
    resolutions: dict[str, int] | None = None
    errors: tuple[str, ...] = ()


class VerifiedPipelineService:
    def __init__(
        self,
        repository: SqliteRepository,
        artifacts: ArtifactStore,
        backend: SandboxBackend,
        reviewers: list[EvidenceReviewerAgent],
        *,
        output_root: Path,
        variant_compiler: VariantCompiler | None = None,
        source_root: Path | None = None,
        analysis: dict | None = None,
        recipe_synthesizer: RecipeSynthesizer | None = None,
    ):
        self.repository = repository
        self.artifacts = artifacts
        self.backend = backend
        self.reviewers = reviewers
        self.output_root = output_root
        self.variant_compiler = variant_compiler
        self.source_root = source_root
        self.analysis = analysis or {}
        self.recipe_synthesizer = recipe_synthesizer

    async def verify(
        self,
        *,
        run_id: str,
        run_dir: Path,
        image: str,
    ) -> VerificationSummary:
        run = self.repository.get_run(run_id)
        if run is None or run.source_snapshot is None:
            raise ValueError("verified pipeline requires an immutable run snapshot")
        grouped = self._group_findings(run_id, run_dir)
        accepted = sum(1 for item in grouped.values() if item.recipe.recipe)
        rejected = sum(
            1
            for item in grouped.values()
            if item.raw.get("status") == "confirmed" and item.recipe.recipe is None
        )
        errors: list[str] = []
        synthesis_attempts = 0
        synthesizer = self.recipe_synthesizer
        if synthesizer is None and self.reviewers:
            synthesizer = LLMRecipeSynthesizer(self.reviewers[0].client)

        self._advance_run(run_id, RunState.REPRODUCING)
        candidates = []
        for fingerprint, item in sorted(grouped.items()):
            finding = self._save_candidate(run_id, fingerprint, item)
            candidates.append(finding.candidate_id)
            if finding.resolution is not None:
                continue
            assessment = finding.feasibility or assess_native_feasibility(
                finding,
                source_root=self.source_root,
                source_snapshot=run.source_snapshot,
                analysis=self.analysis,
            )
            finding = self.repository.attach_candidate_feasibility(
                finding.candidate_id,
                assessment,
            )
            if assessment.status is FeasibilityStatus.LOGICALLY_INFEASIBLE:
                if finding.state is FindingState.STATICALLY_SUPPORTED:
                    finding = self.repository.transition_finding(
                        finding.candidate_id,
                        FindingState.STATICALLY_REFUTED,
                        idempotency_key="native-feasibility-v1:refuted",
                        reason="source-cited feasibility bounds prove a contradiction",
                    )
                self.repository.attach_candidate_resolution(
                    finding.candidate_id,
                    CandidateResolution(
                        disposition=ResolutionDisposition.STATICALLY_REFUTED,
                        feasibility_status=assessment.status,
                        reason="minimum trigger input exceeds the reachable source-backed maximum",
                    ),
                )
                continue
            recipe = item.recipe.recipe
            if recipe is None:
                decision = SynthesisDecision(
                    recipe=None,
                    attempted=False,
                    error="no recipe synthesizer is configured",
                )
                if synthesizer is not None and self.source_root is not None:
                    decision = await self._synthesize_once(
                        run_id,
                        finding,
                        assessment,
                        synthesizer,
                    )
                    synthesis_attempts += int(decision.attempted)
                recipe = decision.recipe
                if recipe is None:
                    self._defer(
                        finding.candidate_id,
                        assessment.status,
                        reason=decision.error or "no valid reproduction recipe was produced",
                        deferred_reason=VerificationDeferredReason.RECIPE_UNAVAILABLE,
                        remaining_requirement=(
                            "Provide one validated actual-target reproduction recipe."
                        ),
                        synthesis_attempts=self._synthesis_attempts(
                            run_id, finding.candidate_id
                        ),
                    )
                    continue
            try:
                finding = self._attach_poc(finding.candidate_id, recipe)
                if not image:
                    self._defer(
                        finding.candidate_id,
                        assessment.status,
                        reason="no prepared image is available for reproduction",
                        deferred_reason=(
                            VerificationDeferredReason.PREPARED_TARGET_UNAVAILABLE
                        ),
                        remaining_requirement=(
                            "Prepare the immutable target image and rerun reproduction."
                        ),
                        synthesis_attempts=self._synthesis_attempts(
                            run_id, finding.candidate_id
                        ),
                    )
                    continue
                if finding.state is FindingState.POC_READY:
                    outcome = await ReproducerService(
                        self.repository, self.artifacts, self.backend
                    ).reproduce(ReproductionSpec(
                        reproduction_id=f"repro-{finding.candidate_id}-v1",
                        run_id=run_id,
                        candidate_id=finding.candidate_id,
                        source_snapshot=run.source_snapshot,
                        image=image,
                        poc_artifact=finding.poc.artifact,
                        poc_path=recipe.poc_relative,
                        setup_argvs=recipe.setup_argvs,
                        argv=recipe.argv,
                        cwd=recipe.cwd,
                        oracle=recipe.oracle,
                        attempts=2,
                        timeout_seconds=recipe.timeout,
                    ))
                    if outcome.status is not ReproductionStatus.REPRODUCED:
                        self._resolve_reproduction_failure(
                            finding.candidate_id,
                            assessment.status,
                            outcome.status,
                            synthesis_attempts=self._synthesis_attempts(
                                run_id, finding.candidate_id
                            ),
                        )
            except Exception as exc:
                errors.append(f"{finding.candidate_id}: reproduction: {exc}")

        self._advance_run(run_id, RunState.REVIEWING)
        coordinator = EvidenceReviewCoordinator(self.repository, self.artifacts)
        compiler = self.variant_compiler
        if compiler is None and self.reviewers:
            compiler = LLMVariantCompiler(self.reviewers[0].client)
        variant_executor = (
            ReproductionVariantExecutor(
                self.repository,
                self.artifacts,
                self.backend,
                compiler,
            )
            if compiler is not None
            else None
        )
        variants_executed = 0
        variants_failed = 0
        experiment_plans = 0
        experiment_plans_deferred = 0
        automatic_rereviews = 0
        for candidate_id in candidates:
            finding = self.repository.get_candidate(candidate_id)
            if finding is None or finding.state is not FindingState.REPRODUCED:
                continue
            try:
                decision = await coordinator.review(candidate_id, self.reviewers)
                for _ in range(2):
                    if decision.status is not ConsensusStatus.VARIANT_REQUESTED:
                        break
                    request = self._variant_request(run_id, candidate_id)
                    if request is None or variant_executor is None:
                        raise RuntimeError("variant request has no available executor")
                    execution = await variant_executor.execute(request)
                    if execution.plan is not None:
                        experiment_plans += 1
                    if (
                        execution.plan is not None
                        and execution.plan.status is not ExperimentPlanStatus.READY
                    ):
                        experiment_plans_deferred += 1
                        self._defer(
                            candidate_id,
                            finding.feasibility.status if finding.feasibility else (
                                FeasibilityStatus.UNKNOWN
                            ),
                            reason=execution.plan.rationale,
                            deferred_reason=(
                                VerificationDeferredReason.EXPERIMENT_PLAN_UNSUPPORTED
                            ),
                            remaining_requirement=(
                                execution.plan.remaining_requirement
                                or "Provide an executable conforming experiment plan."
                            ),
                            synthesis_attempts=self._synthesis_attempts(
                                run_id, candidate_id
                            ),
                        )
                        break
                    if execution.outcome.status.value == "in_progress":
                        break
                    variants_executed += 1
                    if execution.outcome.error:
                        variants_failed += 1
                        errors.append(
                            f"{candidate_id}: variant {request.request_id}: "
                            f"{execution.outcome.error}"
                        )
                        break
                    automatic_rereviews += 1
                    decision = await coordinator.review(candidate_id, self.reviewers)
            except Exception as exc:
                errors.append(f"{candidate_id}: review: {exc}")

        self._advance_run(run_id, RunState.REPORTING)
        reports = 0
        reporter = StrictReportService(self.repository, self.artifacts)
        for candidate_id in candidates:
            finding = self.repository.get_candidate(candidate_id)
            if finding is None:
                continue
            if finding.state is FindingState.REVIEWER_VERIFIED:
                try:
                    self._attach_confirmed_resolution(finding)
                    reporter.materialize(
                        self.output_root,
                        run_id=run_id,
                        candidate_id=candidate_id,
                    )
                    reports += 1
                except Exception as exc:
                    errors.append(f"{candidate_id}: report: {exc}")
            elif finding.state is FindingState.REPORTABLE:
                self._attach_confirmed_resolution(finding)
                reports += 1

        for candidate_id in candidates:
            self._finalize_resolution(candidate_id)

        self._advance_run(run_id, RunState.COMPLETED)
        state_counts = Counter(
            item.state.value
            for item in self.repository.list_candidates(run_id)
        )
        final_candidates = self.repository.list_candidates(run_id)
        feasibility_counts = Counter(
            item.feasibility.status.value
            for item in final_candidates
            if item.feasibility is not None
        )
        resolution_counts = Counter(
            item.resolution.disposition.value
            for item in final_candidates
            if item.resolution is not None
        )
        return VerificationSummary(
            candidates=len(candidates),
            recipes_accepted=accepted,
            recipes_rejected=rejected,
            states=dict(sorted(state_counts.items())),
            reports=reports,
            variants_executed=variants_executed,
            variants_failed=variants_failed,
            experiment_plans=experiment_plans,
            experiment_plans_deferred=experiment_plans_deferred,
            automatic_rereviews=automatic_rereviews,
            synthesis_attempts=synthesis_attempts,
            feasibility=dict(sorted(feasibility_counts.items())),
            resolutions=dict(sorted(resolution_counts.items())),
            errors=tuple(errors),
        )

    async def _synthesize_once(
        self,
        run_id: str,
        finding: CandidateFinding,
        assessment: FeasibilityAssessment,
        synthesizer: RecipeSynthesizer,
    ) -> SynthesisDecision:
        payload = {
            "policy_version": "recipe-synthesis-v1",
            "candidate_id": finding.candidate_id,
            "source_snapshot": assessment.source_snapshot,
        }
        self.repository.ensure_task(
            run_id,
            "recipe_synthesis",
            finding.candidate_id,
            payload=payload,
        )
        lease = self.repository.acquire_task_lease(
            run_id,
            "recipe_synthesis",
            finding.candidate_id,
            worker_id="verified-recipe-synthesizer",
            lease_seconds=600,
            max_attempts=1,
        )
        if lease is None:
            task = next(
                item for item in self.repository.list_tasks(run_id)
                if item["task_type"] == "recipe_synthesis"
                and item["task_key"] == finding.candidate_id
            )
            return SynthesisDecision(
                None,
                False,
                f"bounded recipe synthesis already ended as {task['status']}",
            )
        try:
            assert self.source_root is not None
            decision = await synthesizer.synthesize(
                finding,
                assessment,
                source_root=self.source_root,
                output_root=self.output_root,
            )
        except Exception as exc:
            decision = SynthesisDecision(
                recipe=None,
                attempted=True,
                error=f"recipe synthesis failed: {exc}",
            )
        self.repository.finish_task_lease(
            lease,
            status="accepted" if decision.recipe is not None else "rejected",
            error=decision.error,
        )
        return decision

    def _synthesis_attempts(self, run_id: str, candidate_id: str) -> int:
        return int(any(
            item["task_type"] == "recipe_synthesis"
            and item["task_key"] == candidate_id
            for item in self.repository.list_tasks(run_id)
        ))

    def _attach_confirmed_resolution(self, finding: CandidateFinding) -> None:
        if finding.resolution is not None:
            return
        feasibility_status = (
            finding.feasibility.status
            if finding.feasibility is not None
            else FeasibilityStatus.UNKNOWN
        )
        self.repository.attach_candidate_resolution(
            finding.candidate_id,
            CandidateResolution(
                disposition=ResolutionDisposition.CONFIRMED,
                feasibility_status=feasibility_status,
                synthesis_attempts=self._synthesis_attempts(
                    finding.run_id, finding.candidate_id
                ),
                reason="prepared-target reproduction and independent review passed",
            ),
        )

    def _defer(
        self,
        candidate_id: str,
        feasibility_status: FeasibilityStatus,
        *,
        reason: str,
        deferred_reason: VerificationDeferredReason,
        remaining_requirement: str,
        synthesis_attempts: int,
    ) -> None:
        finding = self.repository.get_candidate(candidate_id)
        if finding is None:
            raise KeyError(candidate_id)
        if finding.state is not FindingState.VERIFICATION_DEFERRED:
            self.repository.transition_finding(
                candidate_id,
                FindingState.VERIFICATION_DEFERRED,
                idempotency_key=f"candidate-resolution-v1:{deferred_reason.value}",
                reason=reason,
            )
        self.repository.attach_candidate_resolution(
            candidate_id,
            CandidateResolution(
                disposition=ResolutionDisposition.VERIFICATION_DEFERRED,
                feasibility_status=feasibility_status,
                synthesis_attempts=synthesis_attempts,
                reason=reason[:1000],
                deferred_reason=deferred_reason,
                remaining_requirement=remaining_requirement,
            ),
        )

    def _resolve_reproduction_failure(
        self,
        candidate_id: str,
        feasibility_status: FeasibilityStatus,
        status: ReproductionStatus,
        *,
        synthesis_attempts: int,
    ) -> None:
        finding = self.repository.get_candidate(candidate_id)
        if finding is None or finding.resolution is not None:
            return
        if status in {
            ReproductionStatus.UNVERIFIED,
            ReproductionStatus.ENVIRONMENT_BLOCKED,
        }:
            deferred_reason = (
                VerificationDeferredReason.TARGET_PROVENANCE_MISSING
                if status is ReproductionStatus.UNVERIFIED
                else VerificationDeferredReason.PREPARED_TARGET_UNAVAILABLE
            )
            self.repository.attach_candidate_resolution(
                candidate_id,
                CandidateResolution(
                    disposition=ResolutionDisposition.VERIFICATION_DEFERRED,
                    feasibility_status=feasibility_status,
                    synthesis_attempts=synthesis_attempts,
                    reason=f"reproduction ended as {status.value}",
                    deferred_reason=deferred_reason,
                    remaining_requirement=(
                        "Produce two clean attempts with prepared-target provenance."
                    ),
                ),
            )
            return
        self.repository.attach_candidate_resolution(
            candidate_id,
            CandidateResolution(
                disposition=ResolutionDisposition.REPRODUCTION_REJECTED,
                feasibility_status=feasibility_status,
                synthesis_attempts=synthesis_attempts,
                reason=f"independent reproduction ended as {status.value}",
            ),
        )

    def _finalize_resolution(self, candidate_id: str) -> None:
        finding = self.repository.get_candidate(candidate_id)
        if finding is None or finding.resolution is not None:
            return
        feasibility_status = (
            finding.feasibility.status
            if finding.feasibility is not None
            else FeasibilityStatus.UNKNOWN
        )
        if finding.state is FindingState.REPORTABLE:
            self._attach_confirmed_resolution(finding)
            return
        if finding.state is FindingState.REJECTED:
            self.repository.attach_candidate_resolution(
                candidate_id,
                CandidateResolution(
                disposition=ResolutionDisposition.REPRODUCTION_REJECTED,
                feasibility_status=feasibility_status,
                synthesis_attempts=self._synthesis_attempts(
                    finding.run_id, finding.candidate_id
                ),
                    reason="reproduction or evidence review rejected the candidate",
                ),
            )
            return
        reason = "candidate verification did not reach a reportable terminal result"
        if finding.state not in {
            FindingState.UNCLEAR,
            FindingState.ENVIRONMENT_BLOCKED,
            FindingState.POLICY_BLOCKED,
        }:
            self.repository.transition_finding(
                candidate_id,
                FindingState.VERIFICATION_DEFERRED,
                idempotency_key="candidate-resolution-v1:incomplete",
                reason=reason,
            )
        self.repository.attach_candidate_resolution(
            candidate_id,
            CandidateResolution(
                disposition=ResolutionDisposition.VERIFICATION_DEFERRED,
                feasibility_status=feasibility_status,
                synthesis_attempts=self._synthesis_attempts(
                    finding.run_id, finding.candidate_id
                ),
                reason=reason,
                deferred_reason=VerificationDeferredReason.REVIEW_INCONCLUSIVE,
                remaining_requirement="Resolve the remaining reproduction or review uncertainty.",
            ),
        )

    def _variant_request(
        self,
        run_id: str,
        candidate_id: str,
    ) -> ReproductionVariantRequest | None:
        tasks = [
            task for task in self.repository.list_tasks(run_id)
            if task["task_type"] == "reproduction_variant"
            and task["payload"].get("candidate_id") == candidate_id
        ]
        if not tasks:
            return None
        active = [
            task for task in tasks if task["status"] in {"pending", "running"}
        ]
        selected = (active or tasks)[-1]
        return ReproductionVariantRequest.model_validate(selected["payload"])

    def _group_findings(
        self,
        run_id: str,
        run_dir: Path,
    ) -> dict[str, _HunterFinding]:
        grouped: dict[str, _HunterFinding] = {}
        hunters_root = run_dir / "hunters"
        if not hunters_root.exists():
            return grouped
        for findings_path in sorted(hunters_root.glob("*/hunts/*/findings.json")):
            payload = json.loads(findings_path.read_text())
            pocs_root = findings_path.parent / "pocs"
            relative = findings_path.relative_to(run_dir).as_posix()
            for raw in payload.get("findings", []):
                task_key = relative
                seed = candidate_from_legacy(raw, run_id=run_id, task_key=task_key)
                item = _HunterFinding(
                    raw=raw,
                    task_key=task_key,
                    recipe=validate_recorded_recipe(raw, payload, pocs_root),
                )
                previous = grouped.get(seed.fingerprint)
                if previous is None or (
                    previous.recipe.recipe is None and item.recipe.recipe is not None
                ):
                    grouped[seed.fingerprint] = item
        return grouped

    def _save_candidate(
        self,
        run_id: str,
        fingerprint: str,
        item: _HunterFinding,
    ):
        task_key = f"verified:{fingerprint}"
        seed = candidate_from_legacy(
            item.raw,
            run_id=run_id,
            task_key=task_key,
        )
        candidate_id = _candidate_id(run_id, fingerprint)
        initial = seed.model_copy(update={
            "candidate_id": candidate_id,
            "task_key": task_key,
            "state": FindingState.HYPOTHESIS,
            "evidence_ids": (),
            "poc": None,
        })
        existing = self.repository.get_candidate(candidate_id)
        if existing is not None:
            if _immutable_candidate_data(existing) != _immutable_candidate_data(initial):
                raise ValueError(
                    f"verified candidate changed during replay: {candidate_id}"
                )
            finding = existing
        else:
            finding, _ = self.repository.save_candidate(initial)
        if finding.state is FindingState.HYPOTHESIS:
            finding = self.repository.transition_finding(
                finding.candidate_id,
                FindingState.STATICALLY_SUPPORTED,
                idempotency_key="verified:statically-supported",
                reason="validated Hunter candidate imported into V2",
            )
        return finding

    def _attach_poc(self, candidate_id: str, recipe: CompiledRecipe):
        finding = self.repository.get_candidate(candidate_id)
        if finding is None:
            raise KeyError(candidate_id)
        if finding.poc is None:
            artifact = self.artifacts.put_file(
                recipe.poc_path,
                "text/plain; charset=utf-8",
            )
            self.repository.register_artifact(artifact)
            finding = self.repository.attach_candidate_poc(
                candidate_id,
                PocSpec(
                    artifact=artifact.digest,
                    setup_argvs=recipe.setup_argvs,
                    argv=recipe.argv,
                    cwd=recipe.cwd,
                ),
            )
        if finding.state is FindingState.STATICALLY_SUPPORTED:
            finding = self.repository.transition_finding(
                candidate_id,
                FindingState.POC_READY,
                idempotency_key="verified:poc-ready",
                reason="recorded recipe matched Hunter tool execution",
            )
        return finding

    def _advance_run(self, run_id: str, target: RunState) -> None:
        run = self.repository.get_run(run_id)
        if run is None or run.state not in RUN_SEQUENCE:
            return
        current = RUN_SEQUENCE.index(run.state)
        desired = RUN_SEQUENCE.index(target)
        for state in RUN_SEQUENCE[current + 1 : desired + 1]:
            run = self.repository.transition_run(
                run_id,
                state,
                idempotency_key=f"verified:{state.value}",
                reason="verified finding pipeline",
            )


def _candidate_id(run_id: str, fingerprint: str) -> str:
    digest = hashlib.sha256(f"{run_id}\0{fingerprint}".encode()).hexdigest()[:26]
    return f"cand_verified_{digest}"


def _immutable_candidate_data(finding: CandidateFinding) -> dict:
    return finding.model_dump(exclude={
        "state",
        "evidence_ids",
        "poc",
        "feasibility",
        "resolution",
        "created_at",
        "updated_at",
    })
