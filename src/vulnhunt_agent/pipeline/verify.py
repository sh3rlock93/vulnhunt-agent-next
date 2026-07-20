"""Step 8: independent reproduction, evidence review, and strict reporting."""
from __future__ import annotations

from dataclasses import asdict

from ..core.events import EventBus
from ..core.llm import LLMClient
from ..core.run_store import RunStore
from ..core.v2_run import (
    assert_source_snapshot_current,
    v2_artifact_store,
    v2_repository,
)
from ..reviewing.agent import EvidenceReviewerAgent
from ..sandbox.hardened import HardenedDockerBackend
from ..verification.service import VerifiedPipelineService
from .registry import Step, register


async def run_verify(store: RunStore, bus: EventBus) -> None:
    config = store.load_config() or {}
    prepare = store.load_step("sandbox_prepare") or {}
    assert_source_snapshot_current(store)
    model_value = (
        config.get("model_id_reviewer")
        or config.get("model_id")
    )
    if not isinstance(model_value, str) or not model_value.strip():
        raise ValueError("verified review requires a configured model")
    model_id = model_value.strip()
    client = LLMClient(model_id=model_id)
    reviewers = [
        EvidenceReviewerAgent(
            client=client,
            reviewer="evidence-reviewer-reachability",
            model_id=model_id,
            prompt_variant="challenge reachability, guards, and attacker control",
        ),
        EvidenceReviewerAgent(
            client=client,
            reviewer="evidence-reviewer-impact",
            model_id=model_id,
            prompt_variant="challenge impact, mitigations, and deployment assumptions",
        ),
    ]
    bus.emit(
        "step_start",
        step="verify",
        image=prepare.get("image", ""),
        reviewers=[item.reviewer for item in reviewers],
    )
    with v2_repository(store) as repository:
        summary = await VerifiedPipelineService(
            repository,
            v2_artifact_store(store),
            HardenedDockerBackend(),
            reviewers,
            output_root=store.dir / "verified",
        ).verify(
            run_id=store.dir.name,
            run_dir=store.dir,
            image=str(prepare.get("image") or ""),
        )
    result = asdict(summary)
    store.save_step("verify", result)
    bus.emit(
        "step_done",
        step="verify",
        candidates=summary.candidates,
        reports=summary.reports,
        errors=len(summary.errors),
    )


register(Step(
    name="verify",
    title="8. Verified Findings",
    fn=run_verify,
    depends_on=["hunt"],
))
