from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

from vulnhunt_agent.analysis import build_c_analysis_graph
from vulnhunt_agent.core.llm import LLMClient, LLMResponse
from vulnhunt_agent.core.run_store import RunStore
from vulnhunt_agent.core.v2_run import ensure_source_snapshot, v2_artifact_store
from vulnhunt_agent.domain.schemas import (
    CandidateFinding,
    CodeLocation,
    FeasibilityAssessment,
    FeasibilityStatus,
    ResolutionDisposition,
)
from vulnhunt_agent.domain.states import FindingState
from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
from vulnhunt_agent.verification.feasibility import assess_native_feasibility
from vulnhunt_agent.verification.service import VerifiedPipelineService
from vulnhunt_agent.verification.synthesis import (
    LLMRecipeSynthesizer,
    SynthesisDecision,
)


class NoopBackend:
    async def execute(self, job):  # pragma: no cover - must not run in these tests
        raise AssertionError(job)


class CountingUnavailableSynthesizer:
    def __init__(self) -> None:
        self.calls = 0

    async def synthesize(self, candidate, assessment, *, source_root, output_root):
        self.calls += 1
        return SynthesisDecision(None, True, "fixture could not build a target recipe")


class SynthesisClient:
    def __init__(self, *, actual_target: bool) -> None:
        self.actual_target = actual_target
        self.calls = 0

    async def chat(self, **kwargs) -> LLMResponse:
        self.calls += 1
        target = (
            "/workspace/source/target.c"
            if self.actual_target
            else "/workspace/poc/model.c"
        )
        payload = {
            "poc_filename": "poc.c",
            "poc_source": "int main(void) { return 0; }\n",
            "setup_argvs": [[
                "cc",
                "-fsanitize=address",
                "/workspace/poc/poc.c",
                target,
                "-o",
                "/workspace/exec/poc",
            ]],
            "argv": ["/workspace/exec/poc"],
            "cwd": ".",
            "timeout": 30,
            "oracle": {
                "type": "combined_regex",
                "pattern": "AddressSanitizer.*buffer-overflow",
            },
        }
        text = json.dumps(payload)
        return LLMResponse(
            text=text,
            input_tokens=10,
            output_tokens=10,
            cache_read_tokens=0,
            cache_write_tokens=0,
            stop_reason="end_turn",
            content_blocks=[{"text": text}],
        )


def _fixture(tmp_path: Path, counter_type: str, *, with_public_max: bool) -> tuple:
    repo = tmp_path / f"fixture-{counter_type.replace(' ', '-')}-{with_public_max}"
    repo.mkdir()
    target = repo / "target.c"
    target.write_text(
        f"""#include <stdint.h>
int count_records(const char *cursor, int slots, const char **out) {{
  {counter_type} record_count = 0;
  for (cursor += 1;; cursor += 1) {{
    if (*cursor == 0) return record_count;
    if (record_count < slots) out[record_count] = cursor;
    record_count++;
  }}
}}
"""
    )
    files = ["target.c"]
    if with_public_max:
        (repo / "parser.c").write_text(
            """#include <limits.h>
int count_records(const char *, int, const char **);
static void *grow_input(int requested, int retained) {
  int neededSize = requested + retained;
  int keep = retained;
  if (keep > INT_MAX - neededSize) return 0;
  return (void *)1;
}
int parse_object(const char *input, int slots, const char **out) {
  /* The token spans whole input object when count_records is called. */
  return grow_input(slots, 0) ? count_records(input, slots, out) : -1;
}
"""
        )
        files.append("parser.c")
    graph = build_c_analysis_graph(repo, files)
    candidate = CandidateFinding(
        candidate_id=f"cand-{counter_type.replace(' ', '-')}",
        run_id="run-feasibility",
        task_key="fixture",
        title="Signed record counter can overflow",
        weakness="integer_overflow",
        entrypoint=CodeLocation(path="target.c", line=2, symbol="count_records"),
        sink=CodeLocation(path="target.c", line=7, symbol="record_count"),
        attacker_capability="Supply enough records to overflow record_count",
        impact=("Integer overflow followed by an out-of-bounds array index",),
        confidence=0.7,
    )
    assessment = assess_native_feasibility(
        candidate,
        source_root=repo,
        source_snapshot="sha256:" + "a" * 64,
        analysis={"graph": graph.model_dump(mode="json")},
    )
    return repo, candidate, assessment


def test_source_cited_contradiction_refutes_large_counter(tmp_path: Path) -> None:
    _repo, _candidate, assessment = _fixture(
        tmp_path,
        "int",
        with_public_max=True,
    )

    assert assessment.status is FeasibilityStatus.LOGICALLY_INFEASIBLE
    assert [step.operation for step in assessment.arithmetic] == [
        "add",
        "multiply",
        "compare_gt",
    ]
    assert assessment.arithmetic[-1].result == 1
    assert assessment.arithmetic[-1].operands == (2_147_483_648, 2_147_483_647)
    for bound in assessment.bounds:
        assert bound.sources
        for source in bound.sources:
            assert source.source_snapshot == "sha256:" + "a" * 64
            assert source.content_sha256 == (
                "sha256:" + hashlib.sha256(source.excerpt.encode()).hexdigest()
            )


def test_smaller_reachable_limit_survives_static_falsification(tmp_path: Path) -> None:
    _repo, _candidate, assessment = _fixture(
        tmp_path,
        "int8_t",
        with_public_max=True,
    )

    assert assessment.status is FeasibilityStatus.FEASIBLE
    assert assessment.arithmetic[-1].operation == "compare_gt"
    assert assessment.arithmetic[-1].operands == (128, 2_147_483_647)
    assert assessment.arithmetic[-1].result == 0


def test_expensive_but_unbounded_claim_is_not_auto_refuted(tmp_path: Path) -> None:
    _repo, _candidate, assessment = _fixture(
        tmp_path,
        "int",
        with_public_max=False,
    )

    assert assessment.status is FeasibilityStatus.ENVIRONMENTALLY_EXTREME
    assert assessment.confidence_adjustment < 0
    assert all(step.operation != "compare_gt" for step in assessment.arithmetic)


def test_multiple_nonexclusive_increments_are_not_used_as_a_proof(
    tmp_path: Path,
) -> None:
    repo, candidate, _assessment = _fixture(
        tmp_path,
        "int",
        with_public_max=True,
    )
    target = repo / "target.c"
    target.write_text(target.read_text().replace(
        "    record_count++;",
        "    record_count++;\n    record_count++;",
    ))
    graph = build_c_analysis_graph(repo, ["target.c", "parser.c"])

    assessment = assess_native_feasibility(
        candidate,
        source_root=repo,
        source_snapshot="sha256:" + "a" * 64,
        analysis={"graph": graph.model_dump(mode="json")},
    )

    assert assessment.status is FeasibilityStatus.UNKNOWN
    assert not assessment.bounds


async def test_supported_candidate_gets_one_durable_synthesis_attempt(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "target.c").write_text("int target(int value) { return value; }\n")
    store = RunStore(tmp_path / "run-one-shot")
    store.save_config({"repo_path": str(source), "repo_source": "fixture"})
    ensure_source_snapshot(store)
    hunt = store.dir / "hunters" / "h1" / "hunts" / "task-1"
    hunt.mkdir(parents=True)
    (hunt / "findings.json").write_text(json.dumps({
        "findings": [{
            "title": "Unverified target condition",
            "type": "logic_error",
            "description": "Target behavior requires actual-target reproduction.",
            "attack": "Supply a crafted value.",
            "status": "unverified",
            "entry_file": "target.c",
            "entry_line": 1,
            "sink_file": "target.c",
            "sink_line": 1,
            "files_touched": ["target.c"],
        }],
    }))
    repository = SqliteRepository(store.dir / "state.db")
    synthesizer = CountingUnavailableSynthesizer()
    service = VerifiedPipelineService(
        repository,
        v2_artifact_store(store),
        NoopBackend(),
        [],
        output_root=store.dir / "verified",
        source_root=source,
        analysis={"graph": {"nodes": [], "edges": []}},
        recipe_synthesizer=synthesizer,
    )

    first = await service.verify(
        run_id=store.dir.name,
        run_dir=store.dir,
        image="prepared:test",
    )
    second = await service.verify(
        run_id=store.dir.name,
        run_dir=store.dir,
        image="prepared:test",
    )

    assert synthesizer.calls == 1
    assert first.synthesis_attempts == 1
    assert second.synthesis_attempts == 0
    finding = repository.list_candidates(store.dir.name)[0]
    assert finding.state is FindingState.VERIFICATION_DEFERRED
    assert finding.resolution is not None
    assert finding.resolution.synthesis_attempts == 1
    assert finding.resolution.disposition is ResolutionDisposition.VERIFICATION_DEFERRED
    assert finding.resolution.remaining_requirement
    assert first.states == {"verification_deferred": 1}
    repository.close()


async def test_synthesizer_rejects_standalone_memory_model(tmp_path: Path) -> None:
    repo, candidate, _assessment = _fixture(
        tmp_path,
        "int8_t",
        with_public_max=True,
    )
    assessment = FeasibilityAssessment(
        candidate_id=candidate.candidate_id,
        source_snapshot="sha256:" + "a" * 64,
        status=FeasibilityStatus.FEASIBLE,
        rationale=("fixture",),
    )
    standalone = SynthesisClient(actual_target=False)
    linked = SynthesisClient(actual_target=True)

    rejected = await LLMRecipeSynthesizer(cast(LLMClient, standalone)).synthesize(
        candidate,
        assessment,
        source_root=repo,
        output_root=tmp_path / "out-a",
    )
    accepted = await LLMRecipeSynthesizer(cast(LLMClient, linked)).synthesize(
        candidate,
        assessment,
        source_root=repo,
        output_root=tmp_path / "out-b",
    )

    assert standalone.calls == linked.calls == 1
    assert rejected.attempted and rejected.recipe is None
    assert "actual target" in rejected.error
    assert accepted.recipe is not None


def test_feasibility_engine_has_no_target_signature() -> None:
    source = Path("src/vulnhunt_agent/verification/feasibility.py").read_text()
    assert "nAtts" not in source
    assert "getAtts" not in source
    assert "libexpat" not in source
