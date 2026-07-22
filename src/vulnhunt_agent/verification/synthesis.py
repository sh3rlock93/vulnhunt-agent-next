"""One-shot, actual-target reproduction recipe synthesis."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from ..core.jsonx import try_extract_object
from ..core.llm import LLMClient
from ..domain.schemas import CandidateFinding, FeasibilityAssessment, OracleSpec
from ..reproduction.provenance import requires_actual_target
from .recipe import CompiledRecipe

SYNTHESIS_POLICY = "recipe-synthesis-v1"
MAX_SYNTHESIS_CONTEXT_BYTES = 20_000

SYSTEM_PROMPT = """You synthesize one bounded vulnerability reproduction recipe.

Use only the immutable target source excerpts in the packet. The recipe executes
inside a network-disabled prepared sandbox where target source is mounted at
/workspace/source and the generated PoC is at /workspace/poc/<poc_filename>.
For native memory-safety claims, compile or invoke the actual prepared target;
never substitute a standalone model of the target code. Prefer sanitizers and a
specific non-trivial oracle. Do not use a shell, command substitution, network,
absolute host paths, or destructive commands.

Return only this JSON object:
{
  "poc_filename": "poc.c",
  "poc_source": "<complete source>",
  "setup_argvs": [["cc", "..."], ...],
  "argv": ["/workspace/exec/poc", "..."],
  "cwd": ".",
  "timeout": 60,
  "oracle": {"type": "combined_regex", "pattern": "..."}
}
"""


class SynthesizedRecipePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    poc_filename: str = Field(min_length=1, max_length=100)
    poc_source: str = Field(min_length=1, max_length=100_000)
    setup_argvs: tuple[tuple[str, ...], ...] = Field(default=(), max_length=16)
    argv: tuple[str, ...] = Field(min_length=1, max_length=256)
    cwd: str = "."
    timeout: int = Field(default=60, ge=1, le=180)
    oracle: OracleSpec


@dataclass(frozen=True)
class SynthesisDecision:
    recipe: CompiledRecipe | None
    attempted: bool
    error: str = ""


class RecipeSynthesizer(Protocol):
    async def synthesize(
        self,
        candidate: CandidateFinding,
        assessment: FeasibilityAssessment,
        *,
        source_root: Path,
        output_root: Path,
    ) -> SynthesisDecision: ...


class LLMRecipeSynthesizer:
    """Perform exactly one model call; invalid output becomes typed deferral."""

    def __init__(self, client: LLMClient, *, max_tokens: int = 4000):
        self.client = client
        self.max_tokens = max_tokens

    async def synthesize(
        self,
        candidate: CandidateFinding,
        assessment: FeasibilityAssessment,
        *,
        source_root: Path,
        output_root: Path,
    ) -> SynthesisDecision:
        packet = {
            "policy_version": SYNTHESIS_POLICY,
            "candidate": candidate.model_dump(
                mode="json",
                exclude={"poc", "resolution"},
            ),
            "feasibility": assessment.model_dump(mode="json"),
            "source_excerpts": _source_excerpts(candidate, assessment, source_root),
        }
        response = await self.client.chat(
            messages=[{
                "role": "user",
                "content": [{
                    "text": json.dumps(packet, indent=2, ensure_ascii=False),
                }],
            }],
            system=SYSTEM_PROMPT,
            max_tokens=self.max_tokens,
        )
        parsed = try_extract_object(response.text)
        if parsed is None:
            return SynthesisDecision(None, True, "model returned no JSON recipe")
        try:
            payload = SynthesizedRecipePayload.model_validate(parsed)
            return SynthesisDecision(
                _compile_payload(candidate, payload, output_root),
                True,
            )
        except (ValueError, OSError) as exc:
            return SynthesisDecision(None, True, f"invalid synthesized recipe: {exc}")


def _compile_payload(
    candidate: CandidateFinding,
    payload: SynthesizedRecipePayload,
    output_root: Path,
) -> CompiledRecipe:
    filename = PurePosixPath(payload.poc_filename.replace("\\", "/"))
    if (
        filename.is_absolute()
        or len(filename.parts) != 1
        or filename.name in {"", ".", ".."}
        or re.fullmatch(r"[A-Za-z0-9_.-]+", filename.name) is None
    ):
        raise ValueError("PoC filename must be one safe basename")
    cwd = PurePosixPath(payload.cwd.replace("\\", "/"))
    if cwd.is_absolute() or ".." in cwd.parts:
        raise ValueError("recipe cwd must stay inside the reproduction workspace")
    commands = (*payload.setup_argvs, payload.argv)
    if any(not command or any("\0" in part for part in command) for command in commands):
        raise ValueError("recipe contains an empty command or NUL")
    if any(command[0] in {"sh", "bash", "zsh", "/bin/sh", "/bin/bash"} for command in commands):
        raise ValueError("recipe may not invoke a shell")
    if requires_actual_target(candidate) and not any(
        argument.startswith(("/workspace/source/", "/opt/vulnhunt/build/"))
        for command in commands
        for argument in command
    ):
        raise ValueError("memory-safety recipe does not compile or invoke the actual target")

    target = output_root / "synthesized" / candidate.candidate_id / filename.name
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.read_text() != payload.poc_source:
        raise ValueError("synthesized PoC changed during replay")
    if not target.exists():
        target.write_text(payload.poc_source)
    return CompiledRecipe(
        poc_path=target,
        poc_relative=filename.name,
        setup_argvs=payload.setup_argvs,
        argv=payload.argv,
        cwd=cwd.as_posix(),
        timeout=payload.timeout,
        oracle=payload.oracle,
    )


def _source_excerpts(
    candidate: CandidateFinding,
    assessment: FeasibilityAssessment,
    source_root: Path,
) -> list[dict]:
    locations: dict[str, set[int]] = {}
    for location in (candidate.entrypoint, candidate.sink, *candidate.dataflow):
        if location is not None:
            locations.setdefault(location.path, set()).add(location.line)
    for bound in assessment.bounds:
        for source in bound.sources:
            locations.setdefault(source.path, set()).add(source.line)

    excerpts: list[dict] = []
    remaining = MAX_SYNTHESIS_CONTEXT_BYTES
    root = source_root.resolve()
    for relative in sorted(locations):
        path = (root / relative).resolve()
        if root not in path.parents or not path.is_file():
            continue
        lines = path.read_text(errors="replace").splitlines()
        anchors = sorted(locations[relative])[:4]
        start = max(1, min(anchors) - 60)
        end = min(len(lines), max(anchors) + 60)
        content = "\n".join(lines[start - 1 : end])
        encoded = content.encode()
        if len(encoded) > remaining:
            content = encoded[:remaining].decode(errors="ignore")
        if not content:
            break
        excerpts.append({
            "path": relative,
            "line": start,
            "end_line": start + content.count("\n"),
            "content": content,
        })
        remaining -= len(content.encode())
        if remaining <= 0:
            break
    return excerpts
