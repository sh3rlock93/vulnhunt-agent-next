"""Validate model-supplied reproduction recipes against recorded tool calls."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from ..domain.schemas import OracleSpec, OracleType
from ..reproduction.oracles import evaluate_oracle
from ..sandbox.base import ExecResult


class RecordedRecipe(BaseModel):
    model_config = ConfigDict(extra="forbid")

    setup_argvs: tuple[tuple[str, ...], ...] = Field(default=(), max_length=16)
    argv: tuple[str, ...] = Field(min_length=1, max_length=256)
    cwd: str = Field(min_length=1)
    timeout: int = Field(default=60, ge=1, le=600)
    oracle: OracleSpec

    @model_validator(mode="after")
    def reject_trivial_oracle(self) -> "RecordedRecipe":
        if self.oracle.type in {
            OracleType.STDOUT_REGEX,
            OracleType.STDERR_REGEX,
            OracleType.COMBINED_REGEX,
        }:
            pattern = (self.oracle.pattern or "").strip()
            if len(pattern) < 4 or pattern in {".*", "^.*$", ".+", "^.+$"}:
                raise ValueError("reproduction regex oracle is trivial")
        return self


@dataclass(frozen=True)
class CompiledRecipe:
    poc_path: Path
    poc_relative: str
    setup_argvs: tuple[tuple[str, ...], ...]
    argv: tuple[str, ...]
    cwd: str
    timeout: int
    oracle: OracleSpec


@dataclass(frozen=True)
class RecipeDecision:
    recipe: CompiledRecipe | None
    error: str = ""


def validate_recorded_recipe(
    finding: dict,
    hunt_payload: dict,
    pocs_root: Path,
) -> RecipeDecision:
    if finding.get("status") != "confirmed":
        return RecipeDecision(None, "finding is not confirmed")
    raw_recipe = finding.get("reproduction")
    if not isinstance(raw_recipe, dict):
        return RecipeDecision(None, "confirmed finding has no reproduction recipe")
    try:
        recipe = RecordedRecipe.model_validate(raw_recipe)
    except ValidationError as exc:
        return RecipeDecision(None, f"invalid reproduction recipe: {exc}")

    poc_relative = _normalize_poc_path(str(finding.get("poc_file") or ""))
    if not poc_relative:
        return RecipeDecision(None, "reproduction PoC path is invalid")
    written = {
        _normalize_poc_path(str(item))
        for item in hunt_payload.get("written_pocs", [])
    }
    if poc_relative not in written:
        return RecipeDecision(None, "PoC was not written by the Hunter tool")
    poc_path = (pocs_root / poc_relative).resolve()
    root = pocs_root.resolve()
    if (root not in poc_path.parents and poc_path != root) or not poc_path.is_file():
        return RecipeDecision(None, "recorded PoC file is missing")

    desired = (*recipe.setup_argvs, recipe.argv)
    records = hunt_payload.get("executions", [])
    matched: list[dict] = []
    cursor = 0
    for command in desired:
        found = None
        for index in range(cursor, len(records)):
            record = records[index]
            if (
                tuple(record.get("argv", [])) == command
                and record.get("cwd", "/workspace") == recipe.cwd
                and int(record.get("timeout", 60)) == recipe.timeout
            ):
                found = record
                cursor = index + 1
                break
        if found is None:
            return RecipeDecision(
                None,
                "reproduction commands do not match the recorded exec tool calls",
            )
        matched.append(found)

    final = matched[-1]
    observed = ExecResult(
        exit_code=int(final.get("exit_code", -1)),
        stdout=str(final.get("stdout") or ""),
        stderr=str(final.get("stderr") or ""),
        timed_out=bool(final.get("timed_out")),
        duration_ms=int(final.get("duration_ms", 0)),
    )
    if evaluate_oracle(recipe.oracle, observed).result != "passed":
        return RecipeDecision(
            None,
            "reproduction oracle did not pass against the recorded execution",
        )

    try:
        compiled = CompiledRecipe(
            poc_path=poc_path,
            poc_relative=poc_relative,
            setup_argvs=tuple(
                _rewrite_command(command, poc_relative)
                for command in recipe.setup_argvs
            ),
            argv=_rewrite_command(recipe.argv, poc_relative),
            cwd=_rewrite_cwd(recipe.cwd),
            timeout=recipe.timeout,
            oracle=recipe.oracle,
        )
    except ValueError as exc:
        return RecipeDecision(None, str(exc))
    return RecipeDecision(compiled)


def _normalize_poc_path(value: str) -> str:
    value = value.removeprefix("/workspace/")
    if "\\" in value:
        return ""
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or path == PurePosixPath("."):
        return ""
    return path.as_posix()


def _rewrite_command(
    command: tuple[str, ...],
    poc_relative: str,
) -> tuple[str, ...]:
    original_poc = f"/workspace/{poc_relative}"
    reproduced_poc = f"/workspace/poc/{poc_relative}"
    return tuple(
        argument.replace(original_poc, reproduced_poc).replace(
            "/code", "/workspace/source"
        )
        for argument in command
    )


def _rewrite_cwd(cwd: str) -> str:
    path = PurePosixPath(cwd)
    if path == PurePosixPath("/code"):
        return "."
    if PurePosixPath("/code") in path.parents:
        return path.relative_to("/code").as_posix()
    if path == PurePosixPath("/workspace") or PurePosixPath("/workspace") in path.parents:
        return "."
    if not path.is_absolute() and ".." not in path.parts:
        return path.as_posix()
    raise ValueError(f"recorded cwd cannot be reproduced safely: {cwd}")
