"""Versioned, repository-agnostic vulnerability-pattern retrieval.

The source finding ledger deliberately lives outside the runtime package.  Only
generalized invariants are loaded here, and prompt projections never contain
repository names, commits, paths, symbols, line numbers, or trigger literals.
"""
from __future__ import annotations

from functools import lru_cache
import hashlib
from importlib import resources
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

KNOWLEDGE_POLICY = "generalized-vulnerability-knowledge-v1"
KNOWLEDGE_SELECTION_POLICY = "structural-pattern-retrieval-v1"
DEFAULT_MAX_CARDS = 4


class _KnowledgeModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class PatternApplicability(_KnowledgeModel):
    languages: tuple[str, ...] = Field(min_length=1)
    hunter_roles: tuple[str, ...] = Field(min_length=1)
    semantic_tags: tuple[str, ...] = Field(min_length=1)
    minimum_structural_matches: int = Field(default=1, ge=0, le=8)


class VulnerabilityPattern(_KnowledgeModel):
    pattern_id: str = Field(pattern=r"^vpattern_[a-z0-9_]+$")
    title: str = Field(min_length=1, max_length=120)
    weakness_family: str = Field(min_length=1, max_length=80)
    applicability: PatternApplicability
    invariant: str = Field(min_length=1, max_length=500)
    investigation_steps: tuple[str, ...] = Field(min_length=2, max_length=6)
    required_evidence: tuple[str, ...] = Field(min_length=1, max_length=5)
    falsifiers: tuple[str, ...] = Field(min_length=1, max_length=5)
    base_priority: int = Field(default=1, ge=1, le=5)

    @model_validator(mode="after")
    def validate_uniqueness(self) -> "VulnerabilityPattern":
        for label, values in (
            ("languages", self.applicability.languages),
            ("hunter roles", self.applicability.hunter_roles),
            ("semantic tags", self.applicability.semantic_tags),
            ("investigation steps", self.investigation_steps),
            ("required evidence", self.required_evidence),
            ("falsifiers", self.falsifiers),
        ):
            if len(set(values)) != len(values):
                raise ValueError(f"pattern {label} must be unique")
        return self


class VulnerabilityPatternDatabase(_KnowledgeModel):
    schema_version: int = Field(default=1, ge=1, le=1)
    policy_version: str = Field(pattern=r"^generalized-vulnerability-knowledge-v\d+$")
    patterns: tuple[VulnerabilityPattern, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_pattern_ids(self) -> "VulnerabilityPatternDatabase":
        ids = [item.pattern_id for item in self.patterns]
        if len(set(ids)) != len(ids):
            raise ValueError("vulnerability pattern IDs must be unique")
        return self


class VulnerabilityKnowledgeBase:
    """Immutable pattern database with deterministic structural retrieval."""

    def __init__(self, database: VulnerabilityPatternDatabase, *, digest: str):
        self.database = database
        self.digest = digest

    def select(
        self,
        *,
        hunter: str,
        language: str,
        analysis_context: dict[str, Any] | None,
        limit: int = DEFAULT_MAX_CARDS,
    ) -> dict[str, Any]:
        if limit < 1:
            raise ValueError("knowledge card limit must be positive")
        tags = structural_semantic_tags(analysis_context or {})
        ranked: list[tuple[int, int, str, VulnerabilityPattern, tuple[str, ...]]] = []
        for pattern in self.database.patterns:
            applicability = pattern.applicability
            if language not in applicability.languages:
                continue
            role_match = hunter in applicability.hunter_roles
            matched = tuple(sorted(tags & set(applicability.semantic_tags)))
            if not role_match and len(matched) < applicability.minimum_structural_matches:
                continue
            score = pattern.base_priority + (20 if role_match else 0) + 4 * len(matched)
            ranked.append((score, len(matched), pattern.pattern_id, pattern, matched))
        ranked.sort(key=lambda item: (-item[0], -item[1], item[2]))
        cards = [
            _prompt_card(pattern, matched)
            for _score, _matches, _pattern_id, pattern, matched in ranked[:limit]
        ]
        return {
            "policy_version": self.database.policy_version,
            "selection_policy": KNOWLEDGE_SELECTION_POLICY,
            "database_digest": self.digest,
            "guidance": (
                "These are generalized hypothesis seeds, not signatures or proof. "
                "Do not search for an old repository, path, symbol, line, commit, or "
                "literal trigger. Apply the invariant to the current code, gather the "
                "required evidence, and close it when a falsifier is established."
            ),
            "observed_semantic_tags": sorted(tags),
            "cards": cards,
        }


@lru_cache(maxsize=1)
def load_default_knowledge_base() -> VulnerabilityKnowledgeBase:
    raw = (
        resources.files("vulnhunt_agent.knowledge")
        .joinpath("patterns-v1.json")
        .read_bytes()
    )
    database = VulnerabilityPatternDatabase.model_validate_json(raw)
    if database.policy_version != KNOWLEDGE_POLICY:
        raise ValueError(
            f"unsupported vulnerability knowledge policy: {database.policy_version}"
        )
    return VulnerabilityKnowledgeBase(
        database,
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
    )


def build_knowledge_context(
    *,
    hunter: str,
    language: str,
    analysis_context: dict[str, Any] | None,
    limit: int = DEFAULT_MAX_CARDS,
) -> dict[str, Any]:
    """Build the bounded prompt projection for one Hunter work item."""
    return load_default_knowledge_base().select(
        hunter=hunter,
        language=language,
        analysis_context=analysis_context,
        limit=limit,
    )


def structural_semantic_tags(context: dict[str, Any]) -> set[str]:
    """Extract only structural tags; source identity and free text are ignored."""
    tags: set[str] = set()

    risk_chains = context.get("risk_chains") or ()
    if risk_chains:
        tags.add("integer_transform")
    for chain in risk_chains:
        if str(chain.get("guard_state", "")) in {"absent", "partial", "unknown"}:
            tags.add("missing_numeric_guard")
        for step in chain.get("transform_steps") or ():
            if step.get("narrowing_or_wrap"):
                tags.update(("numeric_wrap", "numeric_narrowing"))
            for operation in step.get("operations") or ():
                tags.update(_operation_tags(str(operation)))

    capacity_chains = context.get("capacity_risk_chains") or ()
    if capacity_chains:
        tags.update(("allocation", "capacity_chain"))
    for chain in capacity_chains:
        if str(chain.get("guard_state", "")) in {"absent", "partial", "unknown"}:
            tags.add("missing_capacity_guard")
        if chain.get("write_fact_ids") or int(chain.get("write_count", 0) or 0):
            tags.add("write")
        if chain.get("pointer_advance_fact_ids") or int(
            chain.get("pointer_advance_count", 0) or 0
        ):
            tags.update(("pointer_advance", "state_transition"))
        if chain.get("return_consumption_call_ids"):
            tags.add("return_consumption")
        for missing in chain.get("missing_elements") or ():
            tags.update(_normalized_structural_value(str(missing)))

    cursor_chains = context.get("cursor_transition_chains") or ()
    if cursor_chains:
        tags.update(("cursor_transition", "read", "state_transition"))
    for chain in cursor_chains:
        if str(chain.get("guard_state", "")) in {"absent", "partial", "unknown"}:
            tags.add("cursor_guard_gap")

    for fact in context.get("constraint_facts") or ():
        tags.update(_normalized_structural_value(str(fact.get("kind", ""))))

    for item in context.get("slices") or ():
        for category in item.get("categories") or ():
            tags.update(_normalized_structural_value(str(category)))
        sink = item.get("sink") or {}
        tags.update(_normalized_structural_value(str(sink.get("category", ""))))
        tags.update(_operation_tags(str(sink.get("operation", ""))))
    return tags


def _prompt_card(pattern: VulnerabilityPattern, matched: tuple[str, ...]) -> dict[str, Any]:
    return {
        "pattern_id": pattern.pattern_id,
        "title": pattern.title,
        "weakness_family": pattern.weakness_family,
        "matched_semantic_tags": list(matched),
        "invariant": pattern.invariant,
        "investigation_steps": list(pattern.investigation_steps),
        "required_evidence": list(pattern.required_evidence),
        "falsifiers": list(pattern.falsifiers),
    }


def _operation_tags(value: str) -> set[str]:
    lowered = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    tags = _normalized_structural_value(lowered)
    if any(token in lowered for token in ("alloc", "malloc", "calloc", "realloc")):
        tags.add("allocation")
    if any(token in lowered for token in ("printf", "format")):
        tags.update(("formatted_output", "write"))
    if any(token in lowered for token in ("memcpy", "memmove", "strcpy", "copy")):
        tags.update(("bulk_write", "write"))
    if any(token in lowered for token in ("index", "subscript", "array")):
        tags.add("array_index")
    if any(token in lowered for token in ("multiply", "addition", "add", "shift")):
        tags.add("numeric_arithmetic")
    return tags


def _normalized_structural_value(value: str) -> set[str]:
    lowered = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    aliases = {
        "allocation": {"allocation"},
        "array_write": {"array_index", "write"},
        "array_read": {"array_index", "read"},
        "buffer_write": {"write"},
        "buffer_size_bound": {"capacity_guard"},
        "copy": {"bulk_write", "write"},
        "cursor_index_read": {"cursor_transition", "read"},
        "dominant_guard": {"capacity_guard"},
        "format_string": {"formatted_output", "write"},
        "growth": {"output_expansion"},
        "guard": {"capacity_guard"},
        "minimum_consumption": {"cursor_transition", "read"},
        "narrowing": {"numeric_narrowing"},
        "numeric_bound": {"numeric_guard"},
        "read": {"read"},
        "source": {"source"},
        "write": {"write"},
        "write_sink": {"write"},
    }
    return set(aliases.get(lowered, ()))
