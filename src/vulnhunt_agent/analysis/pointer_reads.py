"""Cross-file pointer-read preconditions and caller length checks."""
from __future__ import annotations

import hashlib
import re

from .models import (
    CapacityCallSite,
    FunctionCapacitySummary,
    GuardState,
    LengthBeforeReadChain,
    PointerReadSummary,
)

POINTER_READ_SUMMARY_POLICY = "c-pointer-read-summary-v1"
LENGTH_BEFORE_READ_POLICY = "c-length-before-read-v1"


def extract_pointer_read_summaries(
    *,
    path: str,
    node_id: str,
    function: str,
    source: str,
    start_line: int,
    summary: FunctionCapacitySummary,
) -> tuple[PointerReadSummary, ...]:
    """Conservatively summarize raw reads through pointer parameters."""
    facts = []
    body_offset = source.find("{") + 1
    body_source = source[body_offset:]
    for parameter in summary.pointer_parameters:
        tokens = _pointer_events(body_source, parameter)
        offset = 0
        reads: list[tuple[int, int]] = []
        mutations: list[int] = []
        for position, kind, value in tokens:
            line = start_line + source[:body_offset + position].count("\n")
            if kind == "prefix_advance":
                offset += value
                mutations.append(line)
            elif kind == "read_advance":
                reads.append((offset, line))
                offset += value
                mutations.append(line)
            elif kind == "read_index":
                reads.append((offset + value, line))
            else:
                reads.append((offset, line))
        if not reads:
            continue
        maximum_index, maximum_line = max(reads, key=lambda item: (item[0], item[1]))
        first_line = min(line for _, line in reads)
        parameter_index = summary.parameters.index(parameter)
        identity = "\0".join((
            POINTER_READ_SUMMARY_POLICY,
            node_id,
            parameter,
            str(first_line),
            str(maximum_index),
        ))
        facts.append(PointerReadSummary(
            fact_id="pointer_read_" + hashlib.sha256(identity.encode()).hexdigest()[:20],
            node_id=node_id,
            path=path,
            function=function,
            pointer_parameter=parameter,
            parameter_index=parameter_index,
            first_read_line=first_line,
            maximum_read_line=maximum_line,
            maximum_access_index=maximum_index,
            minimum_required_bytes=maximum_index + 1,
            mutation_lines=tuple(sorted(set(mutations))),
            local_guard_state=GuardState.UNKNOWN,
            evidence=(
                f"pointer parameter requires bytes [0..{maximum_index}] across "
                f"{len(reads)} source-derived reads"
            ),
            confidence="high",
        ))
    return tuple(sorted(facts, key=lambda item: item.fact_id))


def build_length_before_read_chains(
    *,
    reads: tuple[PointerReadSummary, ...],
    calls: tuple[CapacityCallSite, ...],
) -> tuple[LengthBeforeReadChain, ...]:
    """Join a decoder read contract to a caller's cursor/length validation call."""
    reads_by_node: dict[str, list[PointerReadSummary]] = {}
    calls_by_caller: dict[str, list[CapacityCallSite]] = {}
    for read in reads:
        reads_by_node.setdefault(read.node_id, []).append(read)
    for call in calls:
        calls_by_caller.setdefault(call.caller_id, []).append(call)

    chains = []
    for decoder in calls:
        for read in reads_by_node.get(decoder.target_node_id, ()):
            if read.parameter_index >= len(decoder.arguments):
                continue
            decoder_argument = decoder.arguments[read.parameter_index]
            argument_identifiers = set(_identifiers(decoder_argument))
            checks = []
            for check in calls_by_caller.get(decoder.caller_id, ()):
                if check.call_id == decoder.call_id:
                    continue
                references = _addressed_identifiers(check.arguments)
                cursors = sorted(argument_identifiers.intersection(references))
                if not cursors or len(references) < 2:
                    continue
                cursor = cursors[0]
                lengths = sorted(references - {cursor})
                if not lengths:
                    continue
                checks.append((abs(check.line - decoder.line), check, cursor, lengths[0]))
            if not checks:
                continue
            _, check, cursor, length = min(
                checks,
                key=lambda item: (item[0], item[1].line, item[1].call_id),
            )
            checked_before = check.line < decoder.line
            checked_after = check.line > decoder.line
            rebased = bool(
                check.result_subject
                and re.search(
                    rf"\b{re.escape(check.result_subject)}\b",
                    decoder_argument,
                )
            )
            controlled = bool(
                check.result_subject
                and check.result_subject in decoder.control_subjects
            )
            safe = checked_before and rebased and controlled
            guard_state = GuardState.DOMINATES if safe else GuardState.ABSENT
            identity = "\0".join((
                LENGTH_BEFORE_READ_POLICY,
                decoder.call_id,
                check.call_id,
                read.fact_id,
            ))
            paths = tuple(sorted({decoder.path, read.path}))
            evidence_lines: dict[str, set[int]] = {}
            evidence_lines.setdefault(decoder.path, set()).update({
                decoder.line,
                check.line,
            })
            evidence_lines.setdefault(read.path, set()).update({
                read.first_read_line,
                read.maximum_read_line,
                *read.mutation_lines,
            })
            chains.append(LengthBeforeReadChain(
                chain_id="length_read_" + hashlib.sha256(identity.encode()).hexdigest()[:20],
                caller_node_id=decoder.caller_id,
                reader_node_id=decoder.target_node_id,
                paths=paths,
                read_fact_id=read.fact_id,
                decoder_call_id=decoder.call_id,
                check_call_id=check.call_id,
                decoder_line=decoder.line,
                check_line=check.line,
                cursor_subject=cursor,
                length_subject=length,
                required_access_index=read.maximum_access_index,
                checked_before_read=checked_before,
                checked_after_read=checked_after,
                pointer_rebased_from_checked_size=rebased,
                check_result_controls_read=controlled,
                boundary_cases=(
                    "zero_remaining",
                    "one_byte_header",
                    f"maximum_extension_{read.minimum_required_bytes}_bytes",
                ),
                guard_state=guard_state,
                evidence_lines={
                    path: tuple(sorted(lines))
                    for path, lines in sorted(evidence_lines.items())
                },
                score=15 if safe else 95,
                confidence="high",
                rationale=(
                    f"callee may read through index {read.maximum_access_index}; "
                    f"length/cursor check is {'before' if checked_before else 'after'} "
                    f"the read; checked-size rebasing={rebased}; "
                    f"check-result control={controlled}"
                ),
            ))
    return tuple(sorted(
        {item.chain_id: item for item in chains}.values(),
        key=lambda item: item.chain_id,
    ))


def _pointer_events(source: str, parameter: str) -> list[tuple[int, str, int]]:
    escaped = re.escape(parameter)
    pattern = re.compile(
        rf"(?P<prefix>\+\+\s*{escaped}|{escaped}\s*\+=\s*[0-9]+)|"
        rf"(?P<read_advance>\*\s*{escaped}\s*\+\+)|"
        rf"(?P<read_index>{escaped}\s*\[\s*[0-9]+\s*\])|"
        rf"(?P<read>\*\s*{escaped}\b)"
    )
    events = []
    for match in pattern.finditer(source):
        text = match.group(0)
        if match.lastgroup == "prefix":
            number = re.search(r"[0-9]+", text)
            amount = int(number.group()) if number is not None else 1
            kind = "prefix_advance"
        elif match.lastgroup == "read_advance":
            amount = 1
            kind = "read_advance"
        elif match.lastgroup == "read_index":
            number = re.search(r"[0-9]+", text)
            amount = int(number.group()) if number is not None else 0
            kind = "read_index"
        else:
            amount = 0
            kind = "read"
        events.append((match.start(), kind, amount))
    return events


def _addressed_identifiers(arguments: tuple[str, ...]) -> set[str]:
    return {
        match.group(1)
        for argument in arguments
        for match in re.finditer(
            r"&\s*([A-Za-z_]\w*)\b(?!\s*(?:->|\.))",
            argument,
        )
    }


def _identifiers(value: str) -> tuple[str, ...]:
    ignored = {"const", "unsigned", "signed", "char", "short", "int", "long"}
    return tuple(
        item for item in re.findall(r"\b[A-Za-z_]\w*\b", value)
        if item not in ignored and not item.endswith("_t")
    )
