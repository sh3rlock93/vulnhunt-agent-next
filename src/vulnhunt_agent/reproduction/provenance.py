"""Classify native reproduction evidence without trusting PoC declarations."""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..domain.schemas import (
    CandidateFinding,
    Evidence,
    ExecutionSubject,
    SanitizerFrame,
)

NATIVE_EVIDENCE_POLICY = "native-evidence-v2"

_TARGET_ROOTS = ("/code/", "/workspace/source/", "/opt/vulnhunt/build/")
_MEMORY_SAFETY_CWES = frozenset({
    "CWE-119",
    "CWE-120",
    "CWE-121",
    "CWE-122",
    "CWE-124",
    "CWE-125",
    "CWE-126",
    "CWE-127",
    "CWE-190",
    "CWE-415",
    "CWE-416",
    "CWE-680",
    "CWE-787",
    "CWE-788",
    "CWE-789",
})
_MEMORY_SAFETY_TERMS = re.compile(
    r"\b(?:buffer[-_ ]?overflow|out[-_ ]of[-_ ]bounds|use[-_ ]after[-_ ]free|"
    r"double[-_ ]free|memory[-_ ]corruption|heap[-_ ]overflow|stack[-_ ]overflow|"
    r"integer[-_ ]overflow)\b",
    re.IGNORECASE,
)
_ASAN_FRAME = re.compile(
    r"^\s*#(?P<index>\d+)\s+(?:0x[0-9a-f]+\s+)?(?:in\s+)?"
    r"(?P<function>.*?)\s+(?P<path>/[^\s():]+)"
    r"(?::(?P<line>\d+))?(?::(?P<column>\d+))?(?:\s|$)",
    re.IGNORECASE | re.MULTILINE,
)
_LOCATION = re.compile(
    r"(?P<path>/(?:code|workspace/source|opt/vulnhunt/build)/[^\s():]+)"
    r":(?P<line>\d+)(?::(?P<column>\d+))?",
)
_BINARY_FRAME = re.compile(
    r"^\s*#(?P<index>\d+)\s+.*?\((?P<path>/[^+\s)]+)(?:\+[^)]*)?\)",
    re.MULTILINE,
)
_ASAN_FAILURE = re.compile(
    r"(?:ERROR|SUMMARY):\s*(?:AddressSanitizer|HWAddressSanitizer):\s*"
    r"(?P<kind>[A-Za-z0-9_-]+)",
    re.IGNORECASE,
)
_OTHER_FAILURES = (
    (re.compile(r"LeakSanitizer", re.IGNORECASE), "memory-leak"),
    (
        re.compile(r"(?:UndefinedBehaviorSanitizer|runtime error:)", re.IGNORECASE),
        "undefined-behavior",
    ),
    (re.compile(r"MemorySanitizer", re.IGNORECASE), "uninitialized-memory"),
)


@dataclass(frozen=True)
class ExecutionProvenance:
    execution_subject: ExecutionSubject
    target_binary: str | None
    linked_target_artifacts: tuple[str, ...]
    sanitizer_failure_class: str | None
    sanitizer_frames: tuple[SanitizerFrame, ...]
    target_source_reached: bool


def derive_execution_provenance(
    *,
    argv: tuple[str, ...],
    setup_argvs: tuple[tuple[str, ...], ...],
    stdout: str,
    stderr: str,
) -> ExecutionProvenance:
    """Derive execution identity from commands and runtime output.

    Paths supplied by the PoC are not enough to claim target execution. A target
    subject is only considered reached when a sanitizer location is rooted in
    the immutable target source or prepared build tree.
    """
    output = "\n".join((stdout, stderr))
    frames = normalize_sanitizer_frames(output)
    target_frames = tuple(frame for frame in frames if frame.in_target)
    failure_class = sanitizer_failure_class(output)
    executable = argv[0] if argv else None
    direct_target = executable is not None and _is_target_path(executable)
    target_artifacts = _target_artifacts(argv, setup_argvs, target_frames)

    if direct_target:
        subject = ExecutionSubject.PREPARED_BINARY
        target_binary = executable
    elif target_frames:
        subject = ExecutionSubject.LINKED_TARGET_HARNESS
        target_binary = None
    elif failure_class is not None:
        subject = ExecutionSubject.STANDALONE_MODEL
        target_binary = None
    else:
        subject = ExecutionSubject.UNKNOWN
        target_binary = None

    return ExecutionProvenance(
        execution_subject=subject,
        target_binary=target_binary,
        linked_target_artifacts=(
            target_artifacts
            if subject is ExecutionSubject.LINKED_TARGET_HARNESS
            else ()
        ),
        sanitizer_failure_class=failure_class,
        sanitizer_frames=frames,
        target_source_reached=bool(
            target_frames
            and subject
            in {
                ExecutionSubject.PREPARED_BINARY,
                ExecutionSubject.LINKED_TARGET_HARNESS,
            }
        ),
    )


def normalize_sanitizer_frames(output: str) -> tuple[SanitizerFrame, ...]:
    frames: list[SanitizerFrame] = []
    seen: set[tuple[int, str, int | None, int | None]] = set()

    def add(
        index: int,
        function: str,
        path: str,
        line: int | None,
        column: int | None,
    ) -> None:
        normalized_path = path.rstrip(".,")
        key = (index, normalized_path, line, column)
        if key in seen:
            return
        seen.add(key)
        frames.append(SanitizerFrame(
            index=index,
            function=" ".join(function.split()),
            path=normalized_path,
            line=line,
            column=column,
            in_target=_is_target_path(normalized_path),
        ))

    for match in _ASAN_FRAME.finditer(output):
        add(
            int(match.group("index")),
            match.group("function"),
            match.group("path"),
            _integer(match.group("line")),
            _integer(match.group("column")),
        )
    next_index = max((frame.index for frame in frames), default=-1) + 1
    for line_text in output.splitlines():
        if "runtime error:" not in line_text.casefold():
            continue
        for match in _LOCATION.finditer(line_text):
            add(
                next_index,
                "runtime_error",
                match.group("path"),
                _integer(match.group("line")),
                _integer(match.group("column")),
            )
            next_index += 1
    for match in _BINARY_FRAME.finditer(output):
        add(int(match.group("index")), "", match.group("path"), None, None)
    return tuple(sorted(frames, key=lambda item: (
        item.index,
        item.path,
        item.line or 0,
        item.column or 0,
    )))


def sanitizer_failure_class(output: str) -> str | None:
    match = _ASAN_FAILURE.search(output)
    if match:
        return match.group("kind").casefold().replace("_", "-")
    for pattern, failure_class in _OTHER_FAILURES:
        if pattern.search(output):
            return failure_class
    return None


def requires_actual_target(finding: CandidateFinding) -> bool:
    if finding.weakness.upper() in _MEMORY_SAFETY_CWES:
        return True
    searchable = " ".join((finding.weakness, finding.title, *finding.impact))
    return _MEMORY_SAFETY_TERMS.search(searchable) is not None


def has_actual_target_provenance(evidence: Evidence) -> bool:
    return (
        evidence.provenance_policy == NATIVE_EVIDENCE_POLICY
        and evidence.execution_subject
        in {
            ExecutionSubject.PREPARED_BINARY,
            ExecutionSubject.LINKED_TARGET_HARNESS,
        }
        and evidence.target_source_reached
        and any(frame.in_target for frame in evidence.sanitizer_frames)
        and evidence.sanitizer_failure_class is not None
        and bool(evidence.clean_environment_id)
    )


def actual_target_group_agrees(evidence: list[Evidence]) -> bool:
    if not evidence or not all(has_actual_target_provenance(item) for item in evidence):
        return False
    subjects = {item.execution_subject for item in evidence}
    snapshots = {item.source_snapshot for item in evidence}
    failures = {item.sanitizer_failure_class for item in evidence}
    environments = {item.clean_environment_id for item in evidence}
    return (
        len(subjects) == 1
        and len(snapshots) == 1
        and len(failures) == 1
        and len(environments) == len(evidence)
    )


def _is_target_path(path: str) -> bool:
    return any(path.startswith(root) for root in _TARGET_ROOTS)


def _target_artifacts(
    argv: tuple[str, ...],
    setup_argvs: tuple[tuple[str, ...], ...],
    frames: tuple[SanitizerFrame, ...],
) -> tuple[str, ...]:
    values = {
        value.rstrip(".,")
        for command in (*setup_argvs, argv)
        for value in command
        if _is_target_path(value)
    }
    values.update(frame.path for frame in frames)
    return tuple(sorted(values))


def _integer(value: str | None) -> int | None:
    return int(value) if value else None
