from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from vulnhunt_agent.agents.durable_queue import DurableHuntQueueStore
from vulnhunt_agent.domain.schemas import BudgetPolicy, HunterWorkItem, RunRecord
from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
from vulnhunt_agent.macos.imageio_crashes import (
    ImageIOCrashTriageClass,
    build_imageio_crash_hunter_plan,
    cluster_imageio_crashes,
    load_imageio_crash_observations,
    minimize_imageio_crash,
)
from vulnhunt_agent.macos.imageio_fuzzer import (
    ImageIOFuzzCase,
    ImageIOFuzzCaseResult,
    ImageIOFuzzClassification,
    ImageIOFuzzExecution,
    ImageIOMutationOperator,
)
from vulnhunt_agent.macos.imageio_harness import (
    ImageIOHarnessEvidence,
    ImageIOHarnessLimits,
    ImageIOVMExitReason,
)
from vulnhunt_agent.macos.imageio_inventory import ImageIOAPIRoute
from vulnhunt_agent.reporting.apple_cve import AppleCrashClass

SOURCE_SNAPSHOT = "sha256:" + "a" * 64
PRE_ATTESTATION = "sha256:" + "b" * 64
POST_ATTESTATION = "sha256:" + "c" * 64


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _crash_log(
    *,
    address: str,
    offset: int,
    marker: str = "ERROR: AddressSanitizer: heap-use-after-free",
) -> bytes:
    return f"""Process: imageio-harness
Exception Type: EXC_BAD_ACCESS (SIGSEGV)
Exception Subtype: KERN_INVALID_ADDRESS at {address}
{marker}
Thread 0 Crashed:
0   ImageIO  0x00000001 DICOMDecodePixelData + {offset}
1   ImageIO  0x00000002 DICOMCreateImage + {offset + 10}
2   imageio-harness 0x00000003 main + 99

""".encode()


def _evidence(
    *,
    route: ImageIOAPIRoute,
    payload: bytes,
    crash_log: bytes | None,
) -> ImageIOHarnessEvidence:
    complete = crash_log is not None
    return ImageIOHarnessEvidence(
        environment_id="imageio-vm-test-crashes",
        boot_id="boot-test-001",
        route=route,
        input_sha256=_sha256(payload),
        input_size_bytes=len(payload),
        argv=("/opt/vulnhunt/bin/imageio-harness", "--route", route.value),
        limits=ImageIOHarnessLimits(),
        exit_reason=ImageIOVMExitReason.SIGNALED,
        exit_code=None,
        terminating_signal=11,
        duration_ms=4,
        stdout_sha256=_sha256(b""),
        stderr_sha256=_sha256(b""),
        crash_log_sha256=_sha256(crash_log) if crash_log is not None else None,
        pre_attestation_sha256=PRE_ATTESTATION,
        post_attestation_sha256=POST_ATTESTATION,
        evidence_complete=complete,
        evidence_gaps=(
            () if complete else ("signaled process has no captured crash log",)
        ),
    )


def _write_crash_case(
    store: Path,
    *,
    suffix: str,
    route: ImageIOAPIRoute,
    payload: bytes,
    crash_log: bytes | None,
) -> str:
    case_id = "case-" + suffix * 32
    evidence = _evidence(route=route, payload=payload, crash_log=crash_log)
    case = ImageIOFuzzCase(
        case_id=case_id,
        campaign_seed="test-campaign",
        seed_sha256="sha256:" + "d" * 64,
        input_sha256=_sha256(payload),
        input_size_bytes=len(payload),
        operator=ImageIOMutationOperator.VALUE_BIT_FLIP,
        target_tag="0028,0010",
        target_offset=140,
        parameter="relative:0:mask:0x80",
        routes=(route,),
    )
    result = ImageIOFuzzCaseResult(
        case=case,
        executions=(
            ImageIOFuzzExecution(
                route=route,
                classification=ImageIOFuzzClassification.CRASH_CANDIDATE,
                evidence=evidence,
            ),
        ),
        interesting=True,
    )
    cases = store / "cases"
    cases.mkdir(parents=True, exist_ok=True)
    (cases / f"{case_id}.json").write_text(
        json.dumps(result.model_dump(mode="json")),
        encoding="utf-8",
    )
    finding = store / "interesting" / case_id
    route_root = finding / route.value
    route_root.mkdir(parents=True)
    (finding / "input.dcm").write_bytes(payload)
    if crash_log is not None:
        (route_root / "crash.log").write_bytes(crash_log)
    return case_id


def test_aslr_addresses_and_offsets_normalize_to_one_crash_cluster(
    tmp_path: Path,
) -> None:
    store = tmp_path / "private-campaign"
    store.mkdir()
    _write_crash_case(
        store,
        suffix="1",
        route=ImageIOAPIRoute.FULL_DECODE,
        payload=b"DICM-first-crash",
        crash_log=_crash_log(address="0x0000000123456789", offset=44),
    )
    _write_crash_case(
        store,
        suffix="2",
        route=ImageIOAPIRoute.INCREMENTAL_DECODE,
        payload=b"DICM-second-crash",
        crash_log=_crash_log(address="0x0000000999999999", offset=812),
    )

    observations = load_imageio_crash_observations(store)
    clusters = cluster_imageio_crashes(observations)

    assert len(observations) == 2
    assert len(clusters) == 1
    cluster = clusters[0]
    assert cluster.triage_class is ImageIOCrashTriageClass.STRONG_MEMORY_SAFETY
    assert cluster.apple_crash_class is AppleCrashClass.USE_AFTER_FREE
    assert cluster.hunter_eligible is True
    assert len(cluster.observations) == 2
    assert cluster.ranking_score >= 500
    assert {item.route for item in cluster.observations} == {
        ImageIOAPIRoute.FULL_DECODE,
        ImageIOAPIRoute.INCREMENTAL_DECODE,
    }


@pytest.mark.parametrize(
    ("address", "marker", "expected"),
    [
        ("0x0000000000000010", "ordinary bad access", ImageIOCrashTriageClass.NULL_DEREFERENCE),
        ("0x0000000123456789", "Assertion failed: rows > 0", ImageIOCrashTriageClass.ASSERTION),
    ],
)
def test_low_value_crashes_do_not_create_hunter_work(
    tmp_path: Path,
    address: str,
    marker: str,
    expected: ImageIOCrashTriageClass,
) -> None:
    store = tmp_path / "private-campaign"
    store.mkdir()
    _write_crash_case(
        store,
        suffix="3",
        route=ImageIOAPIRoute.FULL_DECODE,
        payload=b"DICM-low-value",
        crash_log=_crash_log(address=address, offset=10, marker=marker),
    )

    plan = build_imageio_crash_hunter_plan(
        store_root=store,
        run_id="imageio-run-low-value",
        source_snapshot=SOURCE_SNAPSHOT,
        budget=BudgetPolicy(max_hunter_sessions=4),
    )
    repeated = build_imageio_crash_hunter_plan(
        store_root=store,
        run_id="imageio-run-dedup",
        source_snapshot=SOURCE_SNAPSHOT,
        budget=BudgetPolicy(max_hunter_sessions=4),
    )

    assert repeated == plan
    assert plan.clusters[0].triage_class is expected
    assert plan.routing.work_items == ()
    assert plan.admitted_work_items == ()


def test_duplicate_cluster_creates_one_existing_hunter_work_item_and_queue_task(
    tmp_path: Path,
) -> None:
    store = tmp_path / "private-campaign"
    store.mkdir()
    _write_crash_case(
        store,
        suffix="4",
        route=ImageIOAPIRoute.FULL_DECODE,
        payload=b"DICM-first-crash",
        crash_log=_crash_log(address="0x0000000123456789", offset=44),
    )
    _write_crash_case(
        store,
        suffix="5",
        route=ImageIOAPIRoute.INCREMENTAL_DECODE,
        payload=b"DICM-second-crash",
        crash_log=_crash_log(address="0x0000000999999999", offset=812),
    )

    plan = build_imageio_crash_hunter_plan(
        store_root=store,
        run_id="imageio-run-dedup",
        source_snapshot=SOURCE_SNAPSHOT,
        budget=BudgetPolicy(max_hunter_sessions=4),
    )

    assert len(plan.clusters) == 1
    assert len(plan.routing.work_items) == 1
    assert len(plan.admitted_work_items) == 1
    assert isinstance(plan.admitted_work_items[0], HunterWorkItem)
    assert plan.routing.legacy_sessions == 2
    assert plan.allocation.admitted_work_ids == (
        plan.admitted_work_items[0].work_id,
    )
    assert plan.allocation.ranking[0].pre_admission_rank == 1
    assert plan.admitted_work_items[0].hunter == "imageio-crash-analysis"
    context = store / plan.admitted_work_items[0].seed_file
    assert context.name == "cluster.json"
    assert context.exists()
    assert (store / "hunter-plan.json").exists()
    assert json.loads((store / "hunter-plan.json").read_text())["model_calls"] == 0

    database = store / "state.db"
    with SqliteRepository(database) as repository:
        repository.save_run(
            RunRecord(
                run_id="imageio-run-dedup",
                source_snapshot=SOURCE_SNAPSHOT,
            )
        )
    queue_store = DurableHuntQueueStore(
        store / "hunters",
        database,
        "imageio-run-dedup",
    )
    queue = queue_store.init_from_work_items(plan.admitted_work_items)
    assert len(queue.tasks) == 1
    assert queue.tasks[0].work_id == plan.admitted_work_items[0].work_id


def test_dynamic_cluster_rank_is_the_actual_admission_order(tmp_path: Path) -> None:
    store = tmp_path / "private-campaign"
    store.mkdir()
    _write_crash_case(
        store,
        suffix="6",
        route=ImageIOAPIRoute.FULL_DECODE,
        payload=b"DICM-undifferentiated",
        crash_log=_crash_log(
            address="0x0000000123000000",
            offset=10,
            marker="SIGABRT without a memory diagnostic",
        ),
    )
    _write_crash_case(
        store,
        suffix="7",
        route=ImageIOAPIRoute.FULL_DECODE,
        payload=b"DICM-strong",
        crash_log=_crash_log(address="0x0000000123999999", offset=20),
    )

    plan = build_imageio_crash_hunter_plan(
        store_root=store,
        run_id="imageio-run-ranked",
        source_snapshot=SOURCE_SNAPSHOT,
        budget=BudgetPolicy(max_hunter_sessions=1, max_retries_per_work_item=0),
    )

    assert len(plan.clusters) == 2
    assert plan.clusters[0].ranking_score > plan.clusters[1].ranking_score
    assert plan.allocation.ranking[0].work_id == plan.admitted_work_items[0].work_id
    assert plan.admitted_work_items[0].risk == plan.clusters[0].risk
    assert len(plan.allocation.deferred) == 1


def test_bounded_minimizer_preserves_the_exact_crash_signature() -> None:
    signature = "sha256:" + "9" * 64
    payload = b"DICM" + b"unused-prefix" + b"TRIGGER" + b"unused-suffix"

    def oracle(candidate: bytes) -> str | None:
        return signature if candidate.startswith(b"DICM") and b"TRIGGER" in candidate else None

    minimized = minimize_imageio_crash(
        payload,
        target_signature_sha256=signature,
        oracle=oracle,
        max_attempts=64,
        protected_prefix_bytes=4,
    )

    assert minimized.payload.startswith(b"DICM")
    assert b"TRIGGER" in minimized.payload
    assert len(minimized.payload) < len(payload)
    assert oracle(minimized.payload) == signature
    assert minimized.record.minimized_sha256 == _sha256(minimized.payload)
    assert minimized.record.reduction_percent > 0


def test_incomplete_crash_evidence_is_retained_but_not_scheduled(tmp_path: Path) -> None:
    store = tmp_path / "private-campaign"
    store.mkdir()
    _write_crash_case(
        store,
        suffix="8",
        route=ImageIOAPIRoute.FULL_DECODE,
        payload=b"DICM-no-log",
        crash_log=None,
    )

    plan = build_imageio_crash_hunter_plan(
        store_root=store,
        run_id="imageio-run-incomplete",
        source_snapshot=SOURCE_SNAPSHOT,
        budget=BudgetPolicy(max_hunter_sessions=4),
    )

    assert plan.clusters[0].triage_class is ImageIOCrashTriageClass.INCOMPLETE
    assert plan.clusters[0].hunter_eligible is False
    assert plan.routing.work_items == ()


def test_crash_ranking_and_minimization_never_import_a_model_client() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "src/vulnhunt_agent/macos/imageio_crashes.py"
    ).read_text(encoding="utf-8")

    assert "openai" not in source.casefold()
    assert "boto" not in source.casefold()
