from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnhunt_agent.macos.imageio_fuzzer import (
    ImageIOBehaviorSignature,
    ImageIODecodeStage,
    ImageIOFuzzBudget,
    ImageIOFuzzClassification,
    ImageIOMutationOperator,
    PrivateImageIOFuzzStore,
    PrivateImageIOPayloadHistory,
    build_minimal_dicom_seed,
    generate_dicom_fuzz_cases,
    run_imageio_fuzz_campaign,
)
from vulnhunt_agent.macos.imageio_fuzz_benchmark import (
    ImageIOFuzzBenchmarkStatus,
    assess_imageio_fuzz_benchmark,
)
from vulnhunt_agent.macos.imageio_harness import (
    ImageIOVMCommand,
    ImageIOVMCommandResult,
    ImageIOVMEnvironment,
    ImageIOVMIsolationAttestation,
)

IMAGE_SHA = "sha256:" + "a" * 64
CONFIG_SHA = "sha256:" + "b" * 64
SECURITY_SHA = "sha256:" + "c" * 64


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _environment() -> ImageIOVMEnvironment:
    return ImageIOVMEnvironment(
        environment_id="imageio-vm-stable-fuzzer-01",
        manager="test-utm-runner",
        product_version="26.6",
        build_version="25G72",
        image_sha256=IMAGE_SHA,
        clean_snapshot_id="stable-clean-v1",
        disposable_clone_id="fuzz-clone-0001",
    )


def _attestation(environment: ImageIOVMEnvironment) -> ImageIOVMIsolationAttestation:
    return ImageIOVMIsolationAttestation(
        environment_id=environment.environment_id,
        manager=environment.manager,
        product_version=environment.product_version,
        build_version=environment.build_version,
        architecture="arm64",
        image_sha256=environment.image_sha256,
        snapshot_id=environment.clean_snapshot_id,
        clone_id=environment.disposable_clone_id,
        runtime_instance_id="runtime-clone-0001",
        runtime_configuration_sha256=CONFIG_SHA,
        security_configuration_sha256=SECURITY_SHA,
        boot_id="boot-0001",
        observed_at=datetime.now(UTC),
        virtualization_framework="com.apple.Virtualization",
        execution_boundary="macos_virtual_machine",
        network_device_count=0,
        outbound_network_enabled=False,
        clean_snapshot=True,
        disposable_clone=True,
        executed_on_host=False,
    )


class DeterministicFuzzRunner:
    def __init__(
        self,
        *,
        seed: bytes,
        crash_sha256: str,
        deep_seed: bool = True,
        deep_mutations: bool = False,
    ) -> None:
        self.seed = seed
        self.crash_sha256 = crash_sha256
        self.deep_seed = deep_seed
        self.deep_mutations = deep_mutations
        self.commands: list[ImageIOVMCommand] = []

    def attest(
        self,
        environment: ImageIOVMEnvironment,
    ) -> ImageIOVMIsolationAttestation:
        return _attestation(environment)

    def execute(self, command: ImageIOVMCommand) -> ImageIOVMCommandResult:
        self.commands.append(command)
        payload = command.input_path.read_bytes()
        if command.input_sha256 == self.crash_sha256:
            exit_code = None
            signal = 11
            stdout = b""
            crash_log = b"Process: imageio-harness\nException Type: EXC_BAD_ACCESS\n"
        else:
            exit_code = 0
            signal = None
            crash_log = None
            if payload == self.seed:
                result: dict[str, object] = {
                    "source_created": True,
                    "type_identifier": "org.nema.dicom",
                    "image_count": 1,
                    "status": 0,
                }
                if command.route.value in {"data_properties", "image_properties"}:
                    result.update({"properties_available": True, "property_count": 8})
                if command.route.value in {"full_decode", "incremental_decode"}:
                    result.update(
                        {
                            "image_created": self.deep_seed,
                            "pixels_rendered": self.deep_seed,
                            "width": 1,
                            "height": 1,
                            "decoded_bytes": 4,
                        }
                    )
                if command.route.value == "incremental_decode":
                    result.update({"update_count": 2, "statuses": [-1, 0]})
                stdout = (json.dumps(result) + "\n").encode()
            elif self.deep_mutations:
                status = int.from_bytes(hashlib.sha256(payload).digest()[:2], "big")
                stdout = (
                    json.dumps(
                        {
                            "source_created": True,
                            "type_identifier": "org.nema.dicom",
                            "image_count": 1,
                            "status": status,
                            "image_created": True,
                            "pixels_rendered": True,
                            "width": 1,
                            "height": 1,
                            "decoded_bytes": 4,
                        }
                    )
                    + "\n"
                ).encode()
            elif len(payload) < len(self.seed):
                stdout = b'{"source_created":false,"status":-1}\n'
            else:
                stdout = (
                    b'{"source_created":true,"type_identifier":"org.nema.dicom",'
                    b'"image_count":1,"status":-4}\n'
                )
        return ImageIOVMCommandResult(
            environment_id=command.environment.environment_id,
            boot_id="boot-0001",
            argv=command.argv,
            guest_input_sha256=command.input_sha256,
            enforced_limits=command.limits,
            exit_code=exit_code,
            terminating_signal=signal,
            timed_out=False,
            launch_error=None,
            duration_ms=5,
            stdout=stdout,
            stderr=b"",
            crash_log=crash_log,
        )


def test_minimal_seed_generates_a_stable_bounded_corpus() -> None:
    seed = build_minimal_dicom_seed()

    first = generate_dicom_fuzz_cases(seed, campaign_seed="campaign-001", max_cases=80)
    second = generate_dicom_fuzz_cases(seed, campaign_seed="campaign-001", max_cases=80)

    assert seed[128:132] == b"DICM"
    assert first == second
    assert len(first) == 80
    assert len({case.manifest.case_id for case in first}) == len(first)
    assert len({case.manifest.input_sha256 for case in first}) == len(first)
    assert all(case.manifest.input_sha256 == _sha256(case.payload) for case in first)
    assert all(case.manifest.input_size_bytes == len(case.payload) for case in first)
    assert all(case.manifest.routes for case in first)
    assert any(
        case.manifest.operator is ImageIOMutationOperator.SEMANTIC_US_BOUNDARY for case in first
    )


def test_campaign_seed_changes_case_identity_and_bit_selection() -> None:
    seed = build_minimal_dicom_seed()
    first = generate_dicom_fuzz_cases(seed, campaign_seed="campaign-a", max_cases=80)
    second = generate_dicom_fuzz_cases(seed, campaign_seed="campaign-b", max_cases=80)

    assert [case.manifest.case_id for case in first] != [case.manifest.case_id for case in second]
    first_flips = [
        case.payload
        for case in first
        if case.manifest.operator is ImageIOMutationOperator.VALUE_BIT_FLIP
    ]
    second_flips = [
        case.payload
        for case in second
        if case.manifest.operator is ImageIOMutationOperator.VALUE_BIT_FLIP
    ]
    assert first_flips != second_flips


def test_small_budget_prioritizes_pixel_layout_over_file_metadata() -> None:
    cases = generate_dicom_fuzz_cases(
        build_minimal_dicom_seed(),
        campaign_seed="pixel-priority",
        max_cases=40,
    )
    target_tags = {case.manifest.target_tag for case in cases}

    assert {
        "0028,0002",
        "0028,0010",
        "0028,0011",
        "0028,0100",
        "0028,0101",
        "0028,0102",
        "0028,0103",
        "7FE0,0010",
    } <= target_tags
    assert all(not case.manifest.target_tag.startswith("0002,") for case in cases)


def test_relation_mutations_preserve_cross_tag_evidence_and_decode_routes() -> None:
    cases = generate_dicom_fuzz_cases(
        build_minimal_dicom_seed(),
        campaign_seed="relation-cases",
        max_cases=24,
    )
    relations = [
        case
        for case in cases
        if case.manifest.operator is ImageIOMutationOperator.PIXEL_LAYOUT_RELATION
    ]

    assert len(relations) == 5
    assert all("7FE0,0010" in case.manifest.related_tags for case in relations)
    assert all(
        tuple(route.value for route in case.manifest.routes)
        == ("image_properties", "full_decode", "incremental_decode")
        for case in relations
    )
    assert any(len(case.manifest.related_tags) >= 5 for case in relations)


def test_pixel_data_size_relations_keep_the_dicom_structure_parseable() -> None:
    seed = build_minimal_dicom_seed()
    cases = generate_dicom_fuzz_cases(
        seed,
        campaign_seed="pixel-size-relations",
        max_cases=8,
    )
    relations = [
        case
        for case in cases
        if case.manifest.operator is ImageIOMutationOperator.PIXEL_DATA_SIZE_RELATION
    ]

    assert relations
    assert all(case.manifest.target_tag == "7FE0,0010" for case in relations)
    assert all("0028,0010" in case.manifest.related_tags for case in relations)
    assert all(
        tuple(route.value for route in case.manifest.routes)
        == ("full_decode", "incremental_decode")
        for case in relations
    )
    for case in relations:
        assert generate_dicom_fuzz_cases(
            case.payload,
            campaign_seed="parseable-child",
            max_cases=1,
            generation=2,
            root_seed_sha256=case.manifest.seed_sha256,
            parent_input_sha256=case.manifest.input_sha256,
        )


def test_route_budget_matches_mutation_semantics() -> None:
    cases = generate_dicom_fuzz_cases(
        build_minimal_dicom_seed(),
        campaign_seed="route-budget",
        max_cases=10_000,
    )
    pixel_data = [case for case in cases if case.manifest.target_tag == "7FE0,0010"]
    file_metadata = [
        case for case in cases if case.manifest.target_tag.startswith("0002,")
    ]

    assert pixel_data
    assert file_metadata
    assert all(
        tuple(route.value for route in case.manifest.routes)
        == ("full_decode", "incremental_decode")
        for case in pixel_data
    )
    assert all(
        tuple(route.value for route in case.manifest.routes) == ("data_properties",)
        for case in file_metadata
    )


@pytest.mark.parametrize(
    "invalid",
    [b"", b"\x00" * 132, b"\x00" * 128 + b"DICM" + b"truncated"],
)
def test_generator_rejects_non_dicom_or_truncated_seeds(invalid: bytes) -> None:
    with pytest.raises(ValueError):
        generate_dicom_fuzz_cases(invalid, campaign_seed="campaign-001")


def test_campaign_runs_one_vm_runner_and_retains_only_interesting_raw_artifacts(
    tmp_path: Path,
) -> None:
    seed = build_minimal_dicom_seed()
    seed_path = tmp_path / "seed.dcm"
    seed_path.write_bytes(seed)
    generated = generate_dicom_fuzz_cases(seed, campaign_seed="campaign-001", max_cases=3)
    runner = DeterministicFuzzRunner(
        seed=seed,
        crash_sha256=generated[0].manifest.input_sha256,
    )
    store = PrivateImageIOFuzzStore(tmp_path / "private-campaign")

    summary = run_imageio_fuzz_campaign(
        runner=runner,
        environment=_environment(),
        seed_path=seed_path,
        store=store,
        campaign_id="imageio-fuzz-dicom-smoke",
        campaign_seed="campaign-001",
        budget=ImageIOFuzzBudget(max_cases=3, max_executions=13),
    )

    assert summary.generated_cases == 3
    assert summary.executed_cases == 3
    assert summary.seed_qualification is not None
    assert summary.seed_qualification.deepest_stage is ImageIODecodeStage.PIXELS_RENDERED
    assert len(summary.seed_qualification.executions) == 4
    assert summary.model_calls == 0
    assert summary.classification_counts[ImageIOFuzzClassification.CRASH_CANDIDATE] == 2
    assert summary.classification_counts[ImageIOFuzzClassification.NORMAL] >= 1
    assert summary.interesting_case_ids == (generated[0].manifest.case_id,)
    finding = store.root / "interesting" / generated[0].manifest.case_id
    assert (finding / "input.dcm").read_bytes() == generated[0].payload
    assert (finding / "full_decode" / "crash.log").exists()
    assert (store.root / "campaign-summary.json").exists()
    assert len(runner.commands) == summary.execution_count
    assert all(command.environment == _environment() for command in runner.commands)


def test_campaign_rejects_a_seed_that_does_not_render_pixels(tmp_path: Path) -> None:
    seed = build_minimal_dicom_seed()
    seed_path = tmp_path / "seed.dcm"
    seed_path.write_bytes(seed)
    runner = DeterministicFuzzRunner(
        seed=seed,
        crash_sha256="sha256:" + "f" * 64,
        deep_seed=False,
    )
    store = PrivateImageIOFuzzStore(tmp_path / "private-shallow-seed")

    with pytest.raises(RuntimeError, match="full_decode qualification"):
        run_imageio_fuzz_campaign(
            runner=runner,
            environment=_environment(),
            seed_path=seed_path,
            store=store,
            campaign_id="imageio-fuzz-dicom-shallow",
            campaign_seed="campaign-shallow",
            budget=ImageIOFuzzBudget(max_cases=3, max_executions=13),
        )

    assert [command.route.value for command in runner.commands] == [
        "data_properties",
        "image_properties",
        "full_decode",
    ]
    assert not (store.root / "cases").exists()
    assert not (store.root / "campaign-summary.json").exists()


def test_novel_deep_behavior_grows_a_bounded_second_generation(tmp_path: Path) -> None:
    seed = build_minimal_dicom_seed()
    seed_path = tmp_path / "seed.dcm"
    seed_path.write_bytes(seed)
    runner = DeterministicFuzzRunner(
        seed=seed,
        crash_sha256="sha256:" + "f" * 64,
        deep_mutations=True,
    )
    store = PrivateImageIOFuzzStore(tmp_path / "private-feedback-campaign")

    summary = run_imageio_fuzz_campaign(
        runner=runner,
        environment=_environment(),
        seed_path=seed_path,
        store=store,
        campaign_id="imageio-fuzz-dicom-feedback",
        campaign_seed="campaign-feedback",
        budget=ImageIOFuzzBudget(
            max_cases=8,
            max_feedback_cases=3,
            max_generations=2,
            max_children_per_novel_input=2,
            max_executions=64,
        ),
    )

    assert 8 < summary.generated_cases <= 11
    assert summary.executed_cases == summary.generated_cases
    assert summary.generation_counts[1] == 8
    assert 0 < summary.generation_counts[2] <= 3
    assert summary.max_generation_reached == 2
    assert summary.novel_behavior_case_ids
    assert summary.corpus_input_sha256s
    assert len(summary.corpus_input_sha256s) <= 3
    case_payloads = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (store.root / "cases").glob("*.json")
    ]
    assert (
        sum(payload["case"]["generation"] == 2 for payload in case_payloads)
        == summary.generation_counts[2]
    )
    assert all(
        (store.root / "corpus" / digest.removeprefix("sha256:") / "input.dcm").exists()
        for digest in summary.corpus_input_sha256s
    )


def test_shared_private_history_skips_payloads_from_an_earlier_campaign(
    tmp_path: Path,
) -> None:
    seed = build_minimal_dicom_seed()
    seed_path = tmp_path / "seed.dcm"
    seed_path.write_bytes(seed)
    history = PrivateImageIOPayloadHistory(tmp_path / "shared-payload-history")
    budget = ImageIOFuzzBudget(
        max_cases=3,
        max_feedback_cases=0,
        max_generations=1,
        max_executions=10,
    )

    first_runner = DeterministicFuzzRunner(
        seed=seed,
        crash_sha256="sha256:" + "f" * 64,
    )
    first = run_imageio_fuzz_campaign(
        runner=first_runner,
        environment=_environment(),
        seed_path=seed_path,
        store=PrivateImageIOFuzzStore(tmp_path / "first-campaign"),
        campaign_id="imageio-fuzz-history-first",
        campaign_seed="same-seed",
        budget=budget,
        history=history,
    )
    second_runner = DeterministicFuzzRunner(
        seed=seed,
        crash_sha256="sha256:" + "f" * 64,
    )
    second = run_imageio_fuzz_campaign(
        runner=second_runner,
        environment=_environment(),
        seed_path=seed_path,
        store=PrivateImageIOFuzzStore(tmp_path / "second-campaign"),
        campaign_id="imageio-fuzz-history-second",
        campaign_seed="same-seed",
        budget=budget,
        history=history,
    )

    assert first.executed_cases == 3
    assert first.duplicate_payloads_skipped == 0
    assert second.executed_cases == 0
    assert second.duplicate_payloads_skipped == 3
    assert second.execution_count == 4
    assert len(second_runner.commands) == 4
    assert len(tuple((history.root / "executed").iterdir())) == 3


def test_benchmark_gate_requires_coverage_depth_cleanup_and_an_actual_crash(
    tmp_path: Path,
) -> None:
    seed = build_minimal_dicom_seed()
    seed_path = tmp_path / "seed.dcm"
    seed_path.write_bytes(seed)
    generated = generate_dicom_fuzz_cases(
        seed,
        campaign_seed="benchmark-gate",
        max_cases=40,
    )
    runner = DeterministicFuzzRunner(
        seed=seed,
        crash_sha256=generated[0].manifest.input_sha256,
        deep_mutations=True,
    )
    store = PrivateImageIOFuzzStore(tmp_path / "benchmark-campaign")
    budget = ImageIOFuzzBudget(
        max_cases=40,
        max_feedback_cases=0,
        max_generations=1,
        max_executions=160,
    )
    summary = run_imageio_fuzz_campaign(
        runner=runner,
        environment=_environment(),
        seed_path=seed_path,
        store=store,
        campaign_id="imageio-fuzz-benchmark-gate",
        campaign_seed="benchmark-gate",
        budget=budget,
    )

    passed = assess_imageio_fuzz_benchmark(
        store_root=store.root,
        summary=summary,
        budget=budget,
        disposable_clone_cleanup_verified=True,
    )
    failed_cleanup = assess_imageio_fuzz_benchmark(
        store_root=store.root,
        summary=summary,
        budget=budget,
        disposable_clone_cleanup_verified=False,
    )

    assert passed.status is ImageIOFuzzBenchmarkStatus.PASSED
    assert passed.ready_for_crash_triage is True
    assert passed.missing_pixel_tags == ()
    assert passed.unique_executed_input_ratio == 1.0
    assert passed.pixel_rendered_case_count > 0
    assert passed.crash_candidate_count == 1
    assert passed.host_execution_count == 0
    assert failed_cleanup.status is ImageIOFuzzBenchmarkStatus.FAILED
    assert failed_cleanup.ready_for_crash_triage is False
    assert "disposable clone cleanup was not verified" in failed_cleanup.failures


def test_legacy_behavior_infers_its_decode_stage() -> None:
    behavior = ImageIOBehaviorSignature.model_validate(
        {
            "signature_sha256": "sha256:" + "e" * 64,
            "source_created": True,
            "type_identifier": "org.nema.dicom",
            "image_count": 1,
            "image_created": True,
            "pixels_rendered": True,
        }
    )

    assert behavior.decode_stage is ImageIODecodeStage.PIXELS_RENDERED


def test_private_store_and_fuzzer_source_remain_outside_models_and_git(
    tmp_path: Path,
) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    with pytest.raises(ValueError, match="Git worktree"):
        PrivateImageIOFuzzStore(repository_root / "private-fuzz")

    source = (repository_root / "src/vulnhunt_agent/macos/imageio_fuzzer.py").read_text()
    assert "openai" not in source.casefold()
    assert "boto" not in source.casefold()
    store = PrivateImageIOFuzzStore(tmp_path / "private")
    assert store.root.is_dir()
