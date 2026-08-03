from __future__ import annotations

import hashlib
import json
import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnhunt_agent.macos.imageio_fuzzer import (
    build_minimal_dicom_seed,
    generate_dicom_fuzz_cases,
)
from vulnhunt_agent.macos.imageio_harness import (
    ImageIOVMCommand,
    ImageIOVMCommandResult,
    ImageIOVMEnvironment,
    ImageIOVMIsolationAttestation,
)
from vulnhunt_agent.macos.imageio_inventory import ImageIOAPIRoute
from vulnhunt_agent.macos.imageio_sgi import (
    ImageIOSGIMutationCase,
    ImageIOSGIRelation,
    build_minimal_sgi_rle_seed,
    generate_sgi_relational_cases,
    parse_sgi_rle_seed,
    qualify_sgi_seed,
)

_IMAGE_SHA = "sha256:" + "a" * 64
_CONFIG_SHA = "sha256:" + "b" * 64
_SECURITY_SHA = "sha256:" + "c" * 64


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _environment() -> ImageIOVMEnvironment:
    return ImageIOVMEnvironment(
        environment_id="imageio-vm-m16-sgi-current",
        manager="UTM-Apple-Virtualization",
        product_version="26.6",
        build_version="25G84",
        image_sha256=_IMAGE_SHA,
        clean_snapshot_id="m16-clean-v1",
        disposable_clone_id="m16-sgi-clone-01",
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
        runtime_instance_id="m16-sgi-runtime",
        runtime_configuration_sha256=_CONFIG_SHA,
        security_configuration_sha256=_SECURITY_SHA,
        boot_id="m16-sgi-boot",
        observed_at=datetime.now(UTC),
        virtualization_framework="com.apple.Virtualization",
        execution_boundary="macos_virtual_machine",
        network_device_count=0,
        outbound_network_enabled=False,
        clean_snapshot=True,
        disposable_clone=True,
        executed_on_host=False,
    )


class SGIQualificationRunner:
    def __init__(
        self,
        *,
        type_identifier: str = "com.sgi.sgi-image",
        raw_pixels_copied: bool = True,
    ) -> None:
        self.type_identifier = type_identifier
        self.raw_pixels_copied = raw_pixels_copied
        self.commands: list[ImageIOVMCommand] = []

    def attest(
        self,
        environment: ImageIOVMEnvironment,
    ) -> ImageIOVMIsolationAttestation:
        return _attestation(environment)

    def execute(self, command: ImageIOVMCommand) -> ImageIOVMCommandResult:
        self.commands.append(command)
        result: dict[str, object] = {
            "source_created": True,
            "type_identifier": self.type_identifier,
            "image_count": 1,
            "image_created": True,
            "width": 1,
            "height": 1,
            "decoded_bytes": 4,
        }
        if command.route is ImageIOAPIRoute.FULL_DECODE:
            result["pixels_rendered"] = True
        else:
            result["raw_pixels_copied"] = self.raw_pixels_copied
            result["output_sha256"] = "sha256:" + "d" * 64
        return ImageIOVMCommandResult(
            environment_id=command.environment.environment_id,
            boot_id="m16-sgi-boot",
            argv=command.argv,
            guest_input_sha256=command.input_sha256,
            enforced_limits=command.limits,
            exit_code=0,
            terminating_signal=None,
            timed_out=False,
            launch_error=None,
            duration_ms=5,
            stdout=(json.dumps(result) + "\n").encode(),
            stderr=b"",
            crash_log=None,
        )


def test_minimal_sgi_seed_has_bounded_big_endian_rle_tables() -> None:
    seed = build_minimal_sgi_rle_seed()
    layout = parse_sgi_rle_seed(seed)

    assert seed[:4] == b"\x01\xda\x01\x01"
    assert layout.seed_sha256 == _sha256(seed)
    assert (layout.width, layout.height, layout.channel_count) == (1, 1, 3)
    assert layout.table_count == 3
    assert layout.table_data_offset == 536
    assert tuple(item.data_offset for item in layout.rows) == (536, 539, 542)
    assert tuple(item.byte_length for item in layout.rows) == (3, 3, 3)


def test_sgi_relational_cases_are_deterministic_bounded_and_complete() -> None:
    seed = build_minimal_sgi_rle_seed()

    first = generate_sgi_relational_cases(seed)
    second = generate_sgi_relational_cases(seed)

    assert first == second
    assert len(first) == 15
    assert len(first) <= 16
    assert {case.manifest.asserted_relation for case in first} == set(
        ImageIOSGIRelation
    )
    assert len({case.manifest.case_id for case in first}) == len(first)
    assert len({case.manifest.input_sha256 for case in first}) == len(first)
    assert all(case.manifest.input_sha256 == _sha256(case.payload) for case in first)
    assert all(case.manifest.model_calls == 0 for case in first)
    assert all(
        case.manifest.routes
        == (ImageIOAPIRoute.FULL_DECODE, ImageIOAPIRoute.RAW_PIXEL_COPY)
        for case in first
    )


def test_sgi_mutations_change_only_the_selected_range_or_truncate_tail() -> None:
    seed = build_minimal_sgi_rle_seed()
    cases = generate_sgi_relational_cases(seed)

    for generated in cases:
        case = generated.manifest
        assert struct.unpack_from(">I", generated.payload, case.start_table_offset)[0] == (
            case.mutated_start
        )
        assert struct.unpack_from(">I", generated.payload, case.length_table_offset)[0] == (
            case.mutated_length
        )
        if case.operator is ImageIOSGIRelation.TRUNCATED_AVAILABLE_TAIL:
            assert generated.payload == seed[: case.input_size_bytes]
            continue
        mutable = set(range(case.start_table_offset, case.start_table_offset + 4)) | set(
            range(case.length_table_offset, case.length_table_offset + 4)
        )
        differences = {
            index
            for index, (left, right) in enumerate(zip(seed, generated.payload, strict=True))
            if left != right
        }
        assert differences
        assert differences <= mutable


def test_manifest_relation_and_identity_are_tamper_evident() -> None:
    manifest = generate_sgi_relational_cases(build_minimal_sgi_rle_seed())[0].manifest
    payload = manifest.model_dump(mode="json")
    payload["mutated_length"] = 1
    with pytest.raises(ValidationError):
        ImageIOSGIMutationCase.model_validate(payload)

    payload = manifest.model_dump(mode="json")
    payload["input_sha256"] = "sha256:" + "f" * 64
    with pytest.raises(ValidationError):
        ImageIOSGIMutationCase.model_validate(payload)


@pytest.mark.parametrize(
    "mutate",
    (
        lambda data: data.__setitem__(slice(0, 2), b"\x00\x00"),
        lambda data: data.__setitem__(2, 0),
        lambda data: struct.pack_into(">HH", data, 8, 1024, 1024),
        lambda data: data.__delitem__(slice(520, None)),
    ),
)
def test_sgi_parser_fails_closed_on_invalid_or_oversized_layouts(mutate: object) -> None:
    payload = bytearray(build_minimal_sgi_rle_seed())
    mutate(payload)  # type: ignore[operator]
    with pytest.raises(ValueError):
        parse_sgi_rle_seed(bytes(payload))

    with pytest.raises(ValueError):
        parse_sgi_rle_seed(build_minimal_sgi_rle_seed(), maximum_seed_bytes=544)


def test_sgi_plugin_does_not_change_the_existing_dicom_corpus() -> None:
    seed = build_minimal_dicom_seed()
    before = generate_dicom_fuzz_cases(seed, campaign_seed="m16-dicom-control", max_cases=24)

    generate_sgi_relational_cases(build_minimal_sgi_rle_seed())
    after = generate_dicom_fuzz_cases(seed, campaign_seed="m16-dicom-control", max_cases=24)

    assert before == after


def test_sgi_seed_qualification_uses_exactly_two_deep_vm_routes(tmp_path: Path) -> None:
    seed_path = tmp_path / "qualified.sgi"
    seed_path.write_bytes(build_minimal_sgi_rle_seed())
    runner = SGIQualificationRunner()

    result = qualify_sgi_seed(
        runner=runner,
        environment=_environment(),
        seed_path=seed_path,
    )

    assert result.deep_seed is True
    assert result.model_calls == 0
    assert tuple(item.route for item in result.observations) == (
        ImageIOAPIRoute.FULL_DECODE,
        ImageIOAPIRoute.RAW_PIXEL_COPY,
    )
    assert len(runner.commands) == 2
    assert all(item.pixels_materialized for item in result.observations)
    assert all("sgi" in item.type_identifier for item in result.observations)


@pytest.mark.parametrize(
    ("type_identifier", "raw_pixels_copied"),
    (("public.png", True), ("com.sgi.sgi-image", False)),
)
def test_sgi_seed_qualification_rejects_wrong_type_or_shallow_raw_route(
    tmp_path: Path,
    type_identifier: str,
    raw_pixels_copied: bool,
) -> None:
    seed_path = tmp_path / "rejected.sgi"
    seed_path.write_bytes(build_minimal_sgi_rle_seed())

    with pytest.raises(RuntimeError, match="pixel materialization"):
        qualify_sgi_seed(
            runner=SGIQualificationRunner(
                type_identifier=type_identifier,
                raw_pixels_copied=raw_pixels_copied,
            ),
            environment=_environment(),
            seed_path=seed_path,
        )
