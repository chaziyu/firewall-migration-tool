from pathlib import Path

import pytest

from fwmigrate.application import MigrationPipeline, MigrationRequest
from fwmigrate.builtin_plugins import register_builtin_plugins
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir import IRConfig, IRMetadata, IRPolicy, IRZone
from fwmigrate.ir.enums import PolicyAction
from tests.fixture_paths import FORTIGATE_FIXTURE, VENDOR_FIXTURES


SOURCE_FIXTURES = {
    **VENDOR_FIXTURES,
    "cisco_ftd": Path("tests/fixtures/cisco_ftd/fdm_nat_pipeline_conformance.json"),
}
TARGET_FORMATS = {
    "palo_alto": "xml",
    "fortigate": "cli",
    "cisco_asa": "cli",
    "checkpoint": "cli",
    "juniper_srx": "cli",
}


@pytest.mark.parametrize("source_vendor", SOURCE_FIXTURES)
def test_registered_source_parsers_produce_accounted_output(source_vendor):
    register_builtin_plugins()
    extraction = PluginRegistry.get_parser(source_vendor).extract(
        SOURCE_FIXTURES[source_vendor].read_text(encoding="utf-8")
    )

    assert extraction.canonical_ir is not None
    assert extraction.source_sections
    assert all(section.status for section in extraction.source_sections)
    assert extraction.inventory_items or extraction.unsupported_items


@pytest.mark.parametrize("source_vendor", SOURCE_FIXTURES)
@pytest.mark.parametrize("target_vendor,target_format", TARGET_FORMATS.items())
def test_every_source_target_pair_succeeds_or_fails_closed(
    source_vendor, target_vendor, target_format
):
    result = MigrationPipeline().run(MigrationRequest(
        source_vendor=source_vendor,
        target_vendor=target_vendor,
        source_content=SOURCE_FIXTURES[source_vendor].read_text(encoding="utf-8"),
        target_format=target_format,
    ))

    if result.generation_allowed:
        assert result.artifacts and all(artifact.content for artifact in result.artifacts)
    else:
        assert result.artifacts == []
        assert result.blocking_reasons


def test_unsafe_extraction_cannot_reach_generation():
    result = MigrationPipeline().run(MigrationRequest(
        source_vendor="fortigate",
        target_vendor="palo_alto",
        source_content=FORTIGATE_FIXTURE.read_text(encoding="utf-8"),
        target_format="xml",
    ))

    assert result.generation_allowed is False
    assert result.artifacts == []
    assert result.final_ir is None
    assert result.blocking_reasons


@pytest.mark.parametrize("target_vendor,target_format", TARGET_FORMATS.items())
def test_target_generators_withhold_unsupported_semantics(target_vendor, target_format):
    register_builtin_plugins()
    ir = IRConfig(
        metadata=IRMetadata(hostname="safety-test"),
        zones=[IRZone(name="trust"), IRZone(name="untrust")],
        policies=[IRPolicy(
            name="UNSAFE_MARKER",
            from_zone=["trust"],
            to_zone=["untrust"],
            source=["any"],
            destination=["any"],
            service=["any"],
            action=PolicyAction.ALLOW,
            requires_manual_review=True,
            review_reasons=["unsupported semantics"],
        )],
    )

    output = "\n".join(
        artifact.content
        for artifact in PluginRegistry.get_generator(target_vendor).generate(
            ir, format=target_format
        )
    )
    marker_lines = [line for line in output.splitlines() if "UNSAFE_MARKER" in line]

    assert not marker_lines or all("withheld" in line.lower() for line in marker_lines)
