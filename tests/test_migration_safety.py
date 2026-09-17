import pytest

from fwmigrate.application import MigrationPipeline, MigrationRequest
from fwmigrate.builtin_plugins import register_builtin_plugins
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.extraction.models import ExtractionResult, ExtractionStatus, SourceInventoryItem
from fwmigrate.ir import IRConfig, IRMetadata, IRPolicy, IRZone
from fwmigrate.ir.enums import PolicyAction
from fwmigrate.parsers.palo_alto.policy_nat_coverage import PANOSSourceParser
from tests.fixture_paths import FORTIGATE_FIXTURE, VENDOR_FIXTURES


SOURCE_FIXTURES = VENDOR_FIXTURES
TARGET_FORMATS = {
    "palo_alto": "xml",
    "fortigate": "cli",
    "cisco_asa": "cli",
    "checkpoint": "cli",
    "juniper_srx": "cli",
}


def _panos_config(source: str = "a") -> str:
    return f"""<config><devices><entry name=\"localhost.localdomain\"><vsys><entry name=\"vsys1\"><address><entry name=\"a\"><ip-netmask>10.0.0.1</ip-netmask><tag><member>blue</member><future-tag-setting>on</future-tag-setting></tag></entry></address><rulebase><security><rules><entry name=\"r\"><from><member>any</member></from><to><member>any</member></to><source><member>{source}</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>"""


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


def test_panos_partial_extraction_converts_with_review_required():
    result = MigrationPipeline().run(MigrationRequest(
        source_vendor="palo_alto",
        target_vendor="palo_alto",
        source_content=_panos_config(),
        target_format="xml",
    ))

    assert result.extraction.generation_safe is True
    assert result.extraction.requires_manual_review is True
    assert result.extraction.blocking_reasons == []
    assert result.generation_allowed is True
    assert result.artifacts


def test_panos_partial_extraction_still_reaches_dependency_validation():
    result = MigrationPipeline().analyze(MigrationRequest(
        source_vendor="palo_alto",
        target_vendor="palo_alto",
        source_content=_panos_config(source="missing"),
        target_format="xml",
    ))

    assert result.extraction.generation_safe is True
    assert result.final_ir is not None
    assert result.generation_allowed is False
    assert any("unknown source address: missing" in reason for reason in result.blocking_reasons)


@pytest.mark.parametrize(
    "status",
    [ExtractionStatus.PARSE_ERROR, ExtractionStatus.UNSUPPORTED, ExtractionStatus.EXTRACT_ONLY],
)
def test_panos_hard_inventory_statuses_block_generation(status):
    extraction = ExtractionResult(
        canonical_ir=IRConfig(metadata=IRMetadata(hostname="panos-safety", source_vendor="palo_alto")),
        inventory_items=[SourceInventoryItem(
            domain="test",
            source_path="test/entry",
            status=status,
            requires_manual_review=True,
            notes=["unsafe source semantics"],
        )],
    )

    PANOSSourceParser._refresh_extraction_accounting(extraction)

    assert extraction.requires_manual_review is True
    assert extraction.generation_safe is False
    assert extraction.blocking_reasons == ["test/entry: unsafe source semantics"]


@pytest.mark.parametrize("target_vendor,target_format", TARGET_FORMATS.items())
def test_target_generators_withhold_unsupported_semantics(target_vendor, target_format):
    register_builtin_plugins()
    ir = IRConfig(
        metadata=IRMetadata(hostname="safety-test", source_vendor="test"),
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
