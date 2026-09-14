from fwmigrate.core.registry import PluginRegistry
from tests.fixture_paths import CISCO_ASA_FIXTURE


def test_cisco_asa_to_palo_alto_baseline():
    extraction = PluginRegistry.get_parser("cisco_asa").extract(
        CISCO_ASA_FIXTURE.read_text(encoding="utf-8")
    )
    ir = extraction.canonical_ir

    assert ir.metadata.source_vendor == "cisco_asa"
    assert ir.policies

    generator = PluginRegistry.get_generator("palo_alto")
    artifacts = generator.generate(ir, format="xml")

    assert len(artifacts) == 1
    assert artifacts[0].filename == "palo_alto_config.xml"
    assert artifacts[0].format == "xml"
    assert '<config version="11.1.0"' in artifacts[0].content
    assert "<devices>" in artifacts[0].content
