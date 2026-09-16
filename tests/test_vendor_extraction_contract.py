from pathlib import Path

import pytest

from fwmigrate.parsers.checkpoint import CheckPointSourceParser
from fwmigrate.parsers.cisco_asa import CiscoASASourceParser
from fwmigrate.parsers.cisco_ftd import CiscoFTDSourceParser
from fwmigrate.parsers.palo_alto import PANOSSourceParser


ROOT = Path(__file__).parent


def _stable_dump(result):
    data = result.model_dump()
    data["canonical_ir"]["metadata"]["migration_timestamp"] = None
    return data


@pytest.mark.parametrize(
    ("parser_type", "fixture", "expected"),
    [
        (PANOSSourceParser, "fixtures/example_palo_alto.xml", (11, 15, 0, 4, 1, 1)),
        (
            PANOSSourceParser,
            "fixtures/palo_alto/integrated_panorama.xml",
            (30, 24, 0, 4, 6, 2),
        ),
        (
            CheckPointSourceParser,
            "fixtures/checkpoint/minimal_bundle.json",
            (7, 8, 0, 3, 2, 1),
        ),
        (
            CheckPointSourceParser,
            "fixtures/checkpoint/single_gateway_full.json",
            (11, 19, 2, 1, 0, 0),
        ),
        (
            CiscoASASourceParser,
            "fixtures/cisco_asa/nat_pipeline_conformance.txt",
            (16, 26, 0, 9, 0, 7),
        ),
        (
            CiscoFTDSourceParser,
            "fixtures/cisco_ftd/fmc_nat_pipeline_conformance.json",
            (3, 7, 0, 2, 0, 2),
        ),
        (
            CiscoFTDSourceParser,
            "fixtures/cisco_ftd/fdm_nat_pipeline_conformance.json",
            (2, 8, 0, 3, 0, 2),
        ),
    ],
)
def test_vendor_extraction_contract_is_stable(parser_type, fixture, expected):
    content = (ROOT / fixture).read_text(encoding="utf-8")
    parser = parser_type()
    extraction = parser.extract(content)
    repeated = parser.extract(content)

    parsed = parser.parse(content)
    expected_ir = extraction.canonical_ir.model_dump()
    actual_ir = parsed.model_dump()
    expected_ir["metadata"]["migration_timestamp"] = None
    actual_ir["metadata"]["migration_timestamp"] = None
    assert actual_ir == expected_ir
    assert (
        len(extraction.source_sections),
        len(extraction.inventory_items),
        len(extraction.unsupported_items),
        len(extraction.canonical_ir.addresses),
        len(extraction.canonical_ir.policies),
        len(extraction.canonical_ir.nat_rules),
    ) == expected
    assert _stable_dump(extraction) == _stable_dump(repeated)


def test_ftd_text_honors_zone_mapping():
    content = "interface outside\n ip address 203.0.113.1 255.255.255.0\n"
    result = CiscoFTDSourceParser().extract(content, zone_mapping={"outside": "WAN"})

    assert result.canonical_ir.interfaces[0].zone == "WAN"
    assert result.generation_safe is False


@pytest.mark.parametrize(
    "fixture,authoritative_zone",
    [
        ("fixtures/cisco_ftd/fmc_nat_pipeline_conformance.json", "inside"),
        ("fixtures/cisco_ftd/fdm_nat_pipeline_conformance.json", None),
    ],
)
def test_ftd_structured_inputs_do_not_apply_text_zone_mapping(fixture, authoritative_zone):
    content = (ROOT / fixture).read_text(encoding="utf-8")
    result = CiscoFTDSourceParser().extract(
        content,
        zone_mapping={"inside": "caller-supplied-zone"},
    )
    if authoritative_zone:
        assert any(zone.name == authoritative_zone for zone in result.canonical_ir.zones)
    assert all(zone.name != "caller-supplied-zone" for zone in result.canonical_ir.zones)


def test_vendor_parser_imports_do_not_replace_base_parser_classes():
    import importlib

    pan_parser = importlib.import_module("fwmigrate.parsers.palo_alto.parser")
    pan_pipeline = importlib.import_module("fwmigrate.parsers.palo_alto.pipeline")
    pan_transformer = importlib.import_module("fwmigrate.parsers.palo_alto.transformer")
    pan_routing = importlib.import_module("fwmigrate.parsers.palo_alto.routing")
    pan_pbf = importlib.import_module("fwmigrate.parsers.palo_alto.pbf")
    pan_package = importlib.import_module("fwmigrate.parsers.palo_alto")
    asa_parser = importlib.import_module("fwmigrate.parsers.cisco_asa.parser")
    asa_transformer = importlib.import_module("fwmigrate.parsers.cisco_asa.transformer")

    assert pan_parser.__dict__.get("PANOSSourceParser") is None
    assert pan_package.PANOSSourceParser.__module__.endswith(".extractor")
    assert pan_pipeline.PANOSExtractionPipeline.__bases__ == (
        pan_transformer.PANToIRTransformer,
    )
    assert pan_transformer.PANToIRTransformer.transform.__module__.endswith(
        ".transformer"
    )
    assert pan_routing.PANRouteExtractor.__module__.endswith(".routing")
    assert pan_pbf.PANPBFRuleExtractor.__module__.endswith(".pbf")
    assert asa_parser.CiscoASAParser.__dict__["parse_raw"].__module__ == asa_parser.__name__
    assert asa_parser.CiscoASAParser.__dict__["transform_to_ir"].__module__ == asa_parser.__name__
    assert asa_transformer.ASAtoIRTransformer.transform.__module__.endswith(".transformer")


def test_pan_source_loader_keeps_normalized_input_outside_canonical_ir():
    from fwmigrate.parsers.palo_alto.parser import load_pan_source

    source = load_pan_source(
        "<config version='11.2'><deviceconfig><system><hostname>pan-a</hostname>"
        "</system></deviceconfig></config>"
    )

    assert source.root.tag == "config"
    assert source.hostname == "pan-a"
    assert source.source_version == "11.2"
    assert source.raw_content.startswith("<config")
