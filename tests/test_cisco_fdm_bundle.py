import json

from fwmigrate.ir.enums import NATTranslationMode, NATType
from fwmigrate.parsers.cisco_ftd import CiscoFDMBundleParser, CiscoFTDSourceParser
from fwmigrate.parsers.cisco_ftd.extractor import extract_cisco_ftd_config


def _bundle(unresolved=False):
    return {
        "format": "cisco-fdm-rest-export-v1",
        "source": "fdm-rest-api",
        "domain": {"id": "device-1", "name": "DefaultDevice"},
        "objects": {
            "hosts": [
                {"id": "inside-host", "name": "InsideHost", "value": "10.0.0.10"},
                {"id": "public-host", "name": "PublicHost", "value": "203.0.113.10"},
            ],
            "networks": [{"id": "inside-net", "name": "InsideNet", "value": "10.0.0.0/24"}],
            "ranges": [{"id": "public-range", "name": "PublicRange", "start": "203.0.113.20", "end": "203.0.113.30"}],
            "network_groups": [
                {"id": "nested", "name": "Nested", "members": [{"id": "inside-host"}]},
                {"id": "all-inside", "name": "AllInside", "members": [{"id": "inside-net"}, {"id": "nested"}]},
            ],
            "services": [{"id": "http", "name": "HTTP", "protocol": "tcp", "ports": [{"start": 80}]}],
            "service_groups": [{"id": "web", "name": "WebServices", "members": [{"id": "http"}]}],
            "interfaces": [
                {"id": "if-inside", "name": "inside", "zone": {"id": "zone-inside"}},
                {"id": "if-outside", "name": "outside", "zone": {"id": "zone-outside"}},
            ],
            "zones": [
                {"id": "zone-inside", "name": "inside"},
                {"id": "zone-outside", "name": "outside"},
            ],
        },
        "nat_rules": [
            {
                "id": "nat-static", "name": "Static", "type": "SOURCE", "sequence": 1,
                "sourceInterface": {"id": "if-inside"}, "destinationInterface": {"id": "if-outside"},
                "originalSource": {"id": "inside-host"}, "translatedSource": {"id": "public-host"},
                "sourceTranslationMode": "static", "service": {"id": "web"},
            },
            {
                "id": "nat-pat", "name": "PAT", "type": "SOURCE", "sequence": 2,
                "originalSource": {"id": "inside-net"}, "translatedSource": {"id": "public-range"},
                "sourceTranslationMode": "dynamic-ip-and-port", "patMethod": "pat",
                "originalSourcePort": {"start": 1000, "end": 2000}, "translatedSourcePort": {"start": 3000},
            },
            {
                "id": "nat-twice", "name": "Twice", "type": "TWICE", "sequence": 3,
                "originalSource": {"id": "inside-host"}, "translatedSource": {"id": "public-host"},
                "originalDestination": {"id": "public-host"}, "translatedDestination": {"id": "inside-host"},
                "sourceTranslationMode": "static", "destinationTranslationMode": "static",
            },
            {
                "id": "nat-identity", "name": "Identity", "type": "SOURCE", "sequence": 4,
                "originalSource": {"id": "inside-net"}, "translatedSource": {"id": "inside-net"},
                "sourceTranslationMode": "static", "identity": True,
            },
        ] if not unresolved else [{
            "id": "nat-unresolved", "name": "Unresolved", "type": "SOURCE", "sequence": 1,
            "originalSource": {"id": "missing"}, "translatedSource": {"id": "public-host"},
            "sourceTranslationMode": "static",
        }],
    }


def test_fdm_bundle_uses_separate_contract_and_preserves_canonical_nat():
    text = json.dumps(_bundle())
    ir = CiscoFDMBundleParser(text).parse()

    assert ir.metadata.input_type == "fdm-rest-export"
    assert {item.name for item in ir.addresses} >= {"InsideHost", "InsideNet", "PublicRange"}
    assert next(item for item in ir.address_groups if item.name == "AllInside").members == ["InsideNet", "Nested"]
    assert ir.service_groups[0].members == ["HTTP"]
    assert [rule.sequence for rule in ir.nat_rules] == [1, 2, 3, 4]

    pat = next(rule for rule in ir.nat_rules if rule.name == "PAT")
    assert pat.source_translation_mode == NATTranslationMode.DYNAMIC_IP_AND_PORT
    assert [(port.start, port.end) for port in pat.original_source_ports] == [(1000, 2000)]
    assert [(port.start, port.end) for port in pat.translated_source_ports] == [(3000, 3000)]

    twice = next(rule for rule in ir.nat_rules if rule.name == "Twice")
    assert twice.type == NATType.TWICE
    assert twice.destination == ["PublicHost"]
    assert twice.translated_destinations == ["InsideHost"]
    assert twice.destination_translation_mode == NATTranslationMode.STATIC

    identity = next(rule for rule in ir.nat_rules if rule.name == "Identity")
    assert identity.identity is True
    assert identity.source == identity.translated_sources == ["InsideNet"]


def test_fdm_public_entry_points_route_only_explicit_fdm_bundles():
    text = json.dumps(_bundle())
    result = extract_cisco_ftd_config(text)
    parsed = CiscoFTDSourceParser().parse(text)

    assert result.input_source_type == "fdm-rest-bundle"
    assert result.nat_extraction_supported is True
    assert result.canonical_ir.metadata.input_type == "fdm-rest-export"
    assert len(parsed.nat_rules) == 4
    assert not result.unsupported_items


def test_fdm_unresolved_reference_is_not_broadened():
    result = extract_cisco_ftd_config(json.dumps(_bundle(unresolved=True)))
    rule = result.canonical_ir.nat_rules[0]

    assert rule.source == []
    assert rule.source != ["any"]
    assert result.generation_safe is False
    assert result.unsupported_items
    assert "Unresolved FDM object/policy reference" in result.blocking_reasons
