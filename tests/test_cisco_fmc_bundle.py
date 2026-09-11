import json

from fwmigrate.ir.enums import NATTranslationMode, NATType, PolicyAction
from fwmigrate.parsers.cisco_ftd import CiscoFMCBundleParser, CiscoFTDSourceParser
from fwmigrate.parsers.cisco_ftd.extractor import extract_cisco_ftd_config


def _bundle():
    return {
        "format": "cisco-fmc-rest-export-v1",
        "source": "fmc-rest-api",
        "domain": {"id": "domain-1", "name": "Global"},
        "objects": {
            "hosts": [
                {"id": "host-inside", "name": "InsideHost", "type": "Host", "value": "10.0.0.10"},
                {"id": "host-public", "name": "PublicHost", "type": "Host", "value": "203.0.113.10"},
            ],
            "networks": [
                {"id": "net-dmz", "name": "DMZNet", "type": "Network", "value": "10.0.20.0/24"},
            ],
            "ranges": [],
            "networkgroups": [
                {
                    "id": "grp-trusted", "name": "TrustedNets", "type": "NetworkGroup",
                    "objects": [{"id": "host-inside", "name": "InsideHost", "type": "Host"}],
                    "literals": [{"type": "Network", "value": "10.0.1.0/24"}],
                }
            ],
            "protocolportobjects": [
                {"id": "svc-https", "name": "HTTPS", "type": "ProtocolPortObject", "protocol": "6", "port": "443"},
            ],
            "portobjectgroups": [
                {
                    "id": "svc-web", "name": "WEB", "type": "PortObjectGroup",
                    "objects": [{"id": "svc-https", "name": "HTTPS", "type": "ProtocolPortObject"}],
                }
            ],
            "securityzones": [
                {"id": "zone-inside", "name": "inside", "type": "SecurityZone"},
                {"id": "zone-outside", "name": "outside", "type": "SecurityZone"},
            ],
            "applications": [
                {"id": "app-https", "name": "HTTPS App", "type": "Application"},
            ],
            "users": [
                {"id": "user-alice", "name": "alice", "type": "User"},
            ],
        },
        "access_policies": [
            {
                "id": "acp-1", "name": "Corp ACP",
                "rules": [
                    {
                        "id": "rule-1", "name": "Allow HTTPS", "type": "AccessRule",
                        "metadata": {"ruleIndex": 1}, "enabled": True, "action": "ALLOW",
                        "sourceZones": {"objects": [{"id": "zone-inside", "name": "inside", "type": "SecurityZone"}]},
                        "destinationZones": {"objects": [{"id": "zone-outside", "name": "outside", "type": "SecurityZone"}]},
                        "sourceNetworks": {"objects": [{"id": "grp-trusted", "name": "TrustedNets", "type": "NetworkGroup"}]},
                        "destinationNetworks": {"objects": [{"id": "net-dmz", "name": "DMZNet", "type": "Network"}]},
                        "destinationPorts": {"objects": [{"id": "svc-web", "name": "WEB", "type": "PortObjectGroup"}]},
                        "applications": {"objects": [{"id": "app-https", "name": "HTTPS App", "type": "Application"}]},
                        "users": {"objects": [{"id": "user-alice", "name": "alice", "type": "User"}]},
                        "logBegin": False, "logEnd": True,
                    }
                ],
                "defaultAction": {"id": "default-1", "action": "BLOCK", "logEnd": True},
            }
        ],
        "nat_policies": [
            {
                "id": "nat-policy-1", "name": "FTD NAT",
                "manual_rules_before_auto": [
                    {
                        "id": "manual-1", "name": "Dynamic pool", "type": "FTDManualNatRule",
                        "natType": "DYNAMIC", "enabled": True,
                        "sourceInterface": {"id": "zone-inside", "name": "inside", "type": "SecurityZone"},
                        "destinationInterface": {"id": "zone-outside", "name": "outside", "type": "SecurityZone"},
                        "originalSource": {"id": "grp-trusted", "name": "TrustedNets", "type": "NetworkGroup"},
                        "translatedSource": {"id": "host-public", "name": "PublicHost", "type": "Host"},
                    }
                ],
                "auto_rules": [
                    {
                        "id": "auto-1", "name": "Interface PAT", "type": "FTDAutoNatRule",
                        "natType": "DYNAMIC", "enabled": True,
                        "sourceInterface": {"id": "zone-inside", "name": "inside", "type": "SecurityZone"},
                        "destinationInterface": {"id": "zone-outside", "name": "outside", "type": "SecurityZone"},
                        "originalNetwork": {"id": "host-inside", "name": "InsideHost", "type": "Host"},
                        "interfaceInTranslatedNetwork": True,
                    }
                ],
                "manual_rules_after_auto": [],
            }
        ],
    }


def test_fmc_bundle_normalizes_objects_access_policy_and_nat():
    text = json.dumps(_bundle())
    ir = CiscoFMCBundleParser(text).parse()

    assert ir.metadata.source_vendor == "cisco_ftd"
    assert ir.metadata.source_product == "Cisco Secure Firewall Management Center / FTD"
    assert "source_attributes" not in ir.metadata.model_dump()
    assert {item.name for item in ir.addresses} >= {"InsideHost", "PublicHost", "DMZNet"}
    assert next(group for group in ir.address_groups if group.name == "TrustedNets").members[0] == "InsideHost"
    assert next(group for group in ir.service_groups if group.name == "WEB").members == ["HTTPS"]
    assert {zone.name for zone in ir.zones} == {"inside", "outside"}

    rule = next(policy for policy in ir.policies if policy.name == "Corp ACP__Allow HTTPS")
    assert rule.action == PolicyAction.ALLOW
    assert rule.from_zone == ["inside"]
    assert rule.to_zone == ["outside"]
    assert rule.source == ["TrustedNets"]
    assert rule.destination == ["DMZNet"]
    assert rule.service == ["WEB"]
    assert rule.applications == ["HTTPS App"]
    assert rule.source_users == ["alice"]
    assert rule.log_end is True
    assert rule.requires_manual_review is True
    assert rule.identity_dependency_review is True
    assert any("identity-provider" in reason for reason in rule.review_reasons)

    default = next(policy for policy in ir.policies if policy.name == "Corp ACP__default")
    assert default.action == PolicyAction.DENY

    dynamic = next(rule for rule in ir.nat_rules if rule.name.endswith("Dynamic pool"))
    assert dynamic.type == NATType.SOURCE
    assert dynamic.source_translation_mode == NATTranslationMode.DYNAMIC_IP
    assert dynamic.source == ["TrustedNets"]
    assert dynamic.translated_sources == ["PublicHost"]
    assert dynamic.requires_manual_review is True
    assert any("target-generator" in reason for reason in dynamic.review_reasons)

    interface_pat = next(rule for rule in ir.nat_rules if rule.name.endswith("Interface PAT"))
    assert interface_pat.source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS
    assert ir.generation_safe is False


def test_ftd_source_plugin_and_extraction_accept_fmc_json_bundle():
    text = json.dumps(_bundle())
    ir = CiscoFTDSourceParser().parse(text)
    result = extract_cisco_ftd_config(text)

    assert len(ir.policies) == 2
    assert len(ir.nat_rules) == 2
    assert result.canonical_ir.policies[0].name == "Corp ACP__Allow HTTPS"
    assert {section.path for section in result.source_sections} == {
        "fmc/objects", "fmc/access-policies", "fmc/nat-policies",
    }
    assert not result.unsupported_items
    assert result.requires_manual_review is True
    assert result.migration_complete is False
    assert result.generation_safe is False
    assert result.canonical_ir.generation_safe is False
    assert "FMC policy/NAT semantics require manual target validation" in result.blocking_reasons


def test_unresolved_fmc_reference_blocks_generation_without_broadening():
    bundle = _bundle()
    bundle["access_policies"][0]["rules"][0]["destinationNetworks"] = {
        "objects": [{"id": "missing-object", "name": "MissingObject", "type": "Network"}]
    }
    text = json.dumps(bundle)
    result = extract_cisco_ftd_config(text)
    policy = next(item for item in result.canonical_ir.policies if item.name == "Corp ACP__Allow HTTPS")

    assert policy.destination == ["MissingObject"]
    assert policy.destination != ["any"]
    assert policy.requires_manual_review is True
    assert result.generation_safe is False
    assert result.unsupported_items
    assert result.canonical_ir.generation_safe is False
    assert "Unresolved FMC object/policy reference" in result.canonical_ir.generation_blocking_reasons
    assert "Unresolved FMC object/policy reference" in result.blocking_reasons
    assert any("missing-object" in (item.raw_capture or "") for item in result.unsupported_items)


def test_fmc_preserves_source_ports_zones_interface_groups_and_pbr():
    bundle = _bundle()
    bundle["objects"]["interfaces"] = [{"id": "if-1", "name": "Gig0/1", "type": "PhysicalInterface"}]
    bundle["objects"]["interfacegroups"] = [{
        "id": "ig-1", "name": "Transit", "interfaces": [{"id": "if-1", "name": "Gig0/1"}],
    }]
    bundle["objects"]["securityzones"][0]["interfaces"] = [{"id": "if-1", "name": "Gig0/1"}]
    bundle["access_policies"][0]["rules"][0]["sourcePorts"] = {
        "objects": [{"id": "svc-https", "name": "HTTPS", "type": "ProtocolPortObject"}]
    }
    bundle["pbr_policies"] = [{"name": "PBR", "rules": [{
        "sequence": 5, "matchAcl": "PBR_ACL", "nextHop": "192.0.2.1", "outputInterface": "Gig0/1",
    }]}]
    ir = CiscoFMCBundleParser(json.dumps(bundle)).parse()
    policy = next(item for item in ir.policies if item.name.endswith("Allow HTTPS"))
    assert policy.source_ports == ["HTTPS"]
    assert ir.zones[0].interfaces == ["Gig0/1"]
    assert ir.interface_groups[0].members == ["Gig0/1"]
    assert ir.policy_route_rules[0].source_order == 5
