from __future__ import annotations

from fwmigrate.vendors.checkpoint.extraction import extract_checkpoint_config
from fwmigrate.vendors.checkpoint.loader import load_checkpoint_input
from fwmigrate.vendors.checkpoint.model.address import CPGroup, CPGroupWithExclusion, CPHost, CPNetwork
from fwmigrate.vendors.checkpoint.model.administration import CPAdministrator, CPPermissionProfile
from fwmigrate.vendors.checkpoint.model.gaia import CPGaiaRBARole, CPGaiaUser, CPVTI
from fwmigrate.vendors.checkpoint.model.gateway import CPCluster, CPGateway, CPInteroperableDevice
from fwmigrate.vendors.checkpoint.model.policy import CPAutoNATRule, CPNATRule, CPPolicyPackage
from fwmigrate.vendors.checkpoint.model.service import CPService, CPServiceGroup
from fwmigrate.vendors.checkpoint.model.schedule import CPTime, CPTimeGroup
from fwmigrate.vendors.checkpoint.model.threat import CPHTTPSInspectionRule, CPThreatProfile, CPThreatRule, CPThreatRuleException
from fwmigrate.vendors.checkpoint.model.vpn import CPVPNCommunity
from fwmigrate.vendors.checkpoint.model.zone import CPSecurityZone
from fwmigrate.vendors.checkpoint.models import CheckPointExportBundle


def _extract(command: str, objects: list[dict], data_key: str = "objects") -> object:
    return extract_checkpoint_config(CheckPointExportBundle.model_validate({
        "responses": [{"command": command, "data": {data_key: objects}}],
    })).config


def test_management_object_dispatch_keeps_typed_families_distinct():
    config = _extract("show-objects", [
        {"type": "host", "name": "h"}, {"type": "network", "name": "n"},
        {"type": "group", "name": "g"}, {"type": "group-with-exclusion", "name": "gx"},
        {"type": "security-zone", "name": "z"}, {"type": "service-tcp", "name": "s"},
        {"type": "service-group", "name": "sg"}, {"type": "time", "name": "t"},
        {"type": "time-group", "name": "tg"},
    ])

    assert type(config.hosts[0]) is CPHost
    assert type(config.networks[0]) is CPNetwork
    assert type(config.groups[0]) is CPGroup
    assert type(config.groups_with_exclusion[0]) is CPGroupWithExclusion
    assert type(config.security_zones[0]) is CPSecurityZone
    assert type(config.services[0]) is CPService
    assert type(config.service_groups[0]) is CPServiceGroup
    assert type(config.times[0]) is CPTime
    assert type(config.time_groups[0]) is CPTimeGroup
    assert not isinstance(config.security_zones[0], CPHost)


def test_management_and_gaia_families_do_not_cross_types():
    admin = _extract("show-administrators", [{"type": "administrator", "name": "admin"}]).administrators[0]
    profile = _extract("show-permission-profiles", [{"type": "permission-profile", "name": "profile"}]).permission_profiles[0]
    assert type(admin) is CPAdministrator
    assert type(profile) is CPPermissionProfile
    assert not isinstance(admin, CPGaiaUser)
    assert not isinstance(profile, CPGaiaRBARole)

    bundle, _ = load_checkpoint_input("set user admin shell /bin/bash\nset vti vti1 state on\n")
    config = extract_checkpoint_config(bundle).config
    assert type(config.gaia_users[0]) is CPGaiaUser
    assert type(config.vtis[0]) is CPVTI


def test_policy_gateway_threat_and_vpn_families_remain_distinct():
    nat = _extract("show-nat-rulebase", [{"type": "nat-rule", "name": "nat"}], "rulebase").nat_rules[0]
    auto_nat = _extract("show-nat-rulebase", [{"type": "automatic-nat-rule", "name": "auto", "automatic": True}], "rulebase").nat_rules[0]
    assert type(nat) is CPNATRule
    assert type(auto_nat) is CPAutoNATRule

    gateway = _extract("show-gateways-and-servers", [{"type": "gateway", "name": "gw"}]).gateways[0]
    cluster = _extract("show-clusters", [{"type": "cluster", "name": "cluster"}]).clusters[0]
    device = _extract("show-interoperable-devices", [{"type": "interoperable-device", "name": "device"}]).interoperable_devices[0]
    assert type(gateway) is CPGateway
    assert type(cluster) is CPCluster
    assert type(device) is CPInteroperableDevice

    profile = _extract("show-threat-profiles", [{"type": "threat-profile", "name": "profile"}]).threat_profiles[0]
    rule = _extract("show-threat-rulebase", [{"type": "threat-rule", "name": "rule"}], "rulebase").threat_rules[0]
    exception = _extract("show-threat-rulebase", [{"type": "exception", "name": "exception"}], "rulebase").threat_rule_exceptions[0]
    https = _extract("show-https-rulebase", [{"type": "https-rule", "name": "https"}], "rulebase").https_inspection_rules[0]
    assert type(profile) is CPThreatProfile
    assert type(rule) is CPThreatRule
    assert type(exception) is CPThreatRuleException
    assert type(https) is CPHTTPSInspectionRule

    community = _extract("show-vpn-communities", [{"type": "vpn-community", "name": "community"}]).vpn_communities[0]
    assert type(community) is CPVPNCommunity
    assert not isinstance(nat, (CPHost,))
