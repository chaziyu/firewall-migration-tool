from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser

from types import SimpleNamespace

from fwmigrate.vendors.cisco_asa.model import CiscoIPsecProfile, CiscoNATRule

from fwmigrate.vendors.cisco_asa.model.acl import CiscoACLEndpoint, CiscoAccessRule

from fwmigrate.vendors.cisco_asa.model.service import CiscoPortSpec

from fwmigrate.vendors.cisco_asa.relationships.acl import build_acl_relationships

from fwmigrate.vendors.cisco_asa.relationships.identity import build_identity_relationships

from fwmigrate.vendors.cisco_asa.relationships.mpf import build_mpf_relationships

from fwmigrate.vendors.cisco_asa.relationships.nat import build_nat_relationships

from fwmigrate.vendors.cisco_asa.relationships.references import ASAReferenceIndex, ASAReferenceKind

from fwmigrate.vendors.cisco_asa.relationships.routing import build_routing_relationships

from fwmigrate.vendors.cisco_asa.relationships.vpn import build_vpn_relationships

def test_command_privileges_and_local_fallback_are_source_records():
    config = CiscoASAParser("""aaa authorization command AUTH LOCAL
username operator privilege 7 nopassword
privilege cmd level 7 mode exec command show version
privilege show level 5 command running-config
""").parse_raw()
    assert config.aaa_authorization_rules[0].fallback_local is True
    assert config.local_users[0].privilege == 7
    assert "privilege" in config.local_users[0].explicit_fields
    assert [(p.command_form, p.privilege_level, p.cli_mode) for p in config.command_privileges] == [("cmd", 7, "exec"), ("show", 5, None)]

def test_unmatched_identity_selector_is_source_selector_not_missing_local_user():
    rule = SimpleNamespace(name="auth", source_context="ctx", group_name=None, server_group=None,
                           interface=None, acl_reference=None, user_identity="remote-user")
    config = SimpleNamespace(aaa_server_hosts=[], aaa_authentication_rules=[rule],
                             aaa_authorization_rules=[], aaa_accounting_rules=[])

    relation = build_identity_relationships(config, ASAReferenceIndex()).relationships[0]

    assert relation.local_user is None and relation.user_group is None
    assert relation.selector_status == "SOURCE_SELECTOR"
    assert not build_identity_relationships(config, ASAReferenceIndex()).issues
