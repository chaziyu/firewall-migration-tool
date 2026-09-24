from fwmigrate.vendors.juniper_srx.export.excel import _value
from fwmigrate.vendors.juniper_srx.source_report import extract_juniper_source
from fwmigrate.vendors.juniper_srx.web_report import _project


def test_absent_and_present_source_keywords_remain_distinct():
    result = extract_juniper_source("""set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.2/24 primary preferred
set security zones security-zone plain
set security zones security-zone rst tcp-rst
set security policies from-zone trust to-zone untrust policy P1 then permit
set security policies from-zone trust to-zone untrust policy P2 match source-address-excluded
set security policies from-zone trust to-zone untrust policy P2 match destination-address-excluded
set security policies from-zone trust to-zone untrust policy P2 then log session-init
set security policies from-zone trust to-zone untrust policy P2 then log session-close
set security policies from-zone trust to-zone untrust policy P2 then count
set system ntp peer 192.0.2.10
set system ntp server 192.0.2.11 prefer
set system services ssh
set system services web-management http
""")
    config = result.config
    context = config.get_context()

    addresses = [address for interface in context.interfaces.values()
                 for unit in interface.units.values() for address in unit.addresses]
    assert (addresses[0].primary, addresses[0].preferred) == (None, None)
    assert (addresses[1].primary, addresses[1].preferred) == (True, True)
    assert context.zones["plain"].tcp_rst is None
    assert context.zones["rst"].tcp_rst is True

    policies = {policy.name: policy for policy in context.policies}
    assert (policies["P1"].source_address_excluded, policies["P1"].destination_address_excluded,
            policies["P1"].log_session_init, policies["P1"].log_session_close,
            policies["P1"].count) == (None, None, None, None, None)
    assert (policies["P2"].source_address_excluded, policies["P2"].destination_address_excluded,
            policies["P2"].log_session_init, policies["P2"].log_session_close,
            policies["P2"].count) == (True, True, True, True, True)

    assert [(server.role, server.preferred) for server in config.ntp.servers] == [
        ("peer", None), ("server", True)
    ]
    assert config.ssh.enabled is True
    assert config.netconf.enabled is None
    assert config.web_management.http_enabled is True
    assert config.web_management.https_enabled is None
    assert (_value(None), _value(True), _value(False)) == (None, "Yes", "No")
    assert _project({"unset": None, "configured": True}) == {"unset": None, "configured": True}


def test_bare_addresses_routes_and_disable_are_not_given_defaults():
    result = extract_juniper_source("""set security address-book global address bare
set security address-book global address dns dns-address host.example
set routing-options static route 10.0.0.0/24 discard
set routing-options static route 10.1.0.0/24 no-install
set routing-options static route 10.2.0.0/24 install
set interfaces ge-0/0/1 disable
set interfaces ge-0/0/2 description inactive
deactivate interfaces ge-0/0/2
set security nat source rule-set RS rule R then source-nat interface
""")
    context = result.config.get_context()
    addresses = context.address_books["global"].addresses
    assert addresses["bare"].type is None
    assert addresses["dns"].type == "dns-address"

    discard, no_install, install = context.routes
    assert (discard.action, discard.installation) == ("discard", None)
    assert (no_install.action, no_install.installation) == (None, "no-install")
    assert install.installation == "install"
    interfaces = context.interfaces
    assert interfaces["ge-0/0/1"].disabled is True
    assert interfaces["ge-0/0/2"].disabled is None
    assert any(item.operation == "deactivate" for item in result.config.activation_directives)
    rule = context.nat.source_rule_sets["RS"].rules[0]
    assert rule.nat_type == "source"
    assert "nat_family" not in type(rule).model_fields


def test_secret_presence_is_nullable_and_secret_value_stays_redacted():
    result = extract_juniper_source("""set security ike policy no-key mode main
set security ike policy with-key pre-shared-key ascii-text EXPLICIT-SECRET
""")
    policies = result.config.get_context().vpn.ike_policies
    assert policies["no-key"].has_pre_shared_key is None
    assert policies["with-key"].has_pre_shared_key is True
    assert "EXPLICIT-SECRET" not in str(result.config.model_dump(mode="python"))


def test_group_inheritance_keeps_count_out_of_explicit_source_policy():
    result = extract_juniper_source("""set groups G security policies from-zone trust to-zone untrust policy P then count
set apply-groups G
""")
    assert not result.config.get_context().policies
    assert any(item["origin"] == "inherited-group" and item["target_path"][-1] == "count"
               for item in result.derived.inheritance_view["effective_statements"])
