import ast
from copy import deepcopy
from pathlib import Path

from fwmigrate.vendors.juniper_srx.derived import build_juniper_derived_views
from fwmigrate.vendors.juniper_srx.parser import JuniperSRXParser
from fwmigrate.vendors.juniper_srx.validation import validate_juniper_config


VENDOR = Path(__file__).parents[2] / "src" / "fwmigrate" / "vendors" / "juniper_srx"


def test_juniper_source_parser_does_not_resolve_effective_state():
    tree = ast.parse((VENDOR / "parser.py").read_text(encoding="utf-8"))
    parser = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "JuniperSRXParser")
    extract = next(node for node in parser.body if isinstance(node, ast.FunctionDef) and node.name == "extract_source")
    calls = {node.func.id if isinstance(node.func, ast.Name) else node.func.attr
             for node in ast.walk(extract) if isinstance(node, ast.Call)}
    assert "resolve_group_commands" not in calls
    assert "_apply_activation_state_to_models" not in calls


def test_juniper_derived_inheritance_is_read_only_and_keeps_group_values_downstream():
    parser = JuniperSRXParser("""set groups base interfaces ge-0/0/0 description inherited
set apply-groups base
""")
    config = parser.extract_source()
    before = deepcopy(config.model_dump(mode="python"))
    commands_before = deepcopy(parser.commands)
    derived = build_juniper_derived_views(config, source_commands=parser.commands)
    assert config.model_dump(mode="python") == before
    assert not config.get_context().interfaces
    assert derived.inheritance["effective_commands"][0]["path"] == (
        "interfaces", "ge-0/0/0", "description", "inherited"
    )
    assert parser.commands == commands_before


def test_major_juniper_transforms_and_validation_leave_source_and_commands_unchanged():
    parser = JuniperSRXParser("""set groups G interfaces ge-0/0/0 description inherited
set apply-groups G
set interfaces ge-0/0/0 ether-options 802.3ad ae0
set interfaces ae0 unit 0 family inet address 192.0.2.1/24
set security zones security-zone vpn interfaces st0.1
set routing-instances VR instance-type virtual-router
set access address-assignment pool P family inet range R low 10.0.0.10
set system services dhcp-local-server group D family inet interface ge-0/0/0.0
set security nat source rule-set RS rule N then source-nat interface
set security ike proposal IKE encryption-algorithm aes-256-cbc
set security ike policy IKP proposals IKE
set security ike gateway GW ike-policy IKP
set security ipsec vpn VPN ike gateway GW
set security ipsec vpn VPN bind-interface st0.1
set security remote-access profile RA ipsec-vpn VPN
set security advance-policy-based-routing metrics-profile MET jitter 20
set security advance-policy-based-routing sla-rule SLA metrics-profile MET
""")
    config = parser.extract_source()
    source_before = deepcopy(config.model_dump(mode="python"))
    commands_before = deepcopy(parser.commands)
    derived = build_juniper_derived_views(config, source_commands=parser.commands)
    validate_juniper_config(config, derived)
    assert config.model_dump(mode="python") == source_before
    assert parser.commands == commands_before
