from copy import deepcopy
from io import BytesIO

from fwmigrate.vendors.juniper_srx.export.excel import export_juniper_excel
from fwmigrate.vendors.juniper_srx.source_report import extract_juniper_source
from fwmigrate.vendors.juniper_srx.validation import validate_juniper_config
from fwmigrate.vendors.juniper_srx.web_report import build_juniper_preview


def test_derived_validation_preview_and_excel_leave_source_and_derived_state_unchanged():
    result = extract_juniper_source("""set groups G interfaces ge-0/0/0 description inherited
set apply-groups G
set interfaces ge-0/0/0 ether-options 802.3ad ae0
set interfaces ge-0/0/0 description local
deactivate interfaces ge-0/0/0 description
set logical-systems LS1 interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
set routing-instances RI1 instance-type virtual-router
set access address-assignment pool P1 family inet range R1 low 10.0.0.10
set security nat source rule-set RS1 rule N1 then source-nat interface
set security ike proposal IKE1 encryption-algorithm aes-256-cbc
set security ike policy IKP1 proposals IKE1
set security ike gateway GW1 ike-policy MISSING
set security ipsec vpn VPN1 ike gateway GW1
set security remote-access profile RA1 ipsec-vpn VPN1
set security advance-policy-based-routing sla-rule SLA1 metrics-profile MISSING
""")
    source_before = deepcopy(result.config.model_dump(mode="python"))
    derived_before = deepcopy(result.derived)

    validate_juniper_config(result.config, result.derived)
    build_juniper_preview(result)
    output = BytesIO()
    export_juniper_excel(result, output)

    assert result.config.model_dump(mode="python") == source_before
    assert result.derived == derived_before
