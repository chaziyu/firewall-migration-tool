from fwmigrate.vendors.juniper_srx.source_report import extract_juniper_source


def test_deactivated_value_is_retained_in_source_but_marked_inactive():
    result = extract_juniper_source("""set interfaces ge-0/0/0 description WAN
deactivate interfaces ge-0/0/0 description
""")

    interface = result.config.get_context().interfaces["ge-0/0/0"]
    assert interface.description == "WAN"
    assert any(item.operation == "deactivate" and item.hierarchy_path == (
        "interfaces", "ge-0/0/0", "description"
    ) for item in result.config.activation_directives)
    assert not any(item.get("origin") == "local" and item.get("value") == "WAN"
                   and item.get("status") == "EFFECTIVE"
                   for item in result.derived.inheritance_view["effective_statements"])


def test_explicit_disable_is_not_treated_as_deactivation():
    result = extract_juniper_source("set interfaces ge-0/0/0 disable")

    interface = result.config.get_context().interfaces["ge-0/0/0"]
    assert interface.disabled is True
    assert result.config.activation_directives == []


def test_inactive_vpn_nat_apbr_and_remote_access_references_are_not_unresolved():
    result = extract_juniper_source("""set security ike proposal IKE encryption-algorithm aes-128-cbc
set security ike policy IK proposals IKE
deactivate security ike policy IK proposals IKE
set security nat source pool SP address 192.0.2.10/32
set security nat source rule-set RS rule R then source-nat pool SP
deactivate security nat source rule-set RS rule R then source-nat pool
set security advance-policy-based-routing metrics-profile MET delay-round-trip 10
set security advance-policy-based-routing sla-rule SLA metrics-profile MET
deactivate security advance-policy-based-routing sla-rule SLA metrics-profile
set access profile AP authentication-order password
set security remote-access profile RA access-profile AP
deactivate security remote-access profile RA access-profile
""")
    inactive = [item for item in result.derived.dependencies if item.result == "INACTIVE_SOURCE"]
    assert {(item.source_path, item.source_field, item.reference) for item in inactive} >= {
        ("security ike policy", "proposal", "IKE"),
        ("security nat source", "pool", "SP"),
        ("security advance-policy-based-routing", "metrics-profile", "MET"),
        ("security remote-access", "access-profile", "AP"),
    }
    assert all(item.result != "UNRESOLVED" for item in result.derived.dependencies
               if item.reference in {"IKE", "SP", "MET", "AP"})
    assert any(item.get("source_effective") is False for item in result.derived.vpn_graph)
    assert any(item.get("pool_source_effective") is False for item in result.derived.nat_usage)
    assert any(item.get("source_effective") is False for item in result.derived.apbr_graph)
    assert any(item.get("source_effective") is False for item in result.derived.secure_connect_graph)
    from io import BytesIO
    from openpyxl import load_workbook
    from fwmigrate.vendors.juniper_srx.export.excel import export_juniper_excel
    output = BytesIO()
    export_juniper_excel(result, output)
    workbook = load_workbook(BytesIO(output.getvalue()), read_only=True)
    vpn_rows = list(workbook["VPN Relationships"].values)
    assert next(row for row in vpn_rows[1:] if row[3] == "IKE_PROPOSAL")[8] == "INACTIVE_SOURCE"
    nat_rows = list(workbook["NAT Usage"].values)
    assert next(row for row in nat_rows[1:] if row[3] == "R")[9] == "INACTIVE_SOURCE"
    apbr_rows = list(workbook["APBR Relationships"].values)
    assert next(row for row in apbr_rows[1:] if row[2] == "SLA")[8] == "INACTIVE_SOURCE"
    access_rows = list(workbook["Secure Connect"].values)
    assert next(row for row in access_rows[1:] if row[2] == "RA")[8] == "INACTIVE_SOURCE"
