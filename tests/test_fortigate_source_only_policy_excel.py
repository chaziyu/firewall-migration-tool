import io

from openpyxl import load_workbook

from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.report import IRExcelExporter


def test_source_only_policy_families_export_from_canonical_ir():
    result = extract_fortigate_config(
        """config router policy
    edit 10
        set src "10.0.0.0/24"
    next
end
config router policy6
    edit 20
        set src "2001:db8::/64"
    next
end
config firewall local-in-policy
    edit 30
        set intf "wan1" "wan2"
        set srcaddr "ADMIN-NET"
        set dstaddr "FGT-IP"
        set service "HTTPS"
        set action accept
    next
end
config firewall local-in-policy6
    edit 40
        set intf "wan6"
        set srcaddr "ADMIN6-NET"
        set dstaddr "FGT6-IP"
        set service "HTTPS"
    next
end
config system settings
    set ngfw-mode policy-based
end
config firewall security-policy
    edit 50
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "SRC"
        set srcaddr6 "SRC6"
        set dstaddr "DST"
        set dstaddr6 "DST6"
        set service "HTTPS"
        set application "Web.Client"
        set av-profile "default"
        set ssl-ssh-profile "certificate-inspection"
        set logtraffic all
        set action deny
        set comments "NGFW review"
    next
end
"""
    )
    ir = result.canonical_ir
    workbook = load_workbook(io.BytesIO(IRExcelExporter(ir, result).generate()))

    assert workbook.sheetnames.index("Policies") < workbook.sheetnames.index("Local-In Policies")
    assert workbook.sheetnames.index("Routes") < workbook.sheetnames.index("Policy Routes")
    assert [cell.value for cell in workbook["Policy Routes"][3]][:4] == [
        "Source VDOM", "Rule ID", "Address Family", "Source Order",
    ]
    pbr = workbook["Policy Routes"]
    pbr_headers = {cell.value: cell.column for cell in pbr[3]}
    assert [pbr.cell(row, pbr_headers["Rule ID"]).value for row in range(4, 6)] == ["10", "20"]
    assert pbr.cell(4, pbr_headers["Protocol"]).value is None
    assert pbr.cell(4, pbr_headers["Effective Protocol"]).value == 0
    assert pbr.cell(5, pbr_headers["Effective Source Port Start"]).value == 1

    local = workbook["Local-In Policies"]
    local_headers = {cell.value: cell.column for cell in local[3]}
    assert [local.cell(row, local_headers["Rule ID"]).value for row in range(4, 6)] == ["30", "40"]
    assert local.cell(4, local_headers["Interface"]).value == "wan1\nwan2"
    assert local.cell(5, local_headers["Address Family"]).value == "ipv6"

    ngfw = workbook["NGFW Security Policies"]
    ngfw_headers = {cell.value: cell.column for cell in ngfw[3]}
    assert ngfw.cell(4, ngfw_headers["Rule ID"]).value == "50"
    assert ngfw.cell(4, ngfw_headers["Applications"]).value == "Web.Client"
    assert ngfw.cell(4, ngfw_headers["SSL Inspection Reference"]).value == "certificate-inspection"
    assert ngfw.cell(4, ngfw_headers["Logging"]).value == "all"
    assert ngfw.cell(4, ngfw_headers["Action"]).value == "deny"
    assert ngfw.cell(4, ngfw_headers["Manual Review"]).value == "Yes"

    assert pbr.max_row == 5
    assert local.max_row == 5
    assert ngfw.max_row == 4
    assert workbook["Routes"].max_row == 3
    assert workbook["Policies"].max_row == 3
