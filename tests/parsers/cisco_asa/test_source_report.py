from io import BytesIO

from openpyxl import load_workbook

from fwmigrate.parsers.cisco_asa import extract_cisco_asa_source
from fwmigrate.parsers.cisco_asa.export.excel import export_asa_excel
from fwmigrate.parsers.cisco_asa.web_report import build_asa_preview


def test_source_pipeline_preserves_acl_nat_order_and_uses_source_model():
    content = """hostname asa
interface GigabitEthernet0/1
 nameif outside
 ip address 203.0.113.1 255.255.255.0
object network WEB
 host 10.0.0.10
object-group network SERVERS
 network-object object WEB
access-list OUT extended permit tcp object-group SERVERS any eq 443
access-list OUT extended deny ip any any
access-group OUT in interface outside
nat (inside,outside) source static WEB interface
nat (inside,outside) after-auto 99 source dynamic WEB interface
"""

    result = extract_cisco_asa_source(content)

    assert result.config.hostname == "asa"
    assert [rule.source_order for rule in result.config.access_rules] == [9, 10]
    assert [rule.source_order for rule in result.config.nat_rules] == [12, 13]
    assert result.derived.object_group_memberships["__global__:SERVERS"] == ("WEB",)
    assert result.derived.interface_nameifs == {"GigabitEthernet0/1": "outside"}
    assert not hasattr(result, "canonical_ir")


def test_source_pipeline_resolves_context_scoped_references_without_mutating_config():
    content = """changeto context customer-a
object network WEB
 host 10.0.0.10
object-group network SERVERS
 network-object object WEB
access-list OUT extended permit ip object-group SERVERS any
changeto system
object network WEB
 host 192.0.2.10
"""

    result = extract_cisco_asa_source(content)

    assert [item.source_context for item in result.config.network_objects] == ["customer-a", None]
    assert result.config.network_groups[0].review_reasons == []
    assert all(issue.resolved for issue in result.derived.reference_issues)


def test_source_preview_and_excel_contain_no_ir_or_secret_text():
    result = extract_cisco_asa_source(
        "username admin password 0 super-secret\n"
        "object network WEB\n host 10.0.0.10\n"
    )

    preview = str(build_asa_preview(result))
    assert "super-secret" not in preview

    output = BytesIO()
    export_asa_excel(result, output)
    workbook = load_workbook(BytesIO(output.getvalue()), read_only=True)
    assert workbook.sheetnames == [
        "Summary", "Source Inventory", "Interfaces", "Network Objects",
        "Network Groups", "ACL Rules", "NAT Rules", "Routes", "VPN", "Validation",
    ]
    assert all("super-secret" not in str(row) for sheet in workbook for row in sheet.iter_rows(values_only=True))
