from copy import deepcopy

from fwmigrate.vendors.juniper_srx.parser import JuniperSRXParser
from fwmigrate.vendors.juniper_srx.export.excel import export_juniper_excel
from fwmigrate.vendors.juniper_srx.source_report import extract_juniper_source
from fwmigrate.vendors.juniper_srx.web_report import build_juniper_preview
from fwmigrate.vendors.juniper_srx.transforms.inheritance import build_inheritance_view


def _view(source):
    parser = JuniperSRXParser(source)
    parser.extract_source()
    commands_before = deepcopy(parser.commands)
    result = build_inheritance_view(parser.commands)
    assert parser.commands == commands_before
    return result


def test_local_override_and_group_order_keep_candidates_and_provenance():
    view = _view("""set groups first interfaces ge-0/0/0 description first
set groups second interfaces ge-0/0/0 description second
set apply-groups [ first second ]
set interfaces ge-0/0/0 description local
""")
    inherited = [item for item in view["effective_statements"] if item["origin"] == "inherited-group"]
    assert [item["source_group"] for item in inherited] == ["second", "first"]
    assert all(item["status"] == "SHADOWED" for item in inherited)
    assert all(item["group_chain"] and item["source_path"] for item in inherited)
    assert any(item["origin"] == "local" and item["status"] == "EFFECTIVE" and
               item["value"] == "local" for item in view["effective_statements"])


def test_nested_groups_and_apply_groups_except_retain_excluded_candidates():
    view = _view("""set groups inner system host-name inherited
set groups outer apply-groups inner
set groups excluded system host-name excluded
set apply-groups outer
set apply-groups-except excluded
""")
    assert any(item["source_group"] == "inner" for item in view["effective_statements"])
    assert any(item.get("status") == "EXCLUDED" for item in view["candidates"])


def test_inactive_group_statement_and_inactive_application_are_preserved():
    view = _view("""set groups G system host-name host
deactivate groups G system host-name
set apply-groups G
deactivate apply-groups G
""")
    assert any(item["status"] == "INACTIVE" for item in view["candidates"])
    assert "GROUP_INACTIVE" in {item["status"] for item in view["issues"]}


def test_missing_and_cyclic_groups_are_reported_without_synthetic_targets():
    missing = _view("set apply-groups absent")
    cycle = _view("""set groups A apply-groups B
set groups B apply-groups A
set apply-groups A
""")
    assert "GROUP_NOT_FOUND" in {item["status"] for item in missing["issues"]}
    assert "GROUP_CYCLE" in {item["status"] for item in cycle["issues"]}


def test_wildcard_group_renders_only_to_existing_interfaces():
    view = _view("""set groups G interfaces <*> description inherited
set interfaces ge-0/0/0 unit 0
set apply-groups G
""")
    inherited = [item for item in view["effective_statements"] if item["origin"] == "inherited-group"]
    assert [item["target_path"] for item in inherited] == [
        ("interfaces", "ge-0/0/0", "description", "inherited")
    ]


def test_same_group_name_isolated_between_logical_systems():
    view = _view("""set groups G system host-name root
set apply-groups G
set logical-systems L1 groups G system host-name one
set logical-systems L1 apply-groups G
set logical-systems L2 groups G system host-name two
set logical-systems L2 apply-groups G
""")
    inherited = [item for item in view["effective_statements"] if item["origin"] == "inherited-group"]
    assert {item["context"] for item in inherited} == {"root", "logical-system L1", "logical-system L2"}
    assert {item["value"] for item in inherited} == {"root", "one", "two"}


def test_group_list_precedence_and_hierarchy_incompatibility_are_visible():
    view = _view("""set groups first system host-name first
set groups second system host-name second
set apply-groups [ first second ]
set groups G logical-systems L1 system host-name isolated
set logical-systems L2 apply-groups G
""")
    inherited = [item for item in view["effective_statements"] if item["origin"] == "inherited-group"]
    root = [item for item in inherited if item["context"] == "root"]
    assert [(item["source_group"], item["status"]) for item in root] == [
        ("second", "SHADOWED"), ("first", "EFFECTIVE")
    ]
    assert "GROUP_HIERARCHY_INCOMPATIBLE" in {item["status"] for item in view["issues"]}


def test_tenant_scoped_group_and_recursion_limit():
    lines = ["set groups G system host-name tenant",
             "set tenants T1 groups G system host-name scoped",
             "set tenants T1 apply-groups G"]
    lines.extend(f"set groups G{i} apply-groups G{i + 1}" for i in range(65))
    lines.extend(["set groups G65 system host-name too-deep", "set apply-groups G0"])
    view = _view("\n".join(lines))
    inherited = [item for item in view["effective_statements"] if item["origin"] == "inherited-group"]
    assert any(item["context"] == "tenant T1" and item["value"] == "scoped" for item in inherited)
    assert "GROUP_RECURSION_DEPTH_EXCEEDED" in {item["status"] for item in view["issues"]}


def test_group_candidate_evidence_redacts_secret_values():
    secret = "DO_NOT_EXPORT_GROUP_SECRET"
    view = _view(f"set groups G security ike policy I pre-shared-key ascii-text {secret}\nset apply-groups G")
    assert secret not in repr(view)


def test_validation_and_excel_keep_group_failures_and_excluded_candidates():
    from io import BytesIO

    from openpyxl import load_workbook

    result = extract_juniper_source("\n".join([
        "set groups G system host-name excluded-value",
        "set apply-groups-except G",
        "set apply-groups missing",
    ]))
    assert any(issue.category == "inheritance" for issue in result.validation.issues)
    preview = build_juniper_preview(result)
    assert {"policy_relationships", "nat_usage", "vpn_graph", "secure_connect_graph", "apbr_graph", "inheritance_view"} <= set(preview["relationships"])
    output = BytesIO()
    export_juniper_excel(result, output)
    output.seek(0)
    rows = list(load_workbook(output, read_only=True)["Inheritance"].values)
    assert any(row[0] == "candidate" and str(row[3]).endswith("EXCLUDED") for row in rows[1:])
    assert any(row[0] == "issue" and str(row[3]) == "GROUP_NOT_FOUND" for row in rows[1:])
