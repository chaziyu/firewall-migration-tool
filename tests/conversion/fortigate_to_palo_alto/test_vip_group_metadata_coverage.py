from copy import deepcopy
import io
import json

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, run_migration_pipeline
from fwmigrate.conversion.fortigate_to_palo_alto.coverage import build_migration_coverage
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


SOURCE = """config system interface
edit outside
set type physical
set ip 192.0.2.1 255.255.255.0
next
edit inside
set type physical
set ip 10.0.0.1 255.255.255.0
next
end
config firewall vip
edit published
set type static-nat
set extip 192.0.2.10
set mappedip 10.0.0.10
set extintf outside
next
end
config firewall vipgrp
edit published-group
set member published
next
end
config firewall policy
edit 1
set name inbound
set srcintf outside
set dstintf inside
set srcaddr all
set dstaddr published-group
set service ALL
set action accept
set schedule always
next
end
"""


def source_text(comment=None, extra=""):
    setting = "" if comment is None else f'set comments "{comment}"'
    return SOURCE.replace("set member published", f"set member published\n{setting}\n{extra}")


def options():
    return PANMigrationOptions(vdoms={"root": {"vsys": "vsys1", "virtual_router": "VR"}}, interfaces={"root": {
        "outside": {"target_interface": "ethernet1/1", "target_zone": "outside"},
        "inside": {"target_interface": "ethernet1/2", "target_zone": "inside"}}})


def migrate(text):
    analysis = FortiGateSourceReporter().analyze_source(text)
    before = deepcopy(analysis.extracted)
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived, options=options(),
        include_interface_zones=True, source_inventory=analysis.extracted.source_objects)
    assert analysis.extracted == before
    return result


@pytest.mark.parametrize("comment", [None, "", "Group owner"])
def test_group_metadata_remains_manual_without_blocking_verified_traffic(comment):
    baseline = migrate(source_text())
    assert baseline.artifact_status == "READY"
    result = migrate(source_text(comment))
    assert result.rendered.commands == baseline.rendered.commands
    assert any("rulebase security" in command for command in result.rendered.commands)
    assert any("rulebase nat" in command for command in result.rendered.commands)
    if comment is None:
        assert result.coverage["complete"]
        assert result.artifact_status == "READY"
    else:
        assert result.artifact_status == "PARTIAL"
        assert not result.coverage["complete"]
        gap, = result.coverage["unplanned"]
        assert (gap["source_vdom"], gap["source_kind"], gap["source_name"]) == ("root", "vip_group", "published-group")
        assert "VIP-group comment requires manual metadata review" in gap["reason"]
        assert "membership and consumer coverage" not in gap["reason"]
        assert "Group owner" not in gap["reason"]


def test_unset_comment_does_not_create_metadata_work():
    result = migrate(source_text("Old owner", extra="unset comments"))
    assert result.artifact_status == "READY"
    assert result.coverage["complete"]


def test_same_named_source_groups_keep_scoped_residual_metadata_records():
    text = "config vdom\n" + "".join(f'''edit {vdom}
config firewall vipgrp
edit published-group
set member published
set comments "Scoped owner"
next
end
next
''' for vdom in ("root", "blue")) + "end\n"
    analysis = FortiGateSourceReporter().analyze_source(text)
    covered_membership = {("root", "published-group"), ("blue", "published-group")}
    coverage = build_migration_coverage(analysis.extracted.config, planned_vip_groups=covered_membership)
    assert coverage["unplanned_count"] == 2
    assert {row["source_vdom"] for row in coverage["unplanned"]} == {"root", "blue"}


def test_unrepresented_group_keeps_both_metadata_and_membership_limitations():
    analysis = FortiGateSourceReporter().analyze_source(source_text("Group owner"))
    coverage = build_migration_coverage(analysis.extracted.config)
    gap, = [row for row in coverage["unplanned"] if row["source_kind"] == "vip_group"]
    assert "VIP-group comment requires manual metadata review" in gap["reason"]
    assert "membership and consumer coverage" in gap["reason"]


def test_web_review_exposes_group_metadata_without_echoing_source_comment():
    from fwmigrate.web import create_app

    client = create_app({"TESTING": True}).test_client()
    preview = client.post("/api/preview", data={"file": (io.BytesIO(source_text("Group owner").encode()), "source.conf")})
    assert preview.status_code == 200
    prepared = client.post("/api/migration/design/prepare", json={"source": preview.get_json()["source_evidence"],
        "workflow_mode": "OFFLINE_EXPORT"})
    assert prepared.status_code == 200
    issues = prepared.get_json()["draft"]["issues"]
    assert any(row["category"] == "MANUAL" and "VIP-group comment requires manual metadata review" in row["explanation"]
               for row in issues)
    assert all("Group owner" not in row["explanation"] for row in issues)


def test_cli_keeps_traffic_commands_and_reports_remaining_group_metadata(tmp_path):
    from click.testing import CliRunner
    import yaml
    from fwmigrate.main import cli

    source = tmp_path / "source.conf"
    source.write_text(source_text("Group owner"))
    mapping = tmp_path / "mapping.yaml"
    mapping.write_text(yaml.safe_dump({"vdoms": {"root": {"vsys": "vsys1", "virtual_router": "VR"}},
        "interfaces": {"root": {"outside": {"target_interface": "ethernet1/1", "target_zone": "outside"},
                                "inside": {"target_interface": "ethernet1/2", "target_zone": "inside"}}}}))
    output = tmp_path / "output"
    response = CliRunner().invoke(cli, ["migrate", "-i", str(source), "-o", str(output),
        "--zone-map", str(mapping), "--automation-mode", "REVIEW_ONLY"])
    assert response.exit_code == 0, response.output
    report = json.loads((output / "migration_report.json").read_text())
    commands = (output / "palo_alto_config.set").read_text()
    assert report["plan_status"] == "PARTIAL"
    assert any("rulebase security" in row and "inbound" in row for row in commands.splitlines())
    assert any("VIP-group comment requires manual metadata review" in row["reason"] for row in report["coverage"]["unplanned"])
