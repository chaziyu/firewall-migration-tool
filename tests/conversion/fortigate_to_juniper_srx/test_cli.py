import json
from pathlib import Path

from click.testing import CliRunner
import yaml

from fwmigrate.conversion.fortigate_to_juniper_srx.design.deterministic import options_mapping
from fwmigrate.main import cli


FIXTURE = Path(__file__).parents[2] / "fixtures" / "fortigate" / "multi_vendor_explicit.conf"


def test_cli_writes_set_export_and_full_review_report(tmp_path, complete_options):
    source = FIXTURE.read_text(encoding="utf-8").replace('set interface "lan" "app-vlan"', 'set interface "lan"', 1)
    input_path = tmp_path / "source.conf"
    input_path.write_text(source, encoding="utf-8")
    mapping_path = tmp_path / "mapping.yaml"
    mapping_path.write_text(yaml.safe_dump(options_mapping(complete_options)), encoding="utf-8")
    output_path = tmp_path / "output"

    result = CliRunner().invoke(cli, [
        "migrate", "--input", str(input_path), "--output", str(output_path),
        "--target-vendor", "juniper_srx", "--zone-map", str(mapping_path), "--format", "set",
    ])

    assert result.exit_code == 0, result.output
    commands = (output_path / "juniper_config.set").read_text(encoding="utf-8")
    report = json.loads((output_path / "migration_report.json").read_text(encoding="utf-8"))
    assert commands.endswith("\n")
    assert report["pair_id"] == "fortigate_to_juniper_srx"
    assert report["items"]
    assert report["command_count"] == commands.count("\n")
    assert report["command_sha256"]
    assert report["deployment_available"] is False
    assert report["destination_verified"] is False
    assert (output_path / "migration_decisions.json").is_file()
    assert (output_path / "target_mapping.yaml").is_file()


def test_cli_rejects_destination_comparison_without_completeness_metadata(tmp_path):
    input_path = tmp_path / "source.conf"
    target_path = tmp_path / "target.conf"
    input_path.write_text("config system global\nend\n", encoding="utf-8")
    target_path.write_text("", encoding="utf-8")
    result = CliRunner().invoke(cli, [
        "migrate", "--input", str(input_path), "--output", str(tmp_path / "output"),
        "--target-vendor", "juniper_srx", "--target-config", str(target_path), "--format", "set",
    ])

    assert result.exit_code != 0
    assert "requires target_evidence metadata" in result.output


def test_cli_compares_target_and_reports_bound_snapshot(tmp_path, complete_options):
    source = FIXTURE.read_text(encoding="utf-8").replace('set interface "lan" "app-vlan"', 'set interface "lan"', 1)
    input_path = tmp_path / "source.conf"
    target_path = tmp_path / "target.set"
    input_path.write_text(source, encoding="utf-8")
    target_path.write_text("", encoding="utf-8")
    mapping_path = tmp_path / "mapping.yaml"
    mapping = options_mapping(complete_options)
    mapping["target_evidence"] = {
        "context": "root", "version": "25.2R1", "mode": "standalone",
        "complete_families": [
            "addresses", "applications", "interfaces", "zones", "static_routes",
            "schedules", "policies", "nat",
        ],
    }
    mapping_path.write_text(yaml.safe_dump(mapping), encoding="utf-8")
    output_path = tmp_path / "output"

    result = CliRunner().invoke(cli, [
        "migrate", "--input", str(input_path), "--output", str(output_path),
        "--target-vendor", "juniper_srx", "--zone-map", str(mapping_path),
        "--target-config", str(target_path), "--format", "set",
    ])

    assert result.exit_code == 0, result.output
    report = json.loads((output_path / "migration_report.json").read_text(encoding="utf-8"))
    assert report["workflow_mode"] == "DESTINATION_AWARE"
    assert report["destination_verified"] is False
    assert report["destination_snapshot_compared"] is True
    assert report["snapshot_evidence_complete"] is True
    assert report["target_digest"]
    assert any(item["render_disposition"] == "CREATE" and item["family"] == "policy"
               for item in report["items"])
