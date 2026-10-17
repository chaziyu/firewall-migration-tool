import json

from click.testing import CliRunner

from fwmigrate.main import cli

def test_asa_cli_dispatch_writes_review_and_source_workbook(tmp_path, asa_source_text):
    source = tmp_path / "source.conf"
    source.write_text(asa_source_text, encoding="utf-8")
    mapping = tmp_path / "mapping.yaml"
    mapping.write_text('''source_vdom: root
target_context: single
target_version: "9.20"
target_mode: routed
interfaces:
  root:
    inside:
      interface: GigabitEthernet0/1
      nameif: inside
      security_level: 100
    outside:
      interface: GigabitEthernet0/0
      nameif: outside
      security_level: 0
''', encoding="utf-8")
    output = tmp_path / "out"
    result = CliRunner().invoke(cli, ["migrate", "--input", str(source), "--output", str(output),
                                      "--source-vendor", "fortigate", "--target-vendor", "cisco_asa",
                                      "--zone-map", str(mapping), "--format", "cfg"])
    assert result.exit_code == 0, result.output
    assert (output / "asa_config.cfg").exists()
    assert (output / "source_inventory.xlsx").stat().st_size > 0
    report = json.loads((output / "migration_report.json").read_text(encoding="utf-8"))
    assert report["pair_id"] == "fortigate_to_cisco_asa"
    assert report["deployment_available"] is False
