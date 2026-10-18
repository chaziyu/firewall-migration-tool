import json

from click.testing import CliRunner

from fwmigrate.main import cli
from tests.conversion.fortigate_to_checkpoint.conftest import SOURCE


def test_cli_writes_unapproved_split_review_files(tmp_path):
    source = tmp_path / "source.conf"
    source.write_text(SOURCE, encoding="utf-8")
    output = tmp_path / "review"
    result = CliRunner().invoke(cli, [
        "migrate", "--input", str(source), "--output", str(output),
        "--source-vendor", "fortigate", "--target-vendor", "checkpoint", "--format", "json",
    ])

    assert result.exit_code == 0, result.output
    assert (output / "checkpoint_management_operations.json").exists()
    assert (output / "gaia_config.clish").exists()
    assert (output / "checkpoint_bindings.json").exists()
    report = json.loads((output / "migration_report.json").read_text(encoding="utf-8"))
    assert report["pair_id"] == "fortigate_to_checkpoint"
    assert report["approval_required_for_web_download"] is True
    assert report["cli_output_is_unapproved_review_material"] is True
    assert report["deployment_available"] is False


def test_cli_rejects_invalid_destination_snapshot_for_checkpoint(tmp_path):
    source = tmp_path / "source.conf"
    source.write_text(SOURCE, encoding="utf-8")
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    result = CliRunner().invoke(cli, [
        "migrate", "--input", str(source), "--output", str(tmp_path / "review"),
        "--source-vendor", "fortigate", "--target-vendor", "checkpoint",
        "--format", "json", "--target-config", str(target),
    ])

    assert result.exit_code != 0
    assert "Invalid Check Point destination snapshot" in result.output
