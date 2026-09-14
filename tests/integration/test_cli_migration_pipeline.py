from unittest.mock import patch

from click.testing import CliRunner

from fwmigrate.application import MigrationPipeline
from fwmigrate.main import cli
from tests.fixture_paths import CISCO_ASA_FIXTURE


def test_cli_builds_request_for_shared_pipeline(tmp_path):
    runner = CliRunner()
    output = tmp_path / "output"
    real_pipeline = MigrationPipeline()
    captured = {}

    def run(request):
        captured["request"] = request
        return real_pipeline.run(request)

    with patch("fwmigrate.main.MigrationPipeline") as pipeline_cls:
        pipeline_cls.return_value.run.side_effect = run
        result = runner.invoke(cli, [
            "migrate",
            "-i", str(CISCO_ASA_FIXTURE),
            "--source-vendor", "cisco_asa",
            "--target-vendor", "palo_alto",
            "-o", str(output),
            "--format", "xml",
        ])

    assert result.exit_code == 0, result.output
    assert captured["request"].source_vendor == "cisco_asa"
    assert captured["request"].target_vendor == "palo_alto"
    assert captured["request"].target_format == "xml"
    assert (output / "palo_alto_config.xml").exists()
