from unittest.mock import patch

from click.testing import CliRunner

from fwmigrate.application import MigrationResult
from fwmigrate.core.base_generator import MigrationArtifact
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.main import cli
from tests.fixture_paths import FORTIGATE_FIXTURE


def test_cli_migration_delegates_to_pipeline(tmp_path):
    ir = PluginRegistry.get_parser("fortigate").parse(
        FORTIGATE_FIXTURE.read_text(encoding="utf-8")
    )
    result = MigrationResult(
        extraction=PluginRegistry.get_parser("fortigate").extract(
            FORTIGATE_FIXTURE.read_text(encoding="utf-8")
        ),
        source_ir=ir,
        final_ir=ir,
        artifacts=[MigrationArtifact(filename="result.xml", content="<config/>", format="xml")],
    )

    with patch("fwmigrate.main.MigrationPipeline.run", return_value=result) as run:
        response = CliRunner().invoke(cli, [
            "migrate", "-i", str(FORTIGATE_FIXTURE), "-o", str(tmp_path),
            "--format", "xml",
        ])

    assert response.exit_code == 0
    run.assert_called_once()
    assert run.call_args.args[0].source_vendor == "fortigate"
    assert run.call_args.args[0].target_vendor == "palo_alto"
    assert run.call_args.args[0].target_format == "xml"
    assert (tmp_path / "result.xml").read_text(encoding="utf-8") == "<config/>"
