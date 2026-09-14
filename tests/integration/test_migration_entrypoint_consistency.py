import io
import zipfile

from click.testing import CliRunner

from fwmigrate.main import cli
from fwmigrate.web import create_app
from tests.fixture_paths import CISCO_ASA_FIXTURE


def test_cli_and_web_generate_equivalent_palo_alto_xml(tmp_path):
    content = CISCO_ASA_FIXTURE.read_text(encoding="utf-8")
    cli_output = tmp_path / "cli-output"
    cli_result = CliRunner().invoke(
        cli,
        [
            "migrate",
            "-i",
            str(CISCO_ASA_FIXTURE),
            "-o",
            str(cli_output),
            "--format",
            "xml",
            "--source-vendor",
            "cisco_asa",
        ],
    )

    assert cli_result.exit_code == 0
    cli_artifact = (cli_output / "palo_alto_config.xml").read_text(encoding="utf-8")

    response = create_app({"TESTING": True}).test_client().post(
        "/api/migrate",
        data={
            "source_vendor": "cisco_asa",
            "file": (io.BytesIO(content.encode("utf-8")), "example.cfg"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.read("palo_alto_config.xml").decode("utf-8") == cli_artifact
