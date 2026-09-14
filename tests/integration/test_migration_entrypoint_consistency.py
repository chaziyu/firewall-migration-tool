import io
import zipfile

from click.testing import CliRunner

from fwmigrate.main import cli
from fwmigrate.web import create_app
from tests.fixture_paths import CISCO_ASA_FIXTURE


def test_cli_and_web_use_same_pipeline_output(tmp_path):
    output = tmp_path / "output"
    result = CliRunner().invoke(cli, [
        "migrate",
        "-i", str(CISCO_ASA_FIXTURE),
        "--source-vendor", "cisco_asa",
        "--target-vendor", "palo_alto",
        "-o", str(output),
        "--format", "xml",
    ])
    assert result.exit_code == 0, result.output

    client = create_app({"TESTING": True}).test_client()
    response = client.post(
        "/api/migrate",
        data={
            "source_vendor": "cisco_asa",
            "target_vendor": "palo_alto",
            "file": (io.BytesIO(CISCO_ASA_FIXTURE.read_bytes()), "example.cfg"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 200

    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        web_xml = archive.read("palo_alto_config.xml").decode("utf-8")
        cli_xml = (output / "palo_alto_config.xml").read_text(encoding="utf-8")
        assert web_xml.replace("\r\n", "\n") == cli_xml.replace("\r\n", "\n")
