import io
import zipfile
from unittest.mock import patch

from fwmigrate.application import MigrationPipeline
from fwmigrate.web import create_app
from tests.fixture_paths import CISCO_ASA_FIXTURE


def test_web_migration_uses_shared_pipeline():
    app = create_app({"TESTING": True})
    client = app.test_client()
    real_pipeline = MigrationPipeline()
    captured = {}

    def run(request):
        captured["request"] = request
        return real_pipeline.run(request)

    with patch("fwmigrate.web.MigrationPipeline") as pipeline_cls:
        pipeline_cls.return_value.run.side_effect = run
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
    assert captured["request"].source_name == "example.cfg"
    assert captured["request"].target_format == "all"
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert "palo_alto_config.xml" in archive.namelist()
        assert "migration_report.md" in archive.namelist()
