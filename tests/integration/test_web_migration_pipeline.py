import io
import zipfile
from unittest.mock import patch

from fwmigrate.application import MigrationPipeline, MigrationRequest
from fwmigrate.web import create_app
from tests.fixture_paths import CISCO_ASA_FIXTURE


def test_web_migration_delegates_to_pipeline_and_packages_result():
    content = CISCO_ASA_FIXTURE.read_text(encoding="utf-8")
    expected = MigrationPipeline().run(MigrationRequest(
        source_vendor="cisco_asa",
        target_vendor="palo_alto",
        source_content=content,
        target_format="all",
        source_name="example.cfg",
    ))

    with patch("fwmigrate.web.MigrationPipeline.run", return_value=expected) as run:
        response = create_app({"TESTING": True}).test_client().post(
            "/api/migrate",
            data={
                "source_vendor": "cisco_asa",
                "target_vendor": "palo_alto",
                "file": (io.BytesIO(content.encode("utf-8")), "example.cfg"),
            },
            content_type="multipart/form-data",
        )

    assert response.status_code == 200
    request = run.call_args.args[0]
    assert request.source_vendor == "cisco_asa"
    assert request.target_vendor == "palo_alto"
    assert request.source_content == content
    assert request.source_name == "example.cfg"
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.read("palo_alto_config.xml").decode("utf-8") == next(
            artifact.content
            for artifact in expected.artifacts
            if artifact.filename == "palo_alto_config.xml"
        )


def test_web_returns_structured_blocked_result_without_target_artifacts():
    content = CISCO_ASA_FIXTURE.read_text(encoding="utf-8")
    blocked = MigrationPipeline().run(MigrationRequest(
        source_vendor="cisco_asa",
        target_vendor="palo_alto",
        source_content=content,
        target_format="all",
        source_name="example.cfg",
    ))
    blocked.generation_allowed = False
    blocked.blocking_reasons = ["unsupported dependency"]
    blocked.artifacts = []

    with patch("fwmigrate.web.MigrationPipeline.run", return_value=blocked):
        response = create_app({"TESTING": True}).test_client().post(
            "/api/migrate",
            data={
                "source_vendor": "cisco_asa",
                "target_vendor": "palo_alto",
                "file": (io.BytesIO(content.encode("utf-8")), "example.cfg"),
            },
            content_type="multipart/form-data",
        )

    payload = response.get_json()
    assert response.status_code == 422
    assert payload["status"] == "blocked"
    assert payload["generation_allowed"] is False
    assert payload["blocking_reasons"] == ["unsupported dependency"]
    assert "artifacts" not in payload
