import io
from fwmigrate.web import create_app
from tests.fixture_paths import CISCO_ASA_FIXTURE


def test_migration_endpoint_is_explicitly_unavailable():
    client = create_app({"TESTING": True}).test_client()
    response = client.post(
        "/api/migrate",
        data={
            "source_vendor": "cisco_asa",
            "target_vendor": "palo_alto",
            "include_report": "true",
            "file": (io.BytesIO(CISCO_ASA_FIXTURE.read_bytes()), CISCO_ASA_FIXTURE.name),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 503
    assert response.get_json() == {
        "error": (
            "Configuration conversion is temporarily unavailable while the "
            "pair-specific conversion architecture is being implemented."
        )
    }


def test_terraform_prepare_is_explicitly_unavailable():
    client = create_app({"TESTING": True}).test_client()
    response = client.post("/api/terraform/prepare")

    assert response.status_code == 503
    assert "Configuration conversion is temporarily unavailable" in response.get_json()["error"]
