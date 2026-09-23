import io
from fwmigrate.web import create_app
from tests.fixture_paths import CISCO_ASA_FIXTURE


def test_migration_endpoint_rejects_unsupported_pair():
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

    assert response.status_code == 400
    assert response.get_json() == {"error": "Only fortigate -> palo_alto is supported"}


def test_terraform_endpoints_are_removed():
    client = create_app({"TESTING": True}).test_client()
    for path in (
        "/api/terraform/prepare",
        "/api/terraform/plan",
        "/api/terraform/approve",
        "/api/terraform/apply/stream",
        "/api/terraform/destroy/stream",
        "/api/download/state",
        "/api/download/package",
    ):
        assert client.post(path).status_code == 404
