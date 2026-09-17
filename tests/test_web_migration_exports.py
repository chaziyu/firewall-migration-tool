import io
import zipfile

from fwmigrate.web import create_app
from tests.fixture_paths import CISCO_ASA_FIXTURE


def test_migration_zip_contains_artifacts_and_inventory_only():
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

    assert response.status_code == 200
    names = zipfile.ZipFile(io.BytesIO(response.data)).namelist()
    assert names
    assert not any(name.endswith((".md", ".html")) for name in names)
    assert any(name.endswith(".xlsx") for name in names)
