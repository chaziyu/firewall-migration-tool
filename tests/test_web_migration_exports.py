import io
import zipfile

from fwmigrate.web import create_app
from tests.fixture_paths import CISCO_ASA_FIXTURE


FORTIGATE_ADMIN_ONLY_SOURCE = """
config system interface
    edit port1
    next
    edit port2
    next
end
config firewall policy
    edit 1
        set srcintf port1
        set dstintf port2
        set srcaddr all
        set dstaddr all
        set service ALL
        set action accept
    next
end
config system accprofile
    edit admin-profile
        config utmgrp-permission
            set cli-read enable
        end
    next
end
"""


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


def test_fortigate_admin_only_source_config_still_generates_zip():
    client = create_app({"TESTING": True}).test_client()
    response = client.post(
        "/api/migrate",
        data={
            "source_vendor": "fortigate",
            "target_vendor": "palo_alto",
            "file": (io.BytesIO(FORTIGATE_ADMIN_ONLY_SOURCE.encode()), "fortigate.conf"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    names = zipfile.ZipFile(io.BytesIO(response.data)).namelist()
    assert any(name.endswith(".xlsx") for name in names)
    assert any(
        name.endswith((".xml", ".tf")) and not name.endswith(".xlsx")
        for name in names
    )
