import io
import json

from openpyxl import load_workbook

from fwmigrate.source_reporting import source_reporters
from fwmigrate.web import create_app
from fwmigrate.vendors.fortigate.source_report import (
    FortiGateSourceReporter,
    FortiGateSourceResult,
)


SOURCE = """config system global
    set hostname fg-report
end
config vdom
    edit root
        config firewall address
            edit web
                set subnet 192.0.2.10 255.255.255.255
            next
        end
    next
end
"""

UNSUPPORTED_SOURCE = """config firewall unsupported-section
    edit source-only
        set unsupported-setting preserve-me
    next
end
"""

SECRET_SOURCE = """config vpn ipsec phase1-interface
    edit VPN-HQ
        set psksecret do-not-export-this-secret
    next
end
config user local
    edit alice
        set type password
        set passwd another-do-not-export-secret
    next
end
"""


def test_fortigate_reporter_is_registered_and_keeps_analysis_opaque():
    reporter = source_reporters.get("FORTIGATE")

    assert isinstance(reporter, FortiGateSourceReporter)
    analysis = reporter.analyze_source(SOURCE)
    assert isinstance(analysis, FortiGateSourceResult)
    assert analysis.extracted.config.interfaces == []
    assert analysis.extracted.source_objects
    assert not hasattr(analysis.extracted, "canonical_ir")


def test_fortigate_reporter_builds_preview_and_excel():
    reporter = source_reporters.get("fortigate")
    analysis = reporter.analyze_source(SOURCE)

    preview = reporter.build_preview(analysis)
    assert preview["summary"]["objects"]["addresses"] == 1

    output = io.BytesIO()
    reporter.export_excel(analysis, output)
    workbook = load_workbook(io.BytesIO(output.getvalue()), read_only=True)
    assert "Summary" in workbook.sheetnames
    assert "Addresses" in workbook.sheetnames


def test_shared_web_host_uses_fortigate_reporter_for_preview_and_excel():
    client = create_app({"TESTING": True}).test_client()
    preview = client.post(
        "/api/preview",
        data={
            "source_vendor": "fortigate",
            "file": (io.BytesIO(SOURCE.encode()), "fortigate.conf"),
        },
        content_type="multipart/form-data",
    )

    assert preview.status_code == 200
    preview_payload = preview.get_json()
    assert preview_payload["summary"]["objects"]["addresses"] == 1
    assert preview_payload["preview_id"]

    workbook = client.post(
        "/api/extract/excel",
        data={
            "source_vendor": "fortigate",
            "preview_id": preview_payload["preview_id"],
        },
    )
    assert workbook.status_code == 200
    assert workbook.mimetype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def test_fortigate_web_upload_handles_vdom_config_and_downloads_workbook():
    client = create_app({"TESTING": True}).test_client()

    response = client.post(
        "/api/preview",
        data={"file": (io.BytesIO(SOURCE.encode()), "vdom.conf")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert response.get_json()["summary"]["top_level_sections"] == 2


def test_fortigate_web_rejects_invalid_input():
    client = create_app({"TESTING": True}).test_client()

    response = client.post(
        "/api/preview",
        data={"file": (io.BytesIO(b"\xff\xfe"), "invalid.conf")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert response.get_json()["stage"] == "decode"


def test_fortigate_unsupported_source_is_preserved_without_failing_preview():
    client = create_app({"TESTING": True}).test_client()
    response = client.post(
        "/api/preview",
        data={"file": (io.BytesIO(UNSUPPORTED_SOURCE.encode()), "unsupported.conf")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert response.get_json()["summary"]["top_level_sections"] == 1


def test_fortigate_web_preview_and_excel_redact_secrets():
    client = create_app({"TESTING": True}).test_client()
    preview = client.post(
        "/api/preview",
        data={"file": (io.BytesIO(SECRET_SOURCE.encode()), "secrets.conf")},
        content_type="multipart/form-data",
    )
    assert preview.status_code == 200
    assert "do-not-export-this-secret" not in json.dumps(preview.get_json())
    assert "another-do-not-export-secret" not in json.dumps(preview.get_json())

    workbook = client.post(
        "/api/extract/excel",
        data={"preview_id": preview.get_json()["preview_id"]},
    )
    assert workbook.status_code == 200
    assert b"do-not-export-this-secret" not in workbook.data
    assert b"another-do-not-export-secret" not in workbook.data
