import io
from pathlib import Path

from openpyxl import load_workbook

from fwmigrate.web import create_app
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


FIXTURE = Path(__file__).parents[2] / "fixtures" / "example_palo_alto.xml"


def test_palo_alto_source_preview_and_excel_are_registered():
    client = create_app({"TESTING": True}).test_client()
    source = FIXTURE.read_bytes()

    preview = client.post(
        "/api/preview",
        data={
            "source_vendor": "palo_alto",
            "file": (io.BytesIO(source), "panos.xml"),
        },
        content_type="multipart/form-data",
    )

    assert preview.status_code == 200
    payload = preview.get_json()
    assert payload["vendor"] == "palo_alto"
    assert payload["summary"]["policies"] >= 0

    workbook = client.post(
        "/api/extract/excel",
        data={
            "source_vendor": "palo_alto",
            "preview_id": payload["preview_id"],
        },
        content_type="multipart/form-data",
    )

    assert workbook.status_code == 200
    assert "Interfaces" in load_workbook(io.BytesIO(workbook.data), read_only=True).sheetnames


def test_palo_alto_reporter_keeps_source_result_native_and_scope_aware():
    analysis = PaloAltoSourceReporter().analyze_source(FIXTURE.read_text())

    assert analysis.config.source_format == "xml"
    assert analysis.config.source_inventory
    assert analysis.config.scopes
    assert analysis.config.source_inventory[0].source_path
    assert not hasattr(analysis.config, "canonical_ir")
    assert not hasattr(analysis, "legacy_extraction")


def test_palo_alto_native_source_evidence_redacts_secret_values():
    source = "<config><shared><entry name='admin'><password>do-not-export</password></entry></shared></config>"

    analysis = PaloAltoSourceReporter().analyze_source(source)

    assert "do-not-export" not in str(analysis.config.model_dump())
