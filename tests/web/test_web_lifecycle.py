"""Web API and Excel export tests for FortiGate and PAN-OS lifecycle reporting."""

from __future__ import annotations

import io
import pytest
from openpyxl import load_workbook

from fwmigrate.source_reporting import lifecycle
from fwmigrate.web import create_app


@pytest.fixture(autouse=True)
def _reset_cache():
    lifecycle.clear_lifecycle_cache()
    yield
    lifecycle.clear_lifecycle_cache()


FORTIGATE_CONFIG = """#config-version=FGT60F-7.4.13-FW-build2999-260101:opmode=0:vdom=0:user=admin
#serial_number=FGT60FTK21099999
config system global
    set hostname "edge-fg"
end
config system interface
    edit "port1"
        set ip 192.0.2.1 255.255.255.0
    next
end
"""

PANOS_EXACT_XML = """<config version="11.1.0" detail-version="11.1.4-h1">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>pa-edge</hostname>
        </system>
      </deviceconfig>
    </entry>
  </devices>
</config>"""

PANOS_SCHEMA_ONLY_XML = """<config version="11.1.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>pa-schema</hostname>
        </system>
      </deviceconfig>
    </entry>
  </devices>
</config>"""


def test_preview_includes_nonblocking_lifecycle_without_network(monkeypatch):
    def _fail_network(*_args, **_kwargs):
        raise AssertionError("Preview must not perform outbound HTTP calls")

    monkeypatch.setattr(lifecycle, "_fetch_endoflife_branches", _fail_network)
    monkeypatch.setattr(lifecycle, "_fetch_fortinet_rss_latest", _fail_network)
    monkeypatch.setattr(lifecycle, "_fetch_panos_endoflife_branches", _fail_network)

    client = create_app({"TESTING": True}).test_client()

    fg_resp = client.post(
        "/api/preview",
        data={"source_vendor": "fortigate", "file": (io.BytesIO(FORTIGATE_CONFIG.encode()), "fg.conf")},
        content_type="multipart/form-data",
    )
    assert fg_resp.status_code == 200
    fg_body = fg_resp.get_json()
    fg_card = fg_body["summary"]["lifecycle"]
    assert fg_card["id"] == "fg_lifecycle_card"
    assert fg_card["needs_live_refresh"] is True
    assert fg_card["refresh_params"] == {
        "vendor": "fortigate",
        "model": "FG-60F",
        "firmware": "7.4.13",
    }
    assert "FGT60FTK21099999" not in str(fg_card)

    pa_resp = client.post(
        "/api/preview",
        data={"source_vendor": "palo_alto", "file": (io.BytesIO(PANOS_EXACT_XML.encode()), "pa.xml")},
        content_type="multipart/form-data",
    )
    assert pa_resp.status_code == 200
    pa_body = pa_resp.get_json()
    assert pa_body["source_version"] == "11.1.0"
    assert pa_body["detail_version"] == "11.1.4-h1"
    pa_card = pa_body["summary"]["lifecycle"]
    assert pa_card["id"] == "pa_lifecycle_card"
    assert pa_card["needs_live_refresh"] is True
    assert pa_card["refresh_params"] == {
        "vendor": "palo_alto",
        "version": "11.1.4-h1",
        "exact": True,
    }

    pa_schema_resp = client.post(
        "/api/preview",
        data={"source_vendor": "palo_alto", "file": (io.BytesIO(PANOS_SCHEMA_ONLY_XML.encode()), "pa2.xml")},
        content_type="multipart/form-data",
    )
    assert pa_schema_resp.status_code == 200
    pa_schema_card = pa_schema_resp.get_json()["summary"]["lifecycle"]
    assert pa_schema_card["refresh_params"]["exact"] is False
    assert "XML schema version" in pa_schema_card["rows"][0]["value"]


def test_get_lifecycle_endpoint_fetches_live_and_rejects_unknown_vendor(monkeypatch):
    monkeypatch.setattr(
        lifecycle,
        "_fetch_endoflife_branches",
        lambda: {"7.4": {"release_date": "2023-05-11", "eoes": "2027-05-11", "eos": "2028-11-11", "latest": "7.4.99"}},
    )
    monkeypatch.setattr(lifecycle, "_fetch_fortinet_rss_latest", lambda: {"7.4": "7.4.99"})
    monkeypatch.setattr(
        lifecycle,
        "_fetch_panos_endoflife_branches",
        lambda: {"11.1": {"release_date": "2023-11-03", "eos": "2027-05-03", "latest": "11.1.99", "latest_date": "2026-11-24"}},
    )

    client = create_app({"TESTING": True}).test_client()

    fg_live = client.get("/api/lifecycle?vendor=fortigate&model=FG-60F&firmware=7.4.13")
    assert fg_live.status_code == 200
    fg_card = fg_live.get_json()["lifecycle"]
    assert fg_card["needs_live_refresh"] is False
    assert fg_card["badge"]["text"] == "Patch Available (7.4.99)"

    pa_live = client.get("/api/lifecycle?vendor=palo_alto&version=11.1.4-h1&exact=true")
    assert pa_live.status_code == 200
    pa_card = pa_live.get_json()["lifecycle"]
    assert pa_card["needs_live_refresh"] is False
    assert pa_card["badge"]["text"] == "Patch Available (11.1.99)"

    bad = client.get("/api/lifecycle?vendor=cisco_asa")
    assert bad.status_code == 400


def test_excel_export_writes_offline_lifecycle_rows_without_network(monkeypatch):
    def _fail_network(*_args, **_kwargs):
        raise AssertionError("Excel export must not perform outbound HTTP calls")

    monkeypatch.setattr(lifecycle, "_fetch_endoflife_branches", _fail_network)
    monkeypatch.setattr(lifecycle, "_fetch_fortinet_rss_latest", _fail_network)
    monkeypatch.setattr(lifecycle, "_fetch_panos_endoflife_branches", _fail_network)

    client = create_app({"TESTING": True}).test_client()

    fg_xlsx = client.post(
        "/api/extract/excel",
        data={
            "source_vendor": "fortigate",
            "excel_profile": "fast",
            "file": (io.BytesIO(FORTIGATE_CONFIG.encode()), "fg.conf"),
        },
        content_type="multipart/form-data",
    )
    assert fg_xlsx.status_code == 200
    fg_wb = load_workbook(io.BytesIO(fg_xlsx.data), read_only=True)
    fg_summary = [[cell for cell in row[:2] if cell is not None] for row in fg_wb["Summary"].iter_rows(values_only=True)]
    fg_wb.close()
    assert ["LIFECYCLE & FIRMWARE"] in fg_summary
    assert any(row[0] == "Hardware Model" and row[1] == "FortiGate-60F" for row in fg_summary if len(row) >= 2)

    pa_xlsx = client.post(
        "/api/extract/excel",
        data={
            "source_vendor": "palo_alto",
            "excel_profile": "fast",
            "file": (io.BytesIO(PANOS_EXACT_XML.encode()), "pa.xml"),
        },
        content_type="multipart/form-data",
    )
    assert pa_xlsx.status_code == 200
    pa_wb = load_workbook(io.BytesIO(pa_xlsx.data), read_only=True)
    pa_summary = [[cell for cell in row[:2] if cell is not None] for row in pa_wb["Summary"].iter_rows(values_only=True)]
    pa_wb.close()
    assert ["LIFECYCLE & FIRMWARE"] in pa_summary
    assert any(row[0] == "Current PAN-OS" and "11.1.4-h1" in str(row[1]) for row in pa_summary if len(row) >= 2)
