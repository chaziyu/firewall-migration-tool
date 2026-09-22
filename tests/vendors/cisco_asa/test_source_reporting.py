import io

from fwmigrate.source_reporting import source_reporters
from fwmigrate.web import create_app
from fwmigrate.vendors.cisco_asa import CiscoASASourceReporter, ASASourceResult


SOURCE = """hostname asa
interface GigabitEthernet0/1
 nameif outside
 ip address 203.0.113.1 255.255.255.0
object network WEB
 host 10.0.0.10
access-list OUT extended permit tcp object network WEB any eq 443
access-group OUT in interface outside
nat (inside,outside) source static WEB interface
"""


def test_asa_reporter_is_registered_with_an_opaque_native_result():
    reporter = source_reporters.get("CISCO_ASA")

    assert isinstance(reporter, CiscoASASourceReporter)
    analysis = reporter.analyze_source(SOURCE)
    assert isinstance(analysis, ASASourceResult)
    assert analysis.config.hostname == "asa"
    assert [rule.source_order for rule in analysis.config.access_rules] == [7]
    assert not hasattr(analysis, "canonical_ir")


def test_asa_shared_web_flow_uses_vendor_preview_and_excel():
    client = create_app({"TESTING": True}).test_client()
    preview = client.post(
        "/api/preview",
        data={"source_vendor": "cisco_asa", "file": (io.BytesIO(SOURCE.encode()), "asa.cfg")},
        content_type="multipart/form-data",
    )

    assert preview.status_code == 200
    preview_id = preview.get_json()["preview_id"]

    workbook = client.post(
        "/api/extract/excel",
        data={"source_vendor": "cisco_asa", "preview_id": preview_id},
    )

    assert workbook.status_code == 200
    assert workbook.mimetype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
