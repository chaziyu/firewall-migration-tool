import io
import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from openpyxl import load_workbook

from fwmigrate.web import create_app, source_reporters
from fwmigrate.source_reporting.web_report import normalize_web_report
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


def test_malformed_secret_bearing_source_returns_safe_client_errors():
    client = create_app({"TESTING": True}).test_client()
    source = json.dumps({"format": "checkpoint-export-v1", "responses": [
        {"data": {"password": "ERROR_SECRET_SENTINEL"}},
    ]}).encode()
    for route in ("/api/preview", "/api/extract/excel"):
        response = client.post(route, data={"source_vendor": "checkpoint",
            "file": (io.BytesIO(source), "invalid.json")}, content_type="multipart/form-data")
        assert response.status_code == 400
        assert b"ERROR_SECRET_SENTINEL" not in response.data
        assert b"input_value" not in response.data


ASA_SOURCE = (
    "hostname asa\n"
    "username admin password 0 web-secret\n"
    "interface GigabitEthernet0/1\n"
    " nameif outside\n"
    " ip address 203.0.113.1 255.255.255.0\n"
    "object network WEB\n"
    " host 10.0.0.10\n"
    "access-list OUT extended permit tcp object WEB any eq 443\n"
)

PALO_SOURCE = '<config><shared><address><entry name="web"><ip-netmask>203.0.113.10</ip-netmask><future-password>palo-web-secret</future-password></entry></address></shared></config>'
CHECKPOINT_SOURCE = '{"format":"checkpoint-export-v1","domain":"SMC User","gateway":"CP-Enterprise-Gateway","selected_domain":"SMC User","selected_package":"Standard","selected_access_layer":"Network","selected_gateway":"CP-Enterprise-Gateway","responses":[{"command":"show-hosts","domain":"SMC User","data":{"objects":[{"name":"web","type":"host","ipv4-address":"203.0.113.10","password":"checkpoint-web-secret"}],"from":1,"to":1,"total":1}}]}'
FORTIGATE_SOURCE = """config system interface
    edit "port1"
        set ip 192.0.2.1 255.255.255.0
    next
end
config firewall policy
    edit 1
        set name "web"
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set schedule "always"
        set action accept
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
    next
end
"""

FORTIGATE_IPV6_POLICY_SOURCE = """config system interface
    edit "port1"
        set ip 192.0.2.1 255.255.255.0
    next
end
config firewall address6
    edit "SRC-V6"
        set ip6 2001:db8:1::/64
    next
    edit "DST-V6"
        set ip6 2001:db8:2::/64
    next
end
config firewall policy
    edit 60
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr6 "SRC-V6"
        set dstaddr6 "DST-V6"
        set service "ALL"
        set schedule always
        set action accept
    next
end
"""


def _post(client, path, **fields):
    data = {"source_vendor": "cisco_asa", **fields}
    if path == "/api/preview" or "file" not in data:
        data["file"] = (io.BytesIO(ASA_SOURCE.encode()), "asa.cfg")
    return client.post(path, data=data, content_type="multipart/form-data")


def test_source_preview_and_excel_use_opaque_cached_asa_analysis():
    client = create_app({"TESTING": True}).test_client()

    preview = _post(client, "/api/preview")
    assert preview.status_code == 200
    payload = preview.get_json()
    assert payload["vendor"] == "cisco_asa"
    assert payload["summary"]["interfaces"] == 1
    assert "interfaces" in payload["sections"]
    assert "vpn_phase2" in payload["sections"]
    assert "canonical_ir" not in str(payload)

    workbook = client.post("/api/extract/excel", json={"source_vendor": "cisco_asa", "source": payload["source_evidence"]})
    assert workbook.status_code == 200
    assert workbook.mimetype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    sheets = load_workbook(io.BytesIO(workbook.data), read_only=True).sheetnames
    assert "Interfaces" in sheets
    assert "web-secret" not in workbook.data.decode("latin1", errors="ignore")


def test_source_is_reanalyzed_for_each_request_and_survives_restart(monkeypatch):
    client = create_app({'TESTING': True}).test_client()
    reporter = source_reporters.get('fortigate')
    original = reporter.analyze_source
    calls = []
    def analyze(source, **options):
        calls.append(source)
        return original(source, **options)
    monkeypatch.setattr(reporter, 'analyze_source', analyze)
    preview = client.post('/api/preview', data={'file': (io.BytesIO(FORTIGATE_SOURCE.encode()), 'source.conf')}).get_json()
    assert 'preview_id' not in preview
    restarted = create_app({'TESTING': True}).test_client()
    response = restarted.post('/api/extract/excel', json={'source_vendor': 'fortigate', 'source': preview['source_evidence']})
    assert response.status_code == 200
    assert len(calls) == 2
    assert restarted.post('/api/migration/requirements', json={'source': preview['source_evidence']}).status_code == 200


def test_source_excel_rejects_missing_input_and_unknown_vendor():
    client = create_app({"TESTING": True}).test_client()

    missing = client.post("/api/extract/excel", data={"source_vendor": "cisco_asa"})
    assert missing.status_code == 400

    unknown = _post(client, "/api/preview", source_vendor="unknown")
    assert unknown.status_code == 400


def test_source_excel_vendor_mismatch_does_not_use_cached_preview():
    client = create_app({"TESTING": True}).test_client()
    preview = _post(client, "/api/preview").get_json()

    response = client.post(
        "/api/extract/excel",
        data={"source_vendor": "unknown", "source": preview["source_evidence"]},
        content_type="multipart/form-data",
    )
    assert response.status_code == 422


def test_palo_alto_upload_cached_preview_and_excel_redact_secrets():
    client = create_app({"TESTING": True}).test_client()
    response = client.post("/api/preview", data={"source_vendor": "palo_alto", "file": (io.BytesIO(PALO_SOURCE.encode()), "pan.xml")}, content_type="multipart/form-data")
    assert response.status_code == 200
    payload = response.get_json()
    workbook = client.post("/api/extract/excel", json={"source_vendor": "palo_alto", "source": payload["source_evidence"]})
    assert workbook.status_code == 200
    assert b"palo-web-secret" not in response.data + workbook.data


def test_check_point_upload_cached_preview_and_excel_redact_secrets():
    client = create_app({"TESTING": True}).test_client()
    response = client.post("/api/preview", data={"source_vendor": "checkpoint", "file": (io.BytesIO(CHECKPOINT_SOURCE.encode()), "cp.json")}, content_type="multipart/form-data")
    assert response.status_code == 200
    payload = response.get_json()
    workbook = client.post("/api/extract/excel", json={"source_vendor": "checkpoint", "source": payload["source_evidence"]})
    assert workbook.status_code == 200
    assert b"checkpoint-web-secret" not in response.data + workbook.data


def test_fortigate_preview_exposes_policy_fields_and_overview_sections():
    client = create_app({"TESTING": True}).test_client()
    response = client.post(
        "/api/preview",
        data={"source_vendor": "fortigate", "file": (io.BytesIO(FORTIGATE_SOURCE.encode()), "fortigate.conf")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    report = response.get_json()
    policy = report["sections"]["policies"][0]
    assert policy["source_addresses"] == ["all"]
    assert policy["destination_addresses"] == ["all"]
    assert policy["schedule"] == "always"
    assert len(report["sections"]["routes"]) == 1
    assert report["sections"]["vpn_tunnels"] == []
    assert report["sections"]["vpn_phase2"] == []
    assert "unsupported_count" not in report["summary"]


def test_fortigate_preview_preserves_ipv6_policy_addresses():
    source_policy = FortiGateSourceReporter().analyze_source(FORTIGATE_IPV6_POLICY_SOURCE).extracted.config.policies[0]
    assert source_policy.srcaddr is None
    assert source_policy.dstaddr is None
    client = create_app({"TESTING": True}).test_client()
    response = client.post(
        "/api/preview",
        data={"source_vendor": "fortigate", "file": (io.BytesIO(FORTIGATE_IPV6_POLICY_SOURCE.encode()), "fortigate.conf")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    policy = response.get_json()["sections"]["policies"][0]
    assert policy["source_addresses"] == []
    assert policy["source_addresses_ipv6"] == ["SRC-V6"]
    assert policy["destination_addresses"] == []
    assert policy["destination_addresses_ipv6"] == ["DST-V6"]


def test_all_registered_sources_advertise_view_report():
    client = create_app({"TESTING": True}).test_client()
    sources = client.get("/api/vendors").get_json()["sources"]
    assert {item["vendor_id"] for item in sources} >= {
        "fortigate", "palo_alto", "cisco_asa", "cisco_ftd", "checkpoint", "juniper_srx",
    }
    assert all(item["web_report"] is True for item in sources)


def test_api_preview_contract_covers_every_registered_vendor():
    fixtures = Path(__file__).parent / "fixtures"
    cases = (
        ("fortigate", fixtures / "example_fortigate.conf"),
        ("palo_alto", fixtures / "example_palo_alto.xml"),
        ("cisco_asa", fixtures / "example_cisco_asa.cfg"),
        ("cisco_ftd", fixtures / "cisco_ftd" / "fmc_selected_domains.json"),
        ("checkpoint", fixtures / "checkpoint" / "multidomain_full.json"),
        ("juniper_srx", fixtures / "example_juniper_srx.set"),
    )
    required_sections = {"interfaces", "addresses", "address_groups", "services", "service_groups",
                         "schedules", "policies", "nat", "routes", "vpn_tunnels", "vpn_phase2",
                         "validation", "unresolved_references"}
    client = create_app({"TESTING": True}).test_client()
    for vendor, path in cases:
        response = client.post(
            "/api/preview",
            data={"source_vendor": vendor, "file": (io.BytesIO(path.read_bytes()), path.name)},
            content_type="multipart/form-data",
        )
        assert response.status_code == 200, (vendor, response.get_json())
        report = response.get_json()
        assert report["vendor"] == vendor
        assert isinstance(report["summary"]["objects"], dict)
        assert isinstance(report["summary"]["validation"], dict)
        assert required_sections <= set(report["sections"])
        assert all(isinstance(report["sections"][name], list) for name in required_sections)
        json.dumps(report)
        reporter = source_reporters.get(vendor)
        analysis = reporter.analyze_source(path.read_text(encoding="utf-8"))
        before = deepcopy(analysis)
        copied = normalize_web_report(reporter.build_preview(analysis), vendor)
        owned = normalize_web_report(reporter.build_preview(analysis), vendor, copy=False)
        assert owned == copied, vendor
        assert json.loads(json.dumps(owned)) == {key: value for key, value in report.items() if key not in {"success", "source_evidence", "source_digest"}}, vendor
        assert analysis == before, vendor
