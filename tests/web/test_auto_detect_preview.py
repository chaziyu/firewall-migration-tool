import io

from fwmigrate.web import create_app


FORTIGATE_SAMPLE = b"""config system interface
    edit "port1"
        set ip 192.0.2.1 255.255.255.0
    next
end
"""

PALO_SAMPLE = b'<config><shared><address><entry name="web"><ip-netmask>203.0.113.10</ip-netmask></entry></address></shared></config>'


def test_preview_auto_detects_fortigate_conf_and_cfg():
    client = create_app({"TESTING": True}).test_client()
    for ext in ("conf", "cfg"):
        response = client.post(
            "/api/preview",
            data={"source_vendor": "auto", "file": (io.BytesIO(FORTIGATE_SAMPLE), f"edge.{ext}")},
            content_type="multipart/form-data",
        )
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["success"] is True
        assert payload["vendor"] == "fortigate"
        assert payload["source_evidence"]["vendor"] == "fortigate"


def test_preview_auto_detects_palo_alto_xml_and_txt_xml():
    client = create_app({"TESTING": True}).test_client()
    for name in ("panorama.xml", "running-config.txt"):
        response = client.post(
            "/api/preview",
            data={"source_vendor": "auto", "file": (io.BytesIO(PALO_SAMPLE), name)},
            content_type="multipart/form-data",
        )
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["success"] is True
        assert payload["vendor"] == "palo_alto"
        assert payload["source_evidence"]["vendor"] == "palo_alto"


def test_preview_auto_detects_fortigate_txt():
    client = create_app({"TESTING": True}).test_client()
    response = client.post(
        "/api/preview",
        data={"source_vendor": "auto", "file": (io.BytesIO(FORTIGATE_SAMPLE), "fgt-backup.txt")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["vendor"] == "fortigate"


def test_preview_auto_rejects_unsupported_extension():
    client = create_app({"TESTING": True}).test_client()
    response = client.post(
        "/api/preview",
        data={"source_vendor": "auto", "file": (io.BytesIO(b"PK\x03\x04"), "techsupport.zip")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    payload = response.get_json()
    assert payload["success"] is False
    assert "auto-detect" in payload["error"].lower()
