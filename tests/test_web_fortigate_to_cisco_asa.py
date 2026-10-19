import io
import json
import zipfile

import pytest

from fwmigrate.web import create_app


SOURCE = '''config system interface
edit "inside"
set type physical
set ip 10.0.0.1 255.255.255.0
set status up
next
end
config firewall address
edit "clients"
set type ipmask
set subnet 10.0.0.0 255.255.255.0
next
edit "web"
set type ipmask
set subnet 203.0.113.10 255.255.255.255
next
end
config firewall service custom
edit "https"
set tcp-portrange 443
next
end
config firewall policy
edit 10
set name "allow-https"
set srcintf "inside"
set dstintf "any"
set srcaddr "clients"
set dstaddr "web"
set service "https"
set schedule "always"
set action accept
set nat disable
set nat64 disable
set nat46 disable
set natinbound disable
set natoutbound disable
set srcaddr-negate disable
set dstaddr-negate disable
set service-negate disable
set utm-status disable
set logtraffic disable
set status enable
next
end
'''


def test_asa_api_requires_current_approval_and_serves_exact_artifact_bytes(monkeypatch):
    app = create_app({"TESTING": True, "WORKSPACE_SIGNING_KEY": b"x" * 32})
    client = app.test_client()
    source = {"vendor": "fortigate", "source_text": SOURCE}
    options = {
        "source_vdom": "root", "target_context": "single", "target_version": "9.20", "target_mode": "routed",
        "interfaces": {"root": {"inside": {"interface": "GigabitEthernet0/1", "nameif": "inside", "security_level": 100}}},
    }
    prefix = "/api/migration/fortigate_to_cisco_asa"
    prepared = client.post(prefix + "/design/prepare", json={"source": source, "options": options})
    assert prepared.status_code == 200, prepared.json
    policy = next(item for item in prepared.json["report"]["items"] if item["family"] == "policy")
    approved = client.post(prefix + "/design/approve", json={
        "source": source, "options": options, "draft": prepared.json["draft"],
        "selected_items": [policy["key"]],
    })
    assert approved.status_code == 200, approved.json
    built = client.post(prefix + "/build", json={"source": source, "options": options,
                                                    "approval": approved.json["approval"]})
    assert built.status_code == 200, built.json
    preview = client.post(prefix + "/command-preview", json={"artifact": built.json["artifact"]})
    download = client.post(prefix + "/commands", json={"artifact": built.json["artifact"]})
    assert preview.status_code == 200
    assert download.status_code == 200
    assert download.data.decode("utf-8") == preview.json["text"]
    assert preview.json["command_sha256"] == built.json["artifact"]["command_sha256"]
    bundle = client.post(prefix + "/bundle", json={"source": source, "artifact": built.json["artifact"]})
    assert bundle.status_code == 200
    with zipfile.ZipFile(io.BytesIO(bundle.data)) as archive:
        assert archive.read("asa_config.cfg") == download.data
        assert json.loads(archive.read("migration_report.json")) == built.json["artifact"]["report"]
    import time
    monkeypatch.setattr(time, "time", lambda: built.json["artifact"]["expires_at"] + 1)
    for route in ("command-preview", "commands", "bundle"):
        response = client.post(prefix + "/" + route, json={"source": source, "artifact": built.json["artifact"]})
        assert response.status_code == 400, response.json


@pytest.mark.parametrize("old,new", [
    ("set nat64 disable", "set nat64 enable"),
    ("set nat46 disable", "set nat46 enable"),
    ("set utm-status disable", ""),
])
def test_unsupported_or_unknown_policy_cannot_pass_web_approval(old, new):
    client = create_app({"TESTING": True, "WORKSPACE_SIGNING_KEY": b"x" * 32}).test_client()
    payload = {"source": {"vendor": "fortigate", "source_text": SOURCE.replace(old, new)},
               "options": {"source_vdom": "root", "target_context": "single", "target_version": "9.20", "target_mode": "routed"}}
    prefix = "/api/migration/fortigate_to_cisco_asa"
    prepared = client.post(prefix + "/design/prepare", json=payload)
    assert prepared.status_code == 200
    policy = next(row for row in prepared.json["report"]["items"] if row["family"] == "policy")
    assert policy["render_disposition"] == "BLOCK"
    approved = client.post(prefix + "/design/approve", json={**payload, "draft": prepared.json["draft"], "selected_items": [policy["key"]]})
    assert approved.status_code == 400


def test_asa_artifact_is_rejected_by_panos_deployment_transport():
    app = create_app({"TESTING": True, "WORKSPACE_SIGNING_KEY": b"x" * 32})
    response = app.test_client().post("/api/deploy", json={"artifact": {
        "envelope_type": "fortigate_to_cisco_asa_artifact_v1", "source_vendor": "fortigate",
        "target_vendor": "cisco_asa", "commands": ["hostname asa"],
    }})
    assert response.status_code in {400, 403}
