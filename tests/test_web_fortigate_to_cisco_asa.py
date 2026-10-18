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
set logtraffic disable
set status enable
next
end
'''


def test_asa_api_requires_current_approval_and_serves_exact_artifact_bytes():
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


def test_asa_artifact_is_rejected_by_panos_deployment_transport():
    app = create_app({"TESTING": True, "WORKSPACE_SIGNING_KEY": b"x" * 32})
    response = app.test_client().post("/api/deploy", json={"artifact": {
        "envelope_type": "fortigate_to_cisco_asa_artifact_v1", "source_vendor": "fortigate",
        "target_vendor": "cisco_asa", "commands": ["hostname asa"],
    }})
    assert response.status_code in {400, 403}


def test_asa_signed_partial_export_keeps_source_order_and_required_deny():
    client = create_app({"TESTING": True, "WORKSPACE_SIGNING_KEY": b"x" * 32}).test_client()
    prefix, _, policies = SOURCE.partition("config firewall policy\n")
    rule = policies.rsplit("end", 1)[0]
    deny = rule.replace("edit 10", "edit 20").replace("action accept", "action deny")
    payload = {
        "source": {"vendor": "fortigate", "source_text": prefix + "config firewall policy\n" + deny + rule + "end\n"},
        "options": {"source_vdom": "root", "target_context": "single", "target_version": "9.20", "target_mode": "routed",
                    "interfaces": {"root": {"inside": {"interface": "GigabitEthernet0/1", "nameif": "inside", "security_level": 100}}}},
    }
    prefix = "/api/migration/fortigate_to_cisco_asa"
    prepared = client.post(prefix + "/design/prepare", json=payload)
    assert prepared.status_code == 200
    policy = next(item for item in prepared.json["report"]["items"] if item["family"] == "policy" and item["source_name"] == "10")
    approved = client.post(prefix + "/design/approve", json={**payload, "draft": prepared.json["draft"], "selected_items": [policy["key"]]})
    assert approved.status_code == 200
    built = client.post(prefix + "/build", json={**payload, "approval": approved.json["approval"]})
    assert built.status_code == 200
    artifact = built.json["artifact"]
    preview = client.post(prefix + "/command-preview", json={"artifact": artifact})
    download = client.post(prefix + "/commands", json={"artifact": artifact})
    assert preview.status_code == download.status_code == 200
    assert download.data.decode() == preview.json["text"] == artifact["command_text"]
    rules = [line for line in preview.json["text"].splitlines() if " extended " in line]
    assert " extended deny tcp " in rules[0]
    assert " extended permit tcp " in rules[1]
