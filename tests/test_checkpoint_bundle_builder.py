import json

from fwmigrate.parsers.checkpoint.bundle_builder import build_checkpoint_bundle


def test_offline_bundle_builder_preserves_scope_and_pagination(tmp_path):
    page = tmp_path / "hosts_page_1.json"
    page.write_text(json.dumps({
        "command": "show hosts", "from": 1, "to": 1, "total": 2,
        "objects": [{"uid": "h1", "name": "Host1", "type": "host", "ipv4-address": "10.0.0.1"}],
    }), encoding="utf-8")
    bundle = build_checkpoint_bundle(
        [page], domain="D1", package="Standard", layer="Network", gateway="GW1"
    )
    assert bundle["format"] == "checkpoint-export-v1"
    response = bundle["responses"][0]
    assert response["command"] == "show-hosts"
    assert (response["from"], response["to"], response["total"]) == (1, 1, 2)
    assert response["domain"] == "D1"


def test_offline_bundle_builder_records_failed_input_explicitly(tmp_path):
    broken = tmp_path / "show-hosts.json"
    broken.write_text("not-json", encoding="utf-8")
    bundle = build_checkpoint_bundle([broken])
    response = bundle["responses"][0]
    assert response["collection_status"] == "ERROR"
    assert response["data"] == {}
    assert response["error"]
