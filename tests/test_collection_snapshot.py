import json

import pytest

from fwmigrate.collection.contracts import CollectedSource
from fwmigrate.collection.snapshot import make_snapshot, parse_snapshot


def test_snapshot_sanitizes_source_and_rejects_unsafe_metadata():
    source = CollectedSource("cisco_asa", "username admin password 0 do-not-save", "live-cisco-asa.cfg", "ssh")
    snapshot = make_snapshot(source)
    assert "do-not-save" not in json.dumps(snapshot)
    assert parse_snapshot(json.dumps(snapshot).encode()).source_text == snapshot["source_text"]
    snapshot["metadata"] = {"nested": {"api_key": "do-not-save"}}
    with pytest.raises(ValueError):
        parse_snapshot(json.dumps(snapshot).encode())


def test_structured_snapshot_redacts_auth_headers_and_session_cookies():
    source = CollectedSource("cisco_ftd", json.dumps({
        "format": "cisco-fmc-rest-export-v1", "source": "fmc-rest-api", "objects": {
            "hosts": [{"name": "h", "Authorization": "secret-token", "Set-Cookie": "secret-session",
                       "nested": [[{"password": "deep-secret"}]]}]},
        "access_policies": [], "nat_policies": [],
    }), "live-cisco-fmc.json", "https")
    snapshot = make_snapshot(source)
    assert "secret-token" not in json.dumps(snapshot)
    assert "secret-session" not in json.dumps(snapshot)
    assert "deep-secret" not in json.dumps(snapshot)


@pytest.mark.parametrize("change", [
    {"format": "fwmigrate-collection-snapshot-v2"},
    {"vendor_id": "palo_alto"},
    {"status": "BROKEN"},
    {"source_text": ""},
    {"parts": [{"name": "bad", "status": "secret-value", "complete": True}]},
])
def test_invalid_snapshot_is_rejected(change):
    snapshot = make_snapshot(CollectedSource("cisco_asa", "hostname asa", "live-cisco-asa.cfg", "ssh"))
    snapshot.update(change)
    with pytest.raises(ValueError):
        parse_snapshot(json.dumps(snapshot).encode())
