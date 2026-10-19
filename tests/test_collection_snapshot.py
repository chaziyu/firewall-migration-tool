import json

import pytest

from fwmigrate.collection.contracts import CollectedSource, CollectionPart, CollectionStatus
from fwmigrate.collection.snapshot import make_snapshot, parse_snapshot
from pathlib import Path


def test_snapshot_sanitizes_source_and_rejects_unsafe_metadata():
    source = CollectedSource("cisco_asa", "username admin password 0 do-not-save", "live-cisco-asa.cfg", "ssh")
    snapshot = make_snapshot(source)
    assert "do-not-save" not in json.dumps(snapshot)
    assert parse_snapshot(json.dumps(snapshot).encode()).source_text == snapshot["source_text"]
    snapshot["metadata"] = {"nested": {"api_key": "do-not-save"}}
    with pytest.raises(ValueError):
        parse_snapshot(json.dumps(snapshot).encode())


@pytest.mark.parametrize("source", [
    "interface inside\n description CLI_MARKER\n password SNAPSHOT_SECRET\n",
    (Path(__file__).parent / "fixtures/cisco_ftd/fdm_object_pipeline_conformance.json").read_text(),
    (Path(__file__).parent / "fixtures/cisco_ftd/fdm_nat_pipeline_conformance.json").read_text(),
])
def test_ftd_supported_source_formats_round_trip_sanitized_snapshots(source):
    snapshot = make_snapshot(CollectedSource("cisco_ftd", source, "ftd-source.txt", "offline"))
    restored = parse_snapshot(json.dumps(snapshot).encode())
    assert restored.source_text == snapshot["source_text"]
    assert "SNAPSHOT_SECRET" not in json.dumps(snapshot)
    assert make_snapshot(restored) == snapshot


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


def test_partial_fmc_snapshot_round_trips_part_statuses_and_safe_failure_codes():
    source = CollectedSource("cisco_ftd", json.dumps({"format": "cisco-fmc-rest-export-v1", "objects": {"hosts": [{"id": "h1"}]}}),
        "live-cisco-fmc.json", "https", status=CollectionStatus.PARTIAL,
        parts=(
            CollectionPart("success", "SUCCESS", True, 2), CollectionPart("empty", "EMPTY", True, 0),
            CollectionPart("partial", "PARTIAL", False, 1, "TIMEOUT"),
            CollectionPart("failed", "FAILED", False, 0, "HTTP_API_ERROR"),
        ))
    restored = parse_snapshot(json.dumps(make_snapshot(source)).encode())
    assert restored.status.value == "PARTIAL"
    assert [(part.status, part.complete, part.count, part.failure_reason) for part in restored.parts] == [
        ("SUCCESS", True, 2, None), ("EMPTY", True, 0, None),
        ("PARTIAL", False, 1, "TIMEOUT"), ("FAILED", False, 0, "HTTP_API_ERROR")]


@pytest.mark.parametrize("change", [
    {"format": "fwmigrate-collection-snapshot-v2"},
    {"vendor_id": "palo_alto"},
    {"status": "BROKEN"},
    {"source_text": ""},
    {"parts": [{"name": "bad", "status": "secret-value", "complete": True}]},
    {"metadata": {"multi_context": "true"}},
    {"metadata": {"multi_context": 1}},
    {"vendor_id": "juniper_srx", "metadata": {"multi_context": True}},
])
def test_invalid_snapshot_is_rejected(change):
    snapshot = make_snapshot(CollectedSource("cisco_asa", "hostname asa", "live-cisco-asa.cfg", "ssh"))
    snapshot.update(change)
    with pytest.raises(ValueError):
        parse_snapshot(json.dumps(snapshot).encode())
