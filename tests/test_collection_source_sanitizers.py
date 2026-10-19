import json

import pytest

from fwmigrate.collection.snapshot import sanitize_source


def test_vendor_source_sanitizers_keep_format_and_remove_credentials():
    for vendor, bundle_format in (("cisco_ftd", "cisco-fmc-rest-export-v1"),
                                  ("checkpoint", "checkpoint-export-v1")):
        source = json.dumps({"format": bundle_format, "nested": [{"password": "secret"}]})
        safe = sanitize_source(vendor, source)
        assert json.loads(safe)["format"] == bundle_format
        assert "secret" not in safe
        with pytest.raises(ValueError):
            sanitize_source(vendor, json.dumps({"format": "other"}))


def test_junos_sanitizer_preserves_ntp_key_id_and_redacts_key_value():
    safe = sanitize_source("juniper_srx", "set system ntp server 192.0.2.1 key 7\n"
                           "set security ike gateway gw pre-shared-key secret")
    assert "key 7" in safe
    assert "secret" not in safe


def test_unsupported_collected_source_fails_closed():
    with pytest.raises(ValueError):
        sanitize_source("palo_alto", "hostname edge")


@pytest.mark.parametrize("bundle_format", ["cisco-fmc-rest-export-v1", "cisco-fdm-rest-export-v1"])
def test_ftd_sanitizer_preserves_bundle_identity_and_nested_raw_evidence(bundle_format):
    payload = {"format": bundle_format, "objects": {"hosts": [{"name": "Host", "custom": "MARKER",
        "apiToken": "TOKEN_SECRET", "nested": [[{"raw_lines": ["password RAW_SECRET"]}]]}]}}
    safe = sanitize_source("cisco_ftd", json.dumps(payload))
    assert json.loads(safe)["format"] == bundle_format
    assert "MARKER" in safe and "TOKEN_SECRET" not in safe and "RAW_SECRET" not in safe
    assert sanitize_source("cisco_ftd", safe) == safe


def test_ftd_sanitizer_recognizes_cli_and_keeps_unsupported_sections():
    source = "interface outside\n description MARKER\n password CLI_SECRET\naccess-list ACL extended permit ip any any\n"
    safe = sanitize_source("cisco_ftd", source)
    assert "MARKER" in safe and "access-list ACL" in safe and "CLI_SECRET" not in safe
    assert sanitize_source("cisco_ftd", safe) == safe


@pytest.mark.parametrize("source", [
    "", "unrecognized text", "{}", "[]", "null", '"interface inside"',
    '{"format":"cisco-fdm-rest-export-v1",\ninterface inside',
    '[\ninterface inside', '{"format":"other"}',
])
def test_ftd_sanitizer_rejects_invalid_json_and_unrecognized_text(source):
    with pytest.raises(ValueError):
        sanitize_source("cisco_ftd", source)
