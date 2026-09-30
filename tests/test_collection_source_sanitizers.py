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
