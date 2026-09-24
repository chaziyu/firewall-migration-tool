import json

from fwmigrate.extraction.sanitize import sanitize_source_attributes


def test_fmc_secret_fields_are_removed_and_presence_metadata_survives():
    safe = sanitize_source_attributes({
        "password": "pw", "token": "tok", "bindPassword": "ldap", "radiusSecret": "radius",
        "preSharedKey": "psk", "vpnSecret": "vpn", "privateKey": "key",
        "credential": "credential", "eventHubsConnString": "connection-string",
        "preSharedKeyConfigured": True, "privateKeyPresent": True,
    })
    for secret in ("pw", "tok", "ldap", "radius", "psk", "vpn", "key", "credential", "connection-string"):
        assert secret not in [value for key, value in safe.items() if key not in {"preSharedKeyConfigured", "privateKeyPresent"}]
    assert safe["preSharedKeyConfigured"] is True
    assert safe["privateKeyPresent"] is True
