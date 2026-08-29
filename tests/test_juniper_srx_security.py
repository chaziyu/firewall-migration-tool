"""Comprehensive security, secret redaction, and serialization tests for Juniper SRX."""

from typing import Sequence
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def assert_no_secret_leak(result: ExtractionResult, secret_values: Sequence[str]) -> None:
    """Assert that none of the secret plaintext strings appear anywhere in the serialized ExtractionResult."""
    serialized = result.model_dump_json()
    for secret in secret_values:
        assert secret not in serialized, f"Plaintext secret '{secret}' was leaked in serialized ExtractionResult JSON"


def test_juniper_srx_complete_secret_sanitization_and_no_leak():
    secret_psk = "SuperSecretIKEPsk123"
    secret_snmp = "SuperSecretCommunity999"
    secret_root_enc = "$6$secretEncryptedHashValue"
    secret_radius = "RadiusSecretPhrase456"
    secret_tacacs = "TacacsServerSecret789"
    secret_custom = "UnknownPasswordCustom111"

    content = f"""
    set version 21.4R1.12
    set system host-name SRX-Secret-Audit
    
    # 1. Supported IKE PSK
    set security ike proposal prop1 authentication-method pre-shared-keys
    set security ike policy pol1 mode main proposals prop1
    set security ike policy pol1 pre-shared-key ascii-text "{secret_psk}"
    
    # 2. Unsupported SNMP community
    set snmp community "{secret_snmp}" authorization read-only
    
    # 3. Root password
    set system root-authentication encrypted-password "{secret_root_enc}"
    
    # 4. RADIUS server secret
    set system radius-server 10.0.0.1 secret "{secret_radius}"
    
    # 5. TACACS server secret
    set system tacplus-server 10.0.0.2 secret "{secret_tacacs}"
    
    # 6. Unknown hierarchy with password keyword
    set custom-hierarchy auth-system password "{secret_custom}"
    """

    all_secrets = [
        secret_psk,
        secret_snmp,
        secret_root_enc,
        secret_radius,
        secret_tacacs,
        secret_custom,
    ]

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)

    # 1. Zero secret leak in ExtractionResult JSON
    assert_no_secret_leak(res, all_secrets)

    # 2. Zero secret leak in parse_raw() config model JSON
    raw_parser = JuniperSRXParser(content)
    raw_cfg = raw_parser.parse_raw()
    raw_serialized = raw_cfg.model_dump_json()
    for secret in all_secrets:
        assert secret not in raw_serialized, f"Plaintext secret '{secret}' was leaked in raw config serialization"

    # 3. Check unsupported items have safe names
    for item in res.unsupported_items:
        for secret in all_secrets:
            assert secret not in item.source_name
            assert secret not in item.raw_capture

    # 4. Zero silent loss: all commands classified
    assert_no_silent_loss(res, total_input_commands=10)
