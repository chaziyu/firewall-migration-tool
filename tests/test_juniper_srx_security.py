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


def test_juniper_srx_identifier_names_matching_secret_keywords_not_redacted():
    """Verify that objects named 'password', 'secret', etc. are not falsely redacted."""
    content = """
    set version 21.4R1.12
    set system host-name SRX-Name-Test
    set security address-book global address password 10.0.0.10/32
    set security address-book global address secret 10.0.0.20/32
    set security address-book global address-set password-hosts address password
    set security address-book global address-set password-hosts address secret
    set security zones security-zone password interfaces ge-0/0/0.0
    """
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    # Address 'password' must have its real prefix preserved without [REDACTED]
    addr_pwd = next(a for a in ir.addresses if a.name == "password")
    assert addr_pwd.value == "10.0.0.10/32"
    assert addr_pwd.value != "[REDACTED]"

    addr_sec = next(a for a in ir.addresses if a.name == "secret")
    assert addr_sec.value == "10.0.0.20/32"

    aset = next(g for g in ir.address_groups if g.name == "password-hosts")
    assert "password" in aset.members
    assert "secret" in aset.members

    zone = next(z for z in ir.zones if z.name == "password")
    assert "ge-0/0/0.0" in zone.interfaces

    assert_no_silent_loss(res, total_input_commands=7)


def test_juniper_srx_dynamic_source_attributes_keys_sanitization():
    """Verify that unparsed tokens in handlers cannot leak plaintext secrets through dictionary keys."""
    secret_in_key = "MySecretLeakedToken999"
    content = f"""
    set version 21.4R1.12
    set system host-name SRX-Key-Sanitize
    set security ike proposal prop1 custom-unparsed-secret secret "{secret_in_key}"
    set routing-options custom-bgp-secret password "{secret_in_key}"
    set schedulers scheduler sched1 custom-sched-secret password "{secret_in_key}"
    set security zones security-zone trust custom-zone-secret secret "{secret_in_key}"
    """
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)

    assert_no_secret_leak(res, [secret_in_key])
