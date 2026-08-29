from fwmigrate.core.registry import PluginRegistry
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_vpn_extraction_and_secret_redaction():
    fixture_path = JUNIPER_FIXTURES_DIR / "vpn.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    vpn_dict = {v.name: v for v in ir.vpn_tunnels}
    assert "vpn_to_branch" in vpn_dict
    vpn = vpn_dict["vpn_to_branch"]
    assert vpn.local_interface == "st0.1"
    assert vpn.peer_address == "203.0.113.10"
    assert vpn.has_psk is True
    # Verify entire ExtractionResult serialization has zero secret leaks
    serialized = res.model_dump_json()
    assert "SecretKey123!" not in serialized
    assert "[REDACTED]" in serialized

    assert_no_silent_loss(res, total_input_commands=24)
