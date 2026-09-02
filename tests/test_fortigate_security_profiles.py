from pathlib import Path

from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def test_phase0_security_profile_fixture_preserves_source_sections():
    fixture = Path(__file__).parent / "fixtures" / "fortigate" / "security_profiles_full.conf"
    result = extract_fortigate_config(fixture.read_text())
    paths = {section.path for section in result.source_sections}
    assert {
        "ips sensor",
        "antivirus profile",
        "webfilter profile",
        "dnsfilter profile",
        "application list",
        "dlp sensor",
        "firewall ssl-ssh-profile",
    } <= paths
