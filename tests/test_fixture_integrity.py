from pathlib import Path


FIXTURE_ROOT = Path(__file__).parent / "fixtures"


REQUIRED_FIXTURES = [
    FIXTURE_ROOT / "fortigate" / "security_profiles_full.conf",
    FIXTURE_ROOT / "fortigate" / "fortios_7_4_6_ssl_vpn_full.conf",
]


def test_required_fortigate_fixtures_exist():
    missing = [str(path) for path in REQUIRED_FIXTURES if not path.is_file()]
    assert not missing, f"Missing required test fixtures: {missing}"
