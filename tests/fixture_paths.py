from pathlib import Path


FIXTURES_DIR = Path(__file__).parent / "fixtures"

FORTIGATE_FIXTURE = FIXTURES_DIR / "example_fortigate.conf"
FORTIGATE_FIXTURES_DIR = FIXTURES_DIR / "fortigate"
FORTIGATE_P0_MIGRATION_CRITICAL_FIXTURE = (
    FORTIGATE_FIXTURES_DIR / "p0_migration_critical.conf"
)
FORTIGATE_P0_EDGE_CASES_FIXTURE = (
    FORTIGATE_FIXTURES_DIR / "p0_edge_cases.conf"
)
PALO_ALTO_FIXTURE = FIXTURES_DIR / "example_palo_alto.xml"
VENDOR_FIXTURES = {
    "fortigate": FORTIGATE_FIXTURE,
    "palo_alto": PALO_ALTO_FIXTURE,
}
