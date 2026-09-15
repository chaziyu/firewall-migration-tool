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
CISCO_ASA_FIXTURE = FIXTURES_DIR / "example_cisco_asa.cfg"
CISCO_FTD_FIXTURE = FIXTURES_DIR / "cisco_ftd" / "fdm_nat_pipeline_conformance.json"
CHECKPOINT_FIXTURE = FIXTURES_DIR / "checkpoint" / "minimal_bundle.json"
CHECKPOINT_AMBIGUOUS_FIXTURE = FIXTURES_DIR / "checkpoint" / "legacy_ambiguous_rulebase.json"
CHECKPOINT_GOLDEN_FIXTURE = FIXTURES_DIR / "checkpoint" / "r81_golden_matrix.json"
JUNIPER_SRX_FIXTURE = FIXTURES_DIR / "example_juniper_srx.set"
JUNIPER_FIXTURES_DIR = FIXTURES_DIR / "juniper"

VENDOR_FIXTURES = {
    "fortigate": FORTIGATE_FIXTURE,
    "palo_alto": PALO_ALTO_FIXTURE,
    "cisco_asa": CISCO_ASA_FIXTURE,
    "cisco_ftd": CISCO_FTD_FIXTURE,
    "checkpoint": CHECKPOINT_FIXTURE,
    "juniper_srx": JUNIPER_SRX_FIXTURE,
}
