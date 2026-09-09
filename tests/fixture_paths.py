from pathlib import Path


FIXTURES_DIR = Path(__file__).parent / "fixtures"

FORTIGATE_FIXTURE = FIXTURES_DIR / "example_fortigate.conf"
PALO_ALTO_FIXTURE = FIXTURES_DIR / "example_palo_alto.xml"
CISCO_ASA_FIXTURE = FIXTURES_DIR / "example_cisco_asa.cfg"
CHECKPOINT_FIXTURE = FIXTURES_DIR / "checkpoint" / "minimal_bundle.json"
CHECKPOINT_AMBIGUOUS_FIXTURE = FIXTURES_DIR / "checkpoint" / "legacy_ambiguous_rulebase.json"
CHECKPOINT_GOLDEN_FIXTURE = FIXTURES_DIR / "checkpoint" / "r81_golden_matrix.json"
JUNIPER_SRX_FIXTURE = FIXTURES_DIR / "example_juniper_srx.set"
JUNIPER_FIXTURES_DIR = FIXTURES_DIR / "juniper"

VENDOR_FIXTURES = {
    "fortigate": FORTIGATE_FIXTURE,
    "palo_alto": PALO_ALTO_FIXTURE,
    "cisco_asa": CISCO_ASA_FIXTURE,
    "checkpoint": CHECKPOINT_FIXTURE,
    "juniper_srx": JUNIPER_SRX_FIXTURE,
}
