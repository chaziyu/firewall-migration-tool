from pathlib import Path


FIXTURES_DIR = Path(__file__).parent / "fixtures"

FORTIGATE_FIXTURE = FIXTURES_DIR / "example_fortigate.conf"
PALO_ALTO_FIXTURE = FIXTURES_DIR / "example_palo_alto.xml"
CISCO_ASA_FIXTURE = FIXTURES_DIR / "example_cisco_asa.cfg"
CHECKPOINT_FIXTURE = FIXTURES_DIR / "example_checkpoint.json"
JUNIPER_SRX_FIXTURE = FIXTURES_DIR / "example_juniper_srx.set"

VENDOR_FIXTURES = {
    "fortigate": FORTIGATE_FIXTURE,
    "palo_alto": PALO_ALTO_FIXTURE,
    "cisco_asa": CISCO_ASA_FIXTURE,
    "checkpoint": CHECKPOINT_FIXTURE,
    "juniper_srx": JUNIPER_SRX_FIXTURE,
}
