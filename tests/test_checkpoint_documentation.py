import re
from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.checkpoint.coverage import CHECKPOINT_COVERAGE_SECTIONS


MATRIX = Path(__file__).parents[1] / "documentation" / "CHECKPOINT_SUPPORT_MATRIX.md"


def test_checkpoint_support_matrix_uses_live_sections_and_statuses():
    text = MATRIX.read_text(encoding="utf-8")
    statuses = {status.value for status in ExtractionStatus}
    classifications = {
        "IMPLEMENTABLE_NOW", "SOURCE_DATA_MISSING", "VENDOR_SPECIFIC_NONPORTABLE",
        "OPERATIONAL_ONLY", "INTENTIONALLY_UNSUPPORTED", "NEEDS_FUTURE_IR_DESIGN",
    }
    rows = [line for line in text.splitlines() if line.startswith("|") and "---" not in line]
    assert rows
    for row in rows[1:]:
        columns = [part.strip() for part in row.strip("|").split("|")]
        assert len(columns) == 7
        assert columns[1] in CHECKPOINT_COVERAGE_SECTIONS
        assert columns[2] in statuses
        assert columns[3] in classifications


def test_checkpoint_support_matrix_has_required_audit_areas():
    text = MATRIX.read_text(encoding="utf-8")
    for area in (
        "Network and", "Policy packages", "VPN communities", "LDAP",
        "Threat Prevention", "HTTPS Inspection", "ClusterXL", "SecureXL",
        "Certificates", "Multi-Domain", "Collector contract",
    ):
        assert re.search(re.escape(area), text, re.IGNORECASE)
