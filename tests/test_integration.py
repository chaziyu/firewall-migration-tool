import pytest
from click.testing import CliRunner
from fwmigrate.main import cli
from tests.fixture_paths import FORTIGATE_FIXTURE

def test_full_migration(tmp_path):
    assert FORTIGATE_FIXTURE.exists(), f"Test requires {FORTIGATE_FIXTURE}"
    
    out_dir = tmp_path / "output"
    report_file = tmp_path / "report.md"
    
    runner = CliRunner()
    result = runner.invoke(cli, [
        "migrate",
        "-i", str(FORTIGATE_FIXTURE),
        "-o", str(out_dir),
        "--format", "xml",
        "--report", str(report_file)
    ])
    
    assert result.exit_code == 0
    assert "Migration complete!" in result.output
    
    # Check outputs
    xml_out = out_dir / "palo_alto_config.xml"
    assert xml_out.exists()
    assert report_file.exists()
    
    # Verify XML content roughly
    xml_text = xml_out.read_text(encoding='utf-8')
    assert "<config version=\"11.1.0\"" in xml_text
    assert "<devices>" in xml_text
    
    # Verify Unified Report content
    report_text = report_file.read_text(encoding='utf-8')
    assert "Firewall Migration & Configuration Report" in report_text
    assert "Executive Summary & Migration Health" in report_text
    assert "Total Processed Objects" in report_text
    assert "Network Architecture & Zones" in report_text
    assert "Object Inventory" in report_text
    assert "Rulebase & Policies" in report_text
    assert "Security Policies" in report_text
    assert "NAT Rules" in report_text
