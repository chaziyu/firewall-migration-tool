import pytest
from pathlib import Path
from click.testing import CliRunner
from fg2pan.main import cli

def test_full_migration(tmp_path):
    # Setup test file from real example
    base_dir = Path(__file__).parent.parent
    fg_conf_path = base_dir / "examples" / "example_fortigate.conf"
    
    assert fg_conf_path.exists(), "Test requires examples/example_fortigate.conf"
    
    out_dir = tmp_path / "output"
    report_file = tmp_path / "report.md"
    
    runner = CliRunner()
    result = runner.invoke(cli, [
        "migrate",
        "-i", str(fg_conf_path),
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
