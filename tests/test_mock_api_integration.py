import pytest
import io
from click.testing import CliRunner
from fg2pan.main import cli
from fg2pan.web import create_app

@pytest.fixture
def client():
    app = create_app({'TESTING': True})
    return app.test_client()

def test_cli_vendors_list():
    runner = CliRunner()
    result = runner.invoke(cli, ["vendors"])
    assert result.exit_code == 0
    assert "fortigate" in result.output
    assert "cisco_asa" in result.output
    assert "checkpoint" in result.output
    assert "juniper_srx" in result.output
    assert "palo_alto" in result.output

def test_cli_migrate_cisco_to_palo(tmp_path):
    runner = CliRunner()
    out_dir = tmp_path / "cisco_to_pan"
    report_file = out_dir / "report.md"

    result = runner.invoke(cli, [
        "migrate",
        "-i", "examples/example_cisco_asa.cfg",
        "--source-vendor", "cisco_asa",
        "--target-vendor", "palo_alto",
        "-o", str(out_dir),
        "--format", "terraform",
        "--optimize",
        "--report", str(report_file)
    ])
    assert result.exit_code == 0
    assert (out_dir / "main.tf").exists()
    assert (out_dir / "provider.tf").exists()
    assert report_file.exists()

def test_cli_migrate_palo_alto_to_fortigate(tmp_path):
    runner = CliRunner()
    out_dir = tmp_path / "pan_to_fg"

    result = runner.invoke(cli, [
        "migrate",
        "-i", "examples/example_palo_alto.xml",
        "--source-vendor", "palo_alto",
        "--target-vendor", "fortigate",
        "-o", str(out_dir),
        "--format", "cli"
    ])
    assert result.exit_code == 0
    assert (out_dir / "fortigate_config.conf").exists()

def test_cli_migrate_checkpoint_to_fortigate(tmp_path):
    runner = CliRunner()
    out_dir = tmp_path / "cp_to_fg"

    result = runner.invoke(cli, [
        "migrate",
        "-i", "examples/example_checkpoint.json",
        "--source-vendor", "checkpoint",
        "--target-vendor", "fortigate",
        "-o", str(out_dir),
        "--format", "cli"
    ])
    assert result.exit_code == 0
    assert (out_dir / "fortigate_config.conf").exists()

def test_cli_migrate_fortigate_to_cisco_asa(tmp_path):
    runner = CliRunner()
    out_dir = tmp_path / "fg_to_cisco"

    result = runner.invoke(cli, [
        "migrate",
        "-i", "examples/example_fortigate.conf",
        "--source-vendor", "fortigate",
        "--target-vendor", "cisco_asa",
        "-o", str(out_dir),
        "--format", "cli"
    ])
    assert result.exit_code == 0
    assert (out_dir / "cisco_asa_config.cfg").exists()

def test_cli_migrate_fortigate_to_juniper_srx(tmp_path):
    runner = CliRunner()
    out_dir = tmp_path / "fg_to_srx"

    result = runner.invoke(cli, [
        "migrate",
        "-i", "examples/example_fortigate.conf",
        "--source-vendor", "fortigate",
        "--target-vendor", "juniper_srx",
        "-o", str(out_dir),
        "--format", "set"
    ])
    assert result.exit_code == 0
    assert (out_dir / "junos_srx_config.set").exists()

def test_cli_migrate_fortigate_to_checkpoint(tmp_path):
    runner = CliRunner()
    out_dir = tmp_path / "fg_to_cp"

    result = runner.invoke(cli, [
        "migrate",
        "-i", "examples/example_fortigate.conf",
        "--source-vendor", "fortigate",
        "--target-vendor", "checkpoint",
        "-o", str(out_dir),
        "--format", "cli"
    ])
    assert result.exit_code == 0
    assert (out_dir / "checkpoint_mgmt_cli.sh").exists()

def test_web_api_vendors_endpoint(client):
    resp = client.get('/api/vendors')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    sources = [s['vendor_id'] for s in data['sources']]
    assert 'cisco_asa' in sources
    assert 'juniper_srx' in sources
    targets = [t['vendor_id'] for t in data['targets']]
    assert 'cisco_asa' in targets
    assert 'checkpoint' in targets
    assert 'juniper_srx' in targets

def test_web_api_preview_endpoint(client):
    cfg = "hostname TestASA\nobject network h1\n host 1.1.1.1\n"
    data = {
        'file': (io.BytesIO(cfg.encode('utf-8')), 'test.cfg'),
        'source_vendor': 'cisco_asa'
    }
    resp = client.post('/api/preview', data=data, content_type='multipart/form-data')
    assert resp.status_code == 200
    res_data = resp.get_json()
    assert res_data['success'] is True
    assert res_data['source_vendor'] == 'cisco_asa'
    assert 'stats' in res_data
    assert 'optimization' in res_data
