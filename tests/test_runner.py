import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from fwmigrate.engine.runner import redact_sensitive, TerraformSandbox, TerraformRunner
from fwmigrate.core.base_generator import MigrationArtifact


def test_redact_sensitive():
    sample_text = """
    panos_password = "my_super_secret_password"
    panos_api_key = "LUFRPT14Mk5...secret"
    Connecting with key=ABCDEF123456 and password=pass999
    """
    redacted = redact_sensitive(sample_text, secrets=["my_super_secret_password"])
    assert "my_super_secret_password" not in redacted
    assert "ABCDEF123456" not in redacted
    assert "pass999" not in redacted
    assert "******" in redacted


def test_sandbox_create_and_cleanup(tmp_path):
    sandbox = TerraformSandbox(session_id="test_session_123", base_dir=tmp_path)
    artifacts = [
        MigrationArtifact(filename="main.tf", content="# main", format="terraform"),
        MigrationArtifact(filename="provider.tf", content="# provider", format="terraform")
    ]
    tfvars = {
        "panos_hostname": "10.0.0.1",
        "panos_username": "admin",
        "panos_password": "secret_password"
    }

    dir_path = sandbox.create(artifacts, tfvars=tfvars)
    assert dir_path.exists()
    assert (dir_path / "main.tf").read_text() == "# main"
    assert (dir_path / "provider.tf").read_text() == "# provider"
    
    tfvars_content = (dir_path / "terraform.tfvars").read_text()
    assert 'panos_hostname = "10.0.0.1"' in tfvars_content
    assert 'panos_password = "secret_password"' in tfvars_content

    sandbox.cleanup()
    assert not dir_path.exists()


def test_runner_run_init(tmp_path):
    runner = TerraformRunner(sandbox_dir=tmp_path, terraform_path=Path("fake_terraform"))

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "Terraform has been successfully initialized!"
    mock_proc.stderr = ""

    with patch("subprocess.run", return_value=mock_proc):
        success, output = runner.run_init()
        assert success is True
        assert "initialized" in output


def test_runner_run_plan_parse_summary(tmp_path):
    runner = TerraformRunner(sandbox_dir=tmp_path, terraform_path=Path("fake_terraform"))

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = """
    Terraform used the selected providers to generate the following execution plan.
    Plan: 45 to add, 2 to change, 0 to destroy.
    """
    mock_proc.stderr = ""

    with patch("subprocess.run", return_value=mock_proc):
        success, output, summary = runner.run_plan()
        assert success is True
        assert summary["add"] == 45
        assert summary["change"] == 2
        assert summary["destroy"] == 0


def test_runner_run_apply_stream(tmp_path):
    runner = TerraformRunner(
        sandbox_dir=tmp_path,
        terraform_path=Path("fake_terraform"),
        secrets=["super_secret"]
    )

    mock_popen = MagicMock()
    mock_popen.returncode = 0
    mock_popen.stdout = iter([
        "panos_address_object.addr1: Creating...\n",
        "panos_address_object.addr1: Creation complete after 1s\n",
        "Apply complete! Resources: 1 added, 0 changed, 0 destroyed.\n"
    ])
    mock_popen.wait.return_value = 0

    # Create dummy state file for backup verification
    (tmp_path / "terraform.tfstate").write_text('{"version": 4}')

    with patch("subprocess.Popen", return_value=mock_popen):
        events = list(runner.run_apply_stream())
        assert len(events) >= 3
        
        # Check that log events streamed
        log_events = [e for e in events if e.get("event") == "log"]
        assert any("Creating..." in l["line"] for l in log_events)
        
        # Check completion
        complete_event = next(e for e in events if e.get("event") == "complete")
        assert complete_event["success"] is True
        assert complete_event["exit_code"] == 0

        # Check state backup created
        backup_files = list(tmp_path.glob("terraform.tfstate.backup_*"))
        assert len(backup_files) == 0
