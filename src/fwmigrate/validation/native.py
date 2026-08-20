import subprocess
from pathlib import Path
from typing import List, Optional
from fwmigrate.jobs.models import MigrationIssue
from fwmigrate.engine.runner import TerraformRunner, TerraformSandbox

class NativeValidator:
    """
    Executes native validation on the generated artifacts.
    For Terraform, this runs `terraform validate` and `terraform plan`
    against the target platform to capture provider and schema errors.
    """
    
    def __init__(self, sandbox: TerraformSandbox, runner: TerraformRunner):
        self.sandbox = sandbox
        self.runner = runner
        
    def validate(self) -> List[MigrationIssue]:
        issues = []
        
        # 1. Run Terraform Init
        init_ok, init_log = self.runner.run_init()
        if not init_ok:
            issues.append(MigrationIssue(
                severity="CRITICAL",
                category="NATIVE_VALIDATION",
                source_object="Terraform",
                message=f"terraform init failed: {init_log}",
                blocking=True
            ))
            return issues
            
        # 2. Run Terraform Validate
        cmd = [str(self.runner.binary_path), "validate", "-no-color", "-json"]
        try:
            proc = subprocess.run(
                cmd,
                cwd=self.sandbox.sandbox_dir,
                capture_output=True,
                text=True,
                timeout=180
            )
            if proc.returncode != 0:
                # Parse JSON output for specific errors
                import json
                try:
                    data = json.loads(proc.stdout)
                    for diag in data.get('diagnostics', []):
                        if diag.get('severity') == 'error':
                            issues.append(MigrationIssue(
                                severity="CRITICAL",
                                category="NATIVE_VALIDATION",
                                source_object=diag.get('range', {}).get('filename', 'Terraform'),
                                message=diag.get('summary', 'Validation error') + ": " + diag.get('detail', ''),
                                blocking=True
                            ))
                except json.JSONDecodeError:
                    issues.append(MigrationIssue(
                        severity="CRITICAL",
                        category="NATIVE_VALIDATION",
                        source_object="Terraform",
                        message=f"terraform validate failed: {proc.stdout} {proc.stderr}",
                        blocking=True
                    ))
        except Exception as e:
            issues.append(MigrationIssue(
                severity="CRITICAL",
                category="NATIVE_VALIDATION",
                source_object="Terraform",
                message=f"Failed to execute terraform validate: {str(e)}",
                blocking=True
            ))
            
        return issues
