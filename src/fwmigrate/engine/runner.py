import os
import sys
import re
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, Generator

from fwmigrate.core.base_generator import MigrationArtifact
from fwmigrate.engine.binary_manager import TerraformBinaryManager


def redact_sensitive(text: str, secrets: Optional[List[str]] = None) -> str:
    """Mask credentials and sensitive strings in Terraform command output and logs."""
    if not text:
        return ""

    redacted = text

    # Redact explicitly provided secret strings
    if secrets:
        for sec in secrets:
            if sec and len(sec) >= 3:
                redacted = redacted.replace(sec, "******")

    # Generic patterns for API keys and passwords
    redacted = re.sub(
        r'((?:api_key|password|psk|secret|key)\s*=\s*["\'])([^"\']+)(["\'])',
        r'\1******\3',
        redacted,
        flags=re.IGNORECASE
    )
    redacted = re.sub(
        r'((?:key=|password=|psksecret=))([^\s&]+)',
        r'\1******',
        redacted,
        flags=re.IGNORECASE
    )

    return redacted


class TerraformSandbox:
    """
    Manages isolated filesystem directories for executing Terraform runs.
    """

    def __init__(self, session_id: str, base_dir: Optional[Path] = None):
        self.session_id = session_id
        if base_dir:
            self.sandbox_dir = Path(base_dir) / session_id
        elif getattr(sys, 'frozen', False):
            exe_dir = Path(sys.executable).parent
            self.sandbox_dir = exe_dir / "scratch" / "sessions" / session_id
        else:
            # Default to <repo_root>/scratch/sessions/<session_id>
            repo_root = Path(__file__).resolve().parents[3]
            self.sandbox_dir = repo_root / "scratch" / "sessions" / session_id

    def create(
        self,
        artifacts: List[MigrationArtifact],
        tfvars: Optional[Dict[str, Any]] = None
    ) -> Path:
        """
        Creates sandbox directory and writes generated Terraform files and variable values.
        """
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)

        # 1. Write migration artifacts (.tf files)
        for art in artifacts:
            file_path = self.sandbox_dir / art.filename
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(art.content)

        # 2. Write terraform.tfvars if parameters provided
        if tfvars:
            tfvars_content = []
            tfvars_content.append("# Generated session variables\n")
            for k, v in tfvars.items():
                if v is None:
                    continue
                if isinstance(v, bool):
                    val_str = "true" if v else "false"
                elif isinstance(v, (int, float)):
                    val_str = str(v)
                else:
                    # Escape string
                    escaped = str(v).replace('\\', '\\\\').replace('"', '\\"')
                    val_str = f'"{escaped}"'
                tfvars_content.append(f'{k} = {val_str}\n')

            tfvars_path = self.sandbox_dir / "terraform.tfvars"
            with open(tfvars_path, "w", encoding="utf-8") as f:
                f.writelines(tfvars_content)

        return self.sandbox_dir

    def cleanup(self) -> None:
        """Removes the sandbox directory and its contents."""
        if self.sandbox_dir.exists():
            shutil.rmtree(self.sandbox_dir, ignore_errors=True)


class TerraformRunner:
    """
    Executes Terraform workflow commands (init, plan, apply, destroy) with real-time log streaming.
    """

    def __init__(
        self,
        sandbox_dir: Path,
        terraform_path: Optional[Path] = None,
        secrets: Optional[List[str]] = None
    ):
        self.sandbox_dir = Path(sandbox_dir)
        self.secrets = secrets or []

        if terraform_path:
            self.binary_path = Path(terraform_path)
        else:
            bin_mgr = TerraformBinaryManager()
            self.binary_path = bin_mgr.get_or_download()

    def run_init(self, timeout: int = 180) -> Tuple[bool, str]:
        """Runs `terraform init -no-color`."""
        cmd = [str(self.binary_path), "init", "-no-color"]
        try:
            proc = subprocess.run(
                cmd,
                cwd=self.sandbox_dir,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            raw_output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
            output = redact_sensitive(raw_output, self.secrets)
            return (proc.returncode == 0, output)
        except subprocess.TimeoutExpired:
            return (False, f"Terraform init timed out after {timeout}s")
        except Exception as e:
            return (False, f"Failed to execute terraform init: {e}")

    def run_plan(self, plan_file: str = "tfplan", timeout: int = 300) -> Tuple[bool, str, Dict[str, int]]:
        """
        Runs `terraform plan -no-color -out=<plan_file>`.
        Returns (success, log_output, summary_dict).
        """
        cmd = [str(self.binary_path), "plan", "-no-color", f"-out={plan_file}"]
        summary = {"add": 0, "change": 0, "destroy": 0}

        try:
            proc = subprocess.run(
                cmd,
                cwd=self.sandbox_dir,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            raw_output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
            output = redact_sensitive(raw_output, self.secrets)

            # Parse plan summary
            # Example: Plan: 12 to add, 0 to change, 0 to destroy.
            match = re.search(r"Plan:\s+(\d+)\s+to add,\s+(\d+)\s+to change,\s+(\d+)\s+to destroy", output)
            if match:
                summary["add"] = int(match.group(1))
                summary["change"] = int(match.group(2))
                summary["destroy"] = int(match.group(3))
            elif "No changes. Your infrastructure matches the configuration." in output:
                summary = {"add": 0, "change": 0, "destroy": 0}

            return (proc.returncode == 0, output, summary)
        except subprocess.TimeoutExpired:
            return (False, f"Terraform plan timed out after {timeout}s", summary)
        except Exception as e:
            return (False, f"Failed to execute terraform plan: {e}", summary)

    def run_apply_stream(
        self,
        plan_file: Optional[str] = "tfplan"
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Runs `terraform apply` and yields live output events for SSE streaming.
        """
        if plan_file and (self.sandbox_dir / plan_file).exists():
            cmd = [str(self.binary_path), "apply", "-no-color", "-auto-approve", plan_file]
        else:
            cmd = [str(self.binary_path), "apply", "-no-color", "-auto-approve"]

        yield {"event": "status", "message": f"Starting live deployment: {' '.join(cmd)}"}

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=self.sandbox_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            if proc.stdout:
                for line in proc.stdout:
                    clean_line = redact_sensitive(line.rstrip(), self.secrets)
                    if clean_line:
                        yield {"event": "log", "line": clean_line}

            proc.wait()

            success = (proc.returncode == 0)
            if success:
                backup_path = self.backup_state()
                backup_msg = f" (State backed up to {backup_path.name})" if backup_path else ""
                yield {
                    "event": "complete",
                    "success": True,
                    "exit_code": 0,
                    "message": f"Terraform apply completed successfully!{backup_msg}"
                }
            else:
                yield {
                    "event": "complete",
                    "success": False,
                    "exit_code": proc.returncode,
                    "message": f"Terraform apply failed with exit code {proc.returncode}"
                }

        except Exception as e:
            yield {
                "event": "error",
                "success": False,
                "message": f"Execution error during terraform apply: {e}"
            }

    def run_destroy_stream(self) -> Generator[Dict[str, Any], None, None]:
        """
        Runs `terraform destroy` with live log streaming.
        """
        cmd = [str(self.binary_path), "destroy", "-no-color", "-auto-approve"]
        yield {"event": "status", "message": f"Starting teardown: {' '.join(cmd)}"}

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=self.sandbox_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            if proc.stdout:
                for line in proc.stdout:
                    clean_line = redact_sensitive(line.rstrip(), self.secrets)
                    if clean_line:
                        yield {"event": "log", "line": clean_line}

            proc.wait()
            success = (proc.returncode == 0)

            yield {
                "event": "complete",
                "success": success,
                "exit_code": proc.returncode,
                "message": "Terraform destroy completed successfully" if success else f"Destroy failed with exit code {proc.returncode}"
            }
        except Exception as e:
            yield {
                "event": "error",
                "success": False,
                "message": f"Execution error during terraform destroy: {e}"
            }

    def backup_state(self) -> Optional[Path]:
        """Creates a timestamped backup copy of terraform.tfstate."""
        state_path = self.sandbox_dir / "terraform.tfstate"
        if not state_path.exists():
            return None

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_path = self.sandbox_dir / f"terraform.tfstate.backup_{timestamp}"
        try:
            shutil.copy2(state_path, backup_path)
            return backup_path
        except Exception:
            return None

    def get_state_content(self) -> Optional[str]:
        """Returns the raw content of terraform.tfstate if it exists."""
        state_path = self.sandbox_dir / "terraform.tfstate"
        if state_path.exists():
            try:
                with open(state_path, "r", encoding="utf-8") as f:
                    return f.read()
            except Exception:
                return None
        return None
