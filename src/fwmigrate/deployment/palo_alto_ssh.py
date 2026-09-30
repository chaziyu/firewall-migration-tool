"""Optional, explicit candidate deployment for Palo Alto."""

import re
import time

from .models import (PANCommitResult, PANDeploymentCommandResult, PANDeploymentOptions,
                     PANDeploymentResult, PANValidationResult)
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import RenderedMigration


_ERROR = re.compile(
    r"(?im)^\s*(?:invalid\b|error\b|failed\b|server error\b|syntax error\b|"
    r"unknown command\b|not valid\b|validation error\b)|"
    r"\b(?:validation|commit)\s+failed\b|\bis (?:invalid|not (?:a )?valid)\b"
)
_JOB = re.compile(r"(?:job(?:id)?|id)\s*[:=]?\s*(\d+)", re.I)


def _safe_text(value, password):
    text = "" if value is None else str(value)
    return text.replace(password, "<redacted>") if password else text


class PANSSHDeployer:
    def __init__(self, options: PANDeploymentOptions):
        self.options = options
        self.connection = None

    def connect(self):
        try:
            from netmiko import ConnectHandler
        except ImportError as exc:
            raise RuntimeError("SSH deployment requires optional dependency netmiko") from exc
        self.connection = ConnectHandler(device_type="paloalto_panos", host=self.options.host,
                                         port=self.options.port, username=self.options.username,
                                         password=self.options.password,
                                         ssh_strict=True, system_host_keys=True)
        return self

    def push_candidate(self, rendered: RenderedMigration):
        if not isinstance(rendered, RenderedMigration):
            raise TypeError("deployment requires a RenderedMigration")
        if not rendered.commands:
            return PANDeploymentResult(True, failure_message="The rendered migration has no commands to deploy")
        results = []
        try:
            self.connection.config_mode()
        except Exception as exc:
            return PANDeploymentResult(True, failure_message=_safe_text(f"config mode failed: {exc}", self.options.password))
        for index, command in enumerate(rendered.commands):
            safe_command = _safe_text(command, self.options.password)
            try:
                response = _safe_text(self.connection.send_config_set(
                    [command], exit_config_mode=False, strip_command=True, strip_prompt=True,
                ), self.options.password)
            except Exception as exc:
                response = _safe_text(str(exc), self.options.password)
                results.append(PANDeploymentCommandResult(index, safe_command, False, response))
                return PANDeploymentResult(True, len(results), sum(item.accepted for item in results), index,
                                           f"command {index} failed: {response}", tuple(results))
            # Some transports retain echo despite strip_command; discard only this command.
            diagnostics = "\n".join(line for line in response.splitlines()
                                    if line.strip() != safe_command
                                    and not line.strip().endswith(("> " + safe_command, "# " + safe_command)))
            accepted = not bool(_ERROR.search(diagnostics))
            results.append(PANDeploymentCommandResult(index, safe_command, accepted, response))
            if not accepted:
                return PANDeploymentResult(True, len(results), sum(item.accepted for item in results), index,
                                           f"command {index} rejected: {response or 'command rejected'}", tuple(results))
        return PANDeploymentResult(True, len(results), len(results), command_results=tuple(results))

    def _poll_job(self, job_id):
        attempts = max(1, int(self.options.job_poll_attempts))
        interval = max(0.0, float(self.options.job_poll_interval))
        last = ""
        for attempt in range(attempts):
            last = _safe_text(
                self.connection.send_command(f"show jobs id {job_id}"),
                self.options.password,
            )
            if _ERROR.search(last or ""):
                return "FAILED", last
            if re.search(r"\bFIN\b", last or "", re.I):
                status = (
                    "SUCCESS"
                    if re.search(r"(?:\bOK\b|\bsuccess(?:ful)?\b)", last or "", re.I)
                    else "FAILED"
                )
                return status, last
            if attempt + 1 < attempts and interval:
                time.sleep(interval)
        return "TIMEOUT", last or f"job {job_id} did not reach FIN"

    def validate_candidate(self):
        self.connection.config_mode()
        try:
            response = _safe_text(self.connection.send_command("validate full"), self.options.password)
        finally:
            self.connection.exit_config_mode()
        match = _JOB.search(response or "")
        job_id = match.group(1) if match else None
        if not job_id:
            return PANValidationResult(None, "FAILED", response or "validation job ID missing")
        status, result = self._poll_job(job_id)
        return PANValidationResult(job_id, status, result or response or "")

    def _commit_candidate(self):
        response = _safe_text(self.connection.commit(), self.options.password)
        if _ERROR.search(response or ""):
            return PANCommitResult(None, "FAILED", response or "")
        match = _JOB.search(response or "")
        job_id = match.group(1) if match else None
        if not job_id:
            status = "SUCCESS" if re.search(r"\bsuccess(?:ful)?\b|\bOK\b", response or "", re.I) else "FAILED"
            return PANCommitResult(None, status, response or "commit job ID missing")
        status, result = self._poll_job(job_id)
        return PANCommitResult(job_id, status, result or response or "")

    def deploy(self, rendered: RenderedMigration):
        if not isinstance(rendered, RenderedMigration):
            raise TypeError("deployment requires a RenderedMigration")
        if not rendered.commands:
            return PANDeploymentResult(False, failure_message="The rendered migration has no commands to deploy")
        plan_status = rendered.report.get("plan_status")
        if plan_status != "READY":
            return PANDeploymentResult(
                False,
                failure_message=(
                    "Candidate deployment requires a READY migration artifact; "
                    f"current status is {plan_status or 'UNKNOWN'}"
                ),
            )
        try:
            self.connect()
        except Exception as exc:
            return PANDeploymentResult(False, failure_message=_safe_text(exc, self.options.password))
        try:
            pushed = self.push_candidate(rendered)
            if pushed.failure_message is not None or pushed.failed_command_index is not None:
                return pushed
            try:
                validation = self.validate_candidate() if self.options.validate else PANValidationResult()
            except Exception as exc:
                validation = PANValidationResult(None, "FAILED", _safe_text(exc, self.options.password))
            failure_message = pushed.failure_message
            if self.options.validate and validation.status != "SUCCESS":
                failure_message = f"candidate validation {validation.status.lower()}"
            return PANDeploymentResult(pushed.connected, pushed.commands_attempted, pushed.commands_succeeded,
                                       pushed.failed_command_index, failure_message, pushed.command_results,
                                       validation)
        finally:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            finally:
                self.connection = None

    def commit(self):
        try:
            self.connect()
        except Exception as exc:
            return PANCommitResult(None, "FAILED", _safe_text(exc, self.options.password))
        try:
            return self._commit_candidate()
        except Exception as exc:
            return PANCommitResult(None, "FAILED", _safe_text(exc, self.options.password))
        finally:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            finally:
                self.connection = None

    def validate(self):
        try:
            self.connect()
        except Exception as exc:
            return PANValidationResult(None, "FAILED", _safe_text(exc, self.options.password))
        try:
            return self.validate_candidate()
        except Exception as exc:
            return PANValidationResult(None, "FAILED", _safe_text(exc, self.options.password))
        finally:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            finally:
                self.connection = None


def deploy_set_commands(rendered: RenderedMigration, options: PANDeploymentOptions) -> PANDeploymentResult:
    return PANSSHDeployer(options).deploy(rendered)
