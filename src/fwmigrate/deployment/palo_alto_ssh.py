"""Optional, explicit candidate deployment for Palo Alto."""

import re

from .models import (PANCommitResult, PANDeploymentCommandResult, PANDeploymentOptions,
                     PANDeploymentResult, PANValidationResult)
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import RenderedMigration


_ERROR = re.compile(r"(?:invalid|error|failed|unknown command|not valid)", re.I)
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
                                         password=self.options.password)
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
                response = _safe_text(self.connection.send_config_set([command]), self.options.password)
            except Exception as exc:
                response = _safe_text(str(exc), self.options.password)
                results.append(PANDeploymentCommandResult(index, safe_command, False, response))
                return PANDeploymentResult(True, len(results), sum(item.accepted for item in results), index,
                                           f"command {index} failed: {response}", tuple(results))
            accepted = not bool(_ERROR.search(response))
            results.append(PANDeploymentCommandResult(index, safe_command, accepted, response))
            if not accepted:
                return PANDeploymentResult(True, len(results), sum(item.accepted for item in results), index,
                                           f"command {index} rejected: {response or 'command rejected'}", tuple(results))
        return PANDeploymentResult(True, len(results), len(results), command_results=tuple(results))

    def validate_candidate(self):
        response = _safe_text(self.connection.send_command("validate full"), self.options.password)
        match = _JOB.search(response or "")
        job_id = match.group(1) if match else None
        if not job_id:
            return PANValidationResult(None, "FAILED", response or "validation job ID missing")
        result = _safe_text(self.connection.send_command(f"show jobs id {job_id}"), self.options.password)
        status = "SUCCESS" if not _ERROR.search(result or "") and re.search(r"(?:FIN|success|ok)", result or "", re.I) else "FAILED"
        return PANValidationResult(job_id, status, result or response or "")

    def commit_candidate(self):
        response = _safe_text(self.connection.commit(), self.options.password)
        match = _JOB.search(response or "")
        status = "FAILED" if _ERROR.search(response or "") else "SUCCESS"
        return PANCommitResult(match.group(1) if match else None, status, response or "")

    def deploy(self, rendered: RenderedMigration):
        if not isinstance(rendered, RenderedMigration):
            raise TypeError("deployment requires a RenderedMigration")
        if not rendered.commands:
            return PANDeploymentResult(False, failure_message="The rendered migration has no commands to deploy")
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
            try:
                commit = self.commit_candidate() if self.options.commit and validation.status == "SUCCESS" else PANCommitResult()
            except Exception as exc:
                commit = PANCommitResult(None, "FAILED", _safe_text(exc, self.options.password))
            return PANDeploymentResult(pushed.connected, pushed.commands_attempted, pushed.commands_succeeded,
                                       pushed.failed_command_index, pushed.failure_message, pushed.command_results,
                                       validation, commit)
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
            return self.commit_candidate()
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
