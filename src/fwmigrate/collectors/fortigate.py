from __future__ import annotations

import re
from typing import Callable, Optional, Tuple

from fwmigrate.collectors.base import BaseSourceCollector
from fwmigrate.collectors.models import ConnectionResult, SourceSnapshot

try:
    import paramiko
except ImportError:  # pragma: no cover - surfaced as a clear runtime error
    paramiko = None


_STATUS_COMMAND = "get system status"
_CONFIG_COMMAND = "show full-configuration"
_PAGER_MARKERS = ("--More--", "<space> to continue", "Press any key to continue")
_ERROR_MARKERS = ("command fail", "unknown action", "parse error", "permission denied")


class FortiGateSSHCollector(BaseSourceCollector):
    """Read-only FortiGate configuration collector over SSH.

    A non-PTY exec channel is used intentionally so the collector does not alter
    persistent FortiOS console paging settings on the source device.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        timeout: int = 20,
        verify_host_key: bool = False,
        ssh_client_factory: Optional[Callable[[], object]] = None,
    ) -> None:
        self.host = host.strip()
        self.username = username
        self.password = password
        self.port = int(port)
        self.timeout = int(timeout)
        self.verify_host_key = verify_host_key
        self._ssh_client_factory = ssh_client_factory

    def _new_client(self):
        if self._ssh_client_factory is not None:
            return self._ssh_client_factory()
        if paramiko is None:
            raise RuntimeError(
                "FortiGate live collection requires paramiko. Install the project dependencies first."
            )
        return paramiko.SSHClient()

    def _connect(self):
        if not self.host or not self.username:
            raise ValueError("FortiGate host and username are required.")
        client = self._new_client()
        if hasattr(client, "load_system_host_keys"):
            client.load_system_host_keys()
        if paramiko is not None and hasattr(client, "set_missing_host_key_policy"):
            policy = paramiko.RejectPolicy() if self.verify_host_key else paramiko.AutoAddPolicy()
            client.set_missing_host_key_policy(policy)
        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            auth_timeout=self.timeout,
            banner_timeout=self.timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        return client

    @staticmethod
    def _decode(data) -> str:
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="strict")
        return str(data or "")

    def _exec(self, client, command: str) -> Tuple[str, str]:
        _stdin, stdout, stderr = client.exec_command(
            command,
            timeout=self.timeout,
            get_pty=False,
        )
        out = self._decode(stdout.read())
        err = self._decode(stderr.read())
        return out.replace("\r\n", "\n"), err.replace("\r\n", "\n")

    @staticmethod
    def _parse_status(text: str) -> tuple[Optional[str], Optional[str]]:
        hostname = None
        version = None
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("hostname:"):
                hostname = stripped.split(":", 1)[1].strip() or None
            elif stripped.lower().startswith("version:"):
                version = stripped.split(":", 1)[1].strip() or None
        return hostname, version

    @staticmethod
    def _config_completeness(raw_config: str, stderr: str) -> tuple[bool, list[str], list[str]]:
        warnings: list[str] = []
        errors: list[str] = []
        lowered = raw_config.lower()
        stderr_lower = stderr.lower()

        if not raw_config.strip():
            errors.append("FortiGate returned an empty full-configuration response.")
        if any(marker.lower() in lowered for marker in _PAGER_MARKERS):
            errors.append("Paging markers were detected; the configuration snapshot is incomplete.")
        if any(marker in lowered for marker in _ERROR_MARKERS):
            errors.append("FortiGate CLI error text was detected in the configuration response.")
        if stderr.strip():
            errors.append(f"FortiGate SSH command returned stderr: {stderr.strip()[:500]}")
        if any(marker in stderr_lower for marker in _ERROR_MARKERS):
            errors.append("FortiGate reported a CLI execution failure.")
        if raw_config.strip() and not re.search(r"(?m)^config\s+", raw_config):
            warnings.append("No top-level 'config' statement was found in the returned text.")
        if "config system global" not in lowered:
            warnings.append("'config system global' was not observed; verify administrator permissions and VDOM scope.")

        return not errors, warnings, errors

    def test_connection(self) -> ConnectionResult:
        client = None
        try:
            client = self._connect()
            status, stderr = self._exec(client, _STATUS_COMMAND)
            hostname, version = self._parse_status(status)
            warnings = []
            if stderr.strip():
                warnings.append(stderr.strip()[:500])
            return ConnectionResult(
                success=True,
                vendor="fortigate",
                hostname=hostname,
                software_version=version,
                message="FortiGate SSH connection succeeded.",
                warnings=warnings,
            )
        except Exception as exc:
            return ConnectionResult(
                success=False,
                vendor="fortigate",
                message=str(exc),
            )
        finally:
            if client is not None:
                client.close()

    def collect(self) -> SourceSnapshot:
        client = self._connect()
        try:
            status, status_err = self._exec(client, _STATUS_COMMAND)
            hostname, version = self._parse_status(status)
            raw_config, config_err = self._exec(client, _CONFIG_COMMAND)
            complete, warnings, errors = self._config_completeness(raw_config, config_err)
            if status_err.strip():
                warnings.append(f"System status stderr: {status_err.strip()[:500]}")
            return SourceSnapshot(
                vendor="fortigate",
                hostname=hostname,
                software_version=version,
                raw_config=raw_config,
                collection_method="ssh",
                commands_executed=[_STATUS_COMMAND, _CONFIG_COMMAND],
                complete=complete,
                warnings=warnings,
                errors=errors,
            )
        finally:
            client.close()
