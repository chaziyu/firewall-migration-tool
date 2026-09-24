"""Cisco ASA source validation."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any

from .derived import ASADerivedViews


@dataclass(frozen=True)
class ASAValidationIssue:
    severity: str
    category: str
    message: str
    source_context: str | None = None
    source_object: str | None = None


@dataclass(frozen=True)
class ASAValidationResult:
    issues: tuple[ASAValidationIssue, ...] = ()

    @property
    def errors(self) -> tuple[ASAValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "error")

    @property
    def warnings(self) -> tuple[ASAValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "warning")


def validate_asa_config(config: Any, derived: ASADerivedViews) -> ASAValidationResult:
    issues = [ASAValidationIssue(
        severity="error" if not item.resolved else "warning",
        category=item.reference_type,
        message=item.reason,
        source_context=item.source_context,
        source_object=item.source_object,
    ) for item in derived.relationship_issues if not item.resolved]
    issues.extend(ASAValidationIssue(
        severity="error",
        category="parse",
        message=item.reason,
        source_object=item.object_name,
    ) for item in config.diagnostics)
    issues.extend(ASAValidationIssue(
        severity="warning",
        category="unsupported",
        message=item["reason"],
        source_object=f"line {item.get('line_number', '')}".strip(),
    ) for item in config.unsupported_commands)
    issues.extend(ASAValidationIssue("warning", item.category, item.message,
                                     item.source_context, item.source_object)
                  for item in derived.transform_issues)
    for server in getattr(config, "dhcp_servers", ()):
        if (server.pool or server.enabled) and not server.interface:
            issues.append(ASAValidationIssue("warning", "dhcp", "DHCP server configuration has no explicit interface", server.source_context, server.name))
    pool_owners = {}
    for server in getattr(config, "dhcp_servers", ()):
        if server.pool and server.interface:
            key = (server.source_context, server.pool)
            pool_owners.setdefault(key, set()).add(server.interface)
    for (context, pool), interfaces in pool_owners.items():
        if len(interfaces) > 1:
            issues.append(ASAValidationIssue("warning", "dhcp", f"DHCP pool {pool} is assigned to multiple interfaces", context, pool))
    for interface in getattr(config, "interfaces", ()):
        for monitor in getattr(interface, "policy_route_path_monitors", ()):
            if monitor.mode == "peer":
                try:
                    ipaddress.ip_address(monitor.peer or "")
                except ValueError:
                    issues.append(ASAValidationIssue("warning", "policy-routing", "Path-monitor peer is not a valid IP address", interface.source_context, interface.name))
    for privilege in getattr(config, "command_privileges", ()):
        if not 0 <= privilege.privilege_level <= 15:
            issues.append(ASAValidationIssue("warning", "authorization", "Command privilege level must be between 0 and 15", privilege.source_context, privilege.name))
    for user in getattr(config, "local_users", ()):
        if user.privilege is not None and not 0 <= user.privilege <= 15:
            issues.append(ASAValidationIssue("warning", "authorization", "Username privilege level must be between 0 and 15", user.source_context, user.name))
    return ASAValidationResult(tuple(issues))


__all__ = ["ASAValidationIssue", "ASAValidationResult", "validate_asa_config"]

