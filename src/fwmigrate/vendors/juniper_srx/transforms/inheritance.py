"""Read-only configuration-group effective statements."""

from copy import deepcopy

from ..extraction import is_sensitive_key, sanitize_tokens
from ..group_resolver import resolve_group_commands
from ..tokenizer import JunosActivationState


_GROUP_ERRORS = {
    "GROUP_NOT_FOUND", "GROUP_CYCLE", "GROUP_RECURSION_DEPTH_EXCEEDED",
    "GROUP_HIERARCHY_INCOMPATIBLE", "GROUP_EXCLUDED", "GROUP_INACTIVE",
}
_SCALAR_FIELDS = {"description", "action", "class", "hostname", "host-name", "mtu", "routing-instance",
                  "instance-type", "scheduler-name", "bind-interface", "proposal-set", "ike-policy",
                  "ipsec-policy", "version", "protocol"}


def _safe_candidate(candidate):
    result = dict(candidate)
    provenance = dict(result.get("provenance") or {})
    source_path = tuple(provenance.get("source_path") or ())
    for key in ("source_path", "target_path"):
        if provenance.get(key) is not None:
            provenance[key] = tuple(sanitize_tokens(list(provenance[key])))
    result["provenance"] = provenance
    for key in ("source_path", "target_path"):
        if result.get(key) is not None:
            result[key] = tuple(sanitize_tokens(list(result[key])))
    field_key = result.get("field_key")
    if is_sensitive_key(str(field_key or "")) or any(is_sensitive_key(str(token)) for token in source_path[:-1]):
        result["value"] = "[REDACTED]"
    elif isinstance(result.get("value"), (tuple, list)):
        result["value"] = tuple(sanitize_tokens(list(result["value"])))
    return result


def build_inheritance_view(source_commands=()) -> dict:
    """Resolve groups on private copies and retain local/inherited candidate status."""
    source_commands = tuple(source_commands)
    commands = deepcopy(list(source_commands))
    if not commands:
        return {"effective_statements": (), "candidates": (), "issues": ()}

    resolved = resolve_group_commands(commands)
    activation = JunosActivationState()
    activation.apply(deepcopy(tuple(source_commands)))
    local_paths = {tuple(command.tokens[1:-1]) for command in source_commands
                   if command.operation.value == "set" and "groups" not in command.tokens[1:]
                   and len(command.tokens) > 3 and command.tokens[-2].lower() in _SCALAR_FIELDS}
    inherited_winners = {}
    statements = []
    issues = []

    def scope_for(command, path):
        if command.context_type and command.context_type != "root":
            return f"{command.context_type} {command.context_name}"
        if len(path) > 1 and path[0].lower() in {"logical-systems", "tenants"}:
            prefix = "logical-system" if path[0].lower() == "logical-systems" else "tenant"
            return f"{prefix} {path[1]}"
        return "root"

    for command in resolved:
        path = tuple(sanitize_tokens(list(command.target_path or command.tokens[1:])))
        scope = scope_for(command, path)
        if command.synthetic:
            active = not activation.is_inactive(path)
            scalar = len(path) > 1 and path[-2].lower() in _SCALAR_FIELDS
            overridden = scalar and path[:-1] in local_paths
            winner_key = (scope, path[:-1])
            status = "INACTIVE" if not active else "SHADOWED" if overridden else "EFFECTIVE"
            if active and scalar and not overridden:
                previous = inherited_winners.get(winner_key)
                if previous is not None:
                    statements[previous]["status"] = "SHADOWED"
                inherited_winners[winner_key] = len(statements)
            statements.append({
                "context": scope,
                "target_path": path,
                "source_path": tuple(sanitize_tokens(list(command.source_group_path or ()))),
                "value": path[-1] if path else None,
                "origin": "inherited-group",
                "source_group": command.source_group,
                "group_chain": tuple(command.source_group_chain),
                "source_order": command.source_order or command.line_number,
                "status": status,
                "active": active,
            })
        if command.group_resolution in _GROUP_ERRORS:
            target_path = tuple(sanitize_tokens(list(command.target_path or ())))
            issue = {"status": command.group_resolution,
                     "context": scope_for(command, target_path or command.tokens[1:]),
                     "target_path": target_path, "source_order": command.line_number}
            if issue not in issues:
                issues.append(issue)
    for command in source_commands:
        if command.operation.value != "set" or "groups" in command.tokens[1:]:
            continue
        path = tuple(sanitize_tokens(command.tokens[1:]))
        active = not activation.is_inactive(path)
        statements.append({"context": scope_for(command, path), "target_path": path,
                           "source_path": path, "value": path[-1] if path else None,
                           "origin": "local", "source_group": None, "group_chain": (),
                           "source_order": command.source_order or command.line_number,
                           "status": "EFFECTIVE" if active else "INACTIVE", "active": active})
    candidates = tuple(_safe_candidate(candidate) for command in resolved for candidate in command.candidate_records)
    return {"effective_statements": tuple(statements), "candidates": candidates, "issues": tuple(issues)}
