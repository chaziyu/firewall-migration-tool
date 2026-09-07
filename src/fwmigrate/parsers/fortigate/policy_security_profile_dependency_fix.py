"""FortiOS 7.4.6 firewall-policy security-profile dependency coverage.

The policy source model already types most FortiOS 7.4.6 security-profile
references, but historically only a subset participated in dependency and IR
reference accounting.  Reuse the existing profile-group object-family map,
while applying an explicit policy-field allow-list so profile-group-only
relationships are never copied into firewall policies by inference.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from fwmigrate.parsers.fortigate.phase_46_50_extensions import (
    PROFILE_GROUP_REFERENCE_RULES,
)


# FortiOS 7.4.6 firewall-policy security-profile reference fields covered by
# the existing typed policy model.  Keep this list explicit: do not infer that
# every profile-group field is necessarily valid on a firewall policy.
POLICY_SECURITY_PROFILE_CLI_FIELDS = frozenset(
    {
        "application-list",
        "av-profile",
        "casb-profile",
        "cifs-profile",
        "diameter-filter-profile",
        "dlp-profile",
        "dnsfilter-profile",
        "emailfilter-profile",
        "file-filter-profile",
        "icap-profile",
        "ips-sensor",
        "ips-voip-filter",
        "profile-protocol-options",
        "sctp-filter-profile",
        "ssh-filter-profile",
        "ssl-ssh-profile",
        "videofilter-profile",
        "virtual-patch-profile",
        "voip-profile",
        "waf-profile",
        "webfilter-profile",
    }
)


def _policy_profile_rules(parser_module: Any) -> Dict[str, Tuple[str, str]]:
    """Return active typed policy fields as ``attr -> (cli field, source section)``."""

    model_fields = parser_module.FGPolicy.model_fields
    rules: Dict[str, Tuple[str, str]] = {}
    for cli_field in POLICY_SECURITY_PROFILE_CLI_FIELDS:
        target = PROFILE_GROUP_REFERENCE_RULES.get(cli_field)
        if target is None:
            continue
        attr = cli_field.replace("-", "_")
        if attr in model_fields:
            rules[attr] = (cli_field, target)
    return rules


def install_policy_security_profile_dependency_fix(
    parser_module: Any,
    dependencies_module: Any,
    transformer_module: Any,
) -> None:
    """Install complete policy-level profile dependency/reference accounting."""

    active_rules = _policy_profile_rules(parser_module)

    # Register only fields that are both explicitly valid for firewall policy
    # and present on the active policy model.  Exact target sections avoid the
    # broader aliases used by some legacy dependency families.
    for _attr, (cli_field, target) in active_rules.items():
        dependencies_module.REFERENCE_RULES.setdefault(
            ("firewall policy", cli_field), target
        )
        dependencies_module.REFERENCE_TARGET_SECTIONS.setdefault(
            ("firewall policy", cli_field), {target}
        )

    original_resolver = transformer_module.FGToIRTransformer._resolve_security_profile_references
    if getattr(original_resolver, "_policy_security_profile_dependency_wrapped", False):
        return

    def _resolve_security_profile_references(self: Any, policy: Any):
        source_references, statuses, unresolved, unresolved_list = original_resolver(
            self, policy
        )

        for attr, (cli_field, target) in active_rules.items():
            name = getattr(policy, attr, None)
            if not name or attr in source_references:
                # Earlier/core resolvers remain authoritative for fields they
                # already cover, including Phase 1 DLP and Phase 2 IPS/VoIP.
                continue

            source_references[attr] = name
            contexts = {
                item.source_context
                for item in self.fg.structured_source_objects
                if item.source_path == target and item.name == name
            }

            marker = f"{cli_field}:{name}"
            if policy.source_context in contexts:
                statuses[attr] = "resolved"
                unresolved.pop(attr, None)
            elif contexts:
                statuses[attr] = "cross-context"
                unresolved[attr] = (
                    "exists in other context(s): " + ", ".join(sorted(contexts))
                )
                if marker not in unresolved_list:
                    unresolved_list.append(marker)
            else:
                statuses[attr] = "missing"
                unresolved[attr] = f"not found in context: {policy.source_context}"
                if marker not in unresolved_list:
                    unresolved_list.append(marker)

        return source_references, statuses, unresolved, unresolved_list

    _resolve_security_profile_references._policy_security_profile_dependency_wrapped = True
    transformer_module.FGToIRTransformer._resolve_security_profile_references = (
        _resolve_security_profile_references
    )
