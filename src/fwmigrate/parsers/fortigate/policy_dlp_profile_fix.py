"""FortiOS 7.4.6 firewall-policy DLP profile compatibility.

FortiOS 7.4.6 documents ``set dlp-profile <name>`` under
``config firewall policy``. The historical FortiGate policy model exposes
``dlp_sensor`` instead, so the documented field would otherwise fall through
to ``extra_settings`` and would not participate in typed dependency handling.

Keep this fix scoped to firewall policies. Existing ``dlp_sensor`` handling is
left intact for backward compatibility with older/legacy inputs.
"""

from typing import Any, Optional

from fwmigrate.parsers.fortigate.model import FGPolicy


class FGPolicyDLPProfile746(FGPolicy):
    """Firewall policy source model with the FortiOS 7.4.6 DLP field."""

    dlp_profile: Optional[str] = None


def install_policy_dlp_profile_fix(
    parser_module: Any,
    dependencies_module: Any,
    transformer_module: Any,
) -> None:
    """Install typed parsing, dependency resolution, and IR preservation."""

    # parser.py resolves this model global at runtime inside build_model().
    # This follows the same extension pattern used by the existing FortiGate
    # policy/NAT preservation module and avoids changing unrelated model code.
    parser_module.FGPolicy = FGPolicyDLPProfile746

    # FortiOS 7.4.6: firewall policy -> dlp-profile -> config dlp profile.
    dependencies_module.REFERENCE_RULES[("firewall policy", "dlp-profile")] = (
        "dlp profile"
    )

    original_resolver = transformer_module.FGToIRTransformer._resolve_security_profile_references

    def _resolve_security_profile_references(self: Any, policy: Any):
        source_references, statuses, unresolved, unresolved_list = original_resolver(
            self, policy
        )

        name = getattr(policy, "dlp_profile", None)
        if not name:
            return source_references, statuses, unresolved, unresolved_list

        field = "dlp_profile"
        source_references[field] = name
        contexts = {
            item.source_context
            for item in self.fg.structured_source_objects
            if item.source_path == "dlp profile" and item.name == name
        }

        if policy.source_context in contexts:
            statuses[field] = "resolved"
        elif contexts:
            statuses[field] = "cross-context"
            unresolved[field] = (
                "exists in other context(s): " + ", ".join(sorted(contexts))
            )
            unresolved_list.append(f"dlp:{name}")
        else:
            statuses[field] = "missing"
            unresolved[field] = f"not found in context: {policy.source_context}"
            unresolved_list.append(f"dlp:{name}")

        return source_references, statuses, unresolved, unresolved_list

    transformer_module.FGToIRTransformer._resolve_security_profile_references = (
        _resolve_security_profile_references
    )
