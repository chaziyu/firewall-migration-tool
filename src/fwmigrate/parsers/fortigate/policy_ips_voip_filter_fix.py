"""FortiOS 7.4.6 firewall-policy IPS VoIP filter compatibility.

FortiOS 7.4.6 documents ``set ips-voip-filter <name>`` under
``config firewall policy``. Profile-group handling already maps the same CLI
field to ``voip profile``; this extension adds equivalent typed policy parsing,
dependency resolution, and canonical IR reference preservation.

Keep this fix scoped to firewall policies. It deliberately installs after the
Phase 1 DLP policy extension so ``dlp_profile`` remains available.
"""

from typing import Any, Optional

from fwmigrate.parsers.fortigate.policy_dlp_profile_fix import FGPolicyDLPProfile746


class FGPolicyIPSVoIPFilter746(FGPolicyDLPProfile746):
    """Firewall policy source model with the FortiOS 7.4.6 IPS VoIP field."""

    ips_voip_filter: Optional[str] = None


def install_policy_ips_voip_filter_fix(
    parser_module: Any,
    dependencies_module: Any,
    transformer_module: Any,
) -> None:
    """Install typed parsing, dependency resolution, and IR preservation."""

    # parser.py resolves this model global at runtime inside build_model().
    # Subclass the Phase 1 policy model so dlp-profile support remains intact.
    parser_module.FGPolicy = FGPolicyIPSVoIPFilter746

    # Reuse the object-family mapping already established for profile groups:
    # ips-voip-filter -> config voip profile.
    dependencies_module.REFERENCE_RULES[("firewall policy", "ips-voip-filter")] = (
        "voip profile"
    )

    original_resolver = transformer_module.FGToIRTransformer._resolve_security_profile_references

    def _resolve_security_profile_references(self: Any, policy: Any):
        source_references, statuses, unresolved, unresolved_list = original_resolver(
            self, policy
        )

        name = getattr(policy, "ips_voip_filter", None)
        if not name:
            return source_references, statuses, unresolved, unresolved_list

        field = "ips_voip_filter"
        source_references[field] = name
        contexts = {
            item.source_context
            for item in self.fg.structured_source_objects
            if item.source_path == "voip profile" and item.name == name
        }

        if policy.source_context in contexts:
            statuses[field] = "resolved"
        elif contexts:
            statuses[field] = "cross-context"
            unresolved[field] = (
                "exists in other context(s): " + ", ".join(sorted(contexts))
            )
            unresolved_list.append(f"ips-voip-filter:{name}")
        else:
            statuses[field] = "missing"
            unresolved[field] = f"not found in context: {policy.source_context}"
            unresolved_list.append(f"ips-voip-filter:{name}")

        return source_references, statuses, unresolved, unresolved_list

    transformer_module.FGToIRTransformer._resolve_security_profile_references = (
        _resolve_security_profile_references
    )
