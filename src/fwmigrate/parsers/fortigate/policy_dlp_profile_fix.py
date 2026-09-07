"""FortiOS 7.4.6 firewall-policy DLP profile compatibility.

FortiOS 7.4.6 documents ``set dlp-profile <name>`` under
``config firewall policy``.  The historical FortiGate source model exposes
``dlp_sensor`` instead, so the documented field would otherwise fall through
to ``extra_settings`` and would not participate in typed dependency handling.

Keep this fix scoped to firewall policies.  Existing ``dlp_sensor`` handling is
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
) -> None:
    """Install typed ``dlp-profile`` parsing and dependency resolution.

    ``parser.py`` resolves ``FGPolicy`` from its module globals at runtime in
    ``build_model()``, matching the extension pattern already used by other
    FortiGate preservation fixes.
    """

    parser_module.FGPolicy = FGPolicyDLPProfile746

    # FortiOS 7.4.6: firewall policy -> dlp-profile -> config dlp profile.
    # The dependency resolver accepts the source CLI field name as the key and
    # the referenced FortiGate object section as the value.
    dependencies_module.REFERENCE_RULES[("firewall policy", "dlp-profile")] = (
        "dlp profile"
    )
