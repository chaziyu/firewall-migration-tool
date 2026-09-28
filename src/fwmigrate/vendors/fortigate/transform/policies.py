"""FortiOS firewall-policy semantics for report views."""


def effective_policy_action(action: str | None) -> str:
    """Use the FortiOS deny default when the source action is absent or empty.

    The selected FortiGate CLI reference documents deny for firewall policy.
    Explicit source values are preserved without mutating the source model.
    """
    return action or "deny"
