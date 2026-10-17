"""Supported target command baseline, separate from source defaults."""


def profile_findings(options):
    expected = {"fortios_version": "7.4.6", "operating_mode": "nat", "ngfw_mode": "profile-based"}
    findings = [f"Explicit supported target profile required: {key}={value}." for key, value in expected.items() if options.profile.get(key) != value]
    if options.profile.get("nat_mode") not in {"central", "policy"}:
        findings.append("Choose the target NAT mode explicitly.")
    if options.profile.get("vdom_mode") not in {"single", "multi"}:
        findings.append("Choose single or multi VDOM command scope explicitly.")
    if options.profile.get("vdom_mode") == "single" and options.vdom != "root":
        findings.append("Single VDOM output requires an explicit root VDOM selection.")
    if not options.vdom:
        findings.append("Choose the target VDOM explicitly.")
    return tuple(findings)
