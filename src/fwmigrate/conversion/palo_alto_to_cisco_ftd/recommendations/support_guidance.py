"""Pair-owned support guidance for PAN-OS to Cisco FTD."""

SUPPORT_LIMITS = (
    "Explicit FMC REST API 7.7.0 requests for hosts, networks, ranges, network groups, port objects, port groups, security zones, and access policies are supported.",
    "Target security zone to FTD device interface assignment must be confirmed manually.",
    "Active NAT, App-ID, scheduled policies, and intrusion/file inspection profiles remain blocked or manual.",
    "Output request specifications and shell scripts do not authenticate, push to device, or deploy policies.",
)
