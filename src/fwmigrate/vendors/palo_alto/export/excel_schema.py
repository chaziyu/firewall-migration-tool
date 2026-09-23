"""PAN-OS-only Excel presentation schema."""

from __future__ import annotations


SHEET_ORDER: tuple[str, ...] = (
    "Summary",
    "Review Required",
    "Validation",

    # Objects
    "Tags",
    "Addresses",
    "Address Groups",
    "Services",
    "Service Groups",
    "Schedules",

    # Policy
    "Security Policies",
    "NAT Rules",

    # Security profiles
    "Vulnerability Profiles",
    "Vulnerability Rules",
    "Vulnerability Exceptions",
    "Security Profile Groups",

    # Network / topology
    "Interfaces",
    "Zones",

    # Routing
    "Virtual Router Routes",
    "Logical Router Routes",
    "Route Path Monitors",

    # DHCP
    "DHCP Servers",
    "DHCP IP Pools",
    "DHCP Reservations",
    "DHCP Options",

    # SD-WAN
    "SD-WAN Interface Profiles",
    "SD-WAN Interface Bindings",
    "SD-WAN Path Quality",
    "SD-WAN Traffic Distribution",
    "SD-WAN Traffic Distribution Links",
    "SD-WAN SaaS Quality",
    "SD-WAN Error Correction",
    "SD-WAN Rules",

    # Users / identity
    "Local Users",
    "Local User Groups",
    "Group Mappings",

    # Administration
    "Administrators",
    "Admin Roles",
    "Admin Role Permissions",

    # IPsec VPN
    "IKE Gateways",
    "IKE Crypto Profiles",
    "IPsec Crypto Profiles",
    "IPsec Tunnels",
    "IPsec Proxy IDs",

    # GlobalProtect
    "GlobalProtect Portals",
    "GP Portal Client Configs",
    "GP Portal Gateway Entries",
    "GP Clientless VPN",
    "GlobalProtect Gateways",
    "GP Gateway Client Auth",
    "GP Remote User Tunnels",

    # Technical / traceability
    "Unresolved References",
    "Unsupported",
    "PAN-OS Source Inventory",
    "Extraction Coverage",
)


SHEET_HEADERS: dict[str, tuple[str, ...]] = {
    "Summary": (),

    "Review Required": (
        "Severity",
        "Category",
        "Object",
        "Scope Type",
        "Scope Name",
        "Field",
        "Issue / Review Reason",
        "Source Sheet",
    ),

    "Validation": (
        "Severity",
        "Domain",
        "Object",
        "Scope Type",
        "Scope Name",
        "Field",
        "Issue / Review Reason",
        "Source Sheet",
    ),

    # ------------------------------------------------------------------
    # Objects
    # ------------------------------------------------------------------

    "Tags": (
        "Name",
        "Color",
        "Comments",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "Addresses": (
        "Name",
        "Type",
        "Value",
        "Tags",
        "Description",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "Address Groups": (
        "Name",
        "Group Type",
        "Static Members",
        "Dynamic Filter",
        "Tags",
        "Description",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "Services": (
        "Name",
        "Protocol",
        "Destination Port",
        "Source Port",
        "Override Enabled",
        "Timeout",
        "Half-Close Timeout",
        "Time-Wait Timeout",
        "Tags",
        "Description",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "Service Groups": (
        "Name",
        "Members",
        "Tags",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "Schedules": (
        "Name",
        "Schedule Type",
        "Daily Entries",
        "Weekly Entries",
        "Non-Recurring Entries",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    # ------------------------------------------------------------------
    # Policy
    # ------------------------------------------------------------------

    "Security Policies": (
        "Source Order",
        "Rulebase Position",
        "Effective Order",
        "Name",
        "Rule Type",
        "From Zones",
        "To Zones",
        "Source Addresses",
        "Source Negate",
        "Source Users",
        "Destination Addresses",
        "Destination Negate",
        "Applications",
        "Services",
        "Categories",
        "Source HIP",
        "Destination HIP",
        "Schedule",
        "Tags",
        "Action",
        "Disabled",
        "ICMP Unreachable",
        "Disable Inspect",
        "Profile Group",
        "URL Filtering",
        "Data Filtering",
        "File Blocking",
        "WildFire Analysis",
        "Antivirus",
        "Anti-Spyware",
        "Vulnerability Profile",
        "Log Setting",
        "Log Start",
        "Log End",
        "Group Tag",
        "Description",
        "Scope Type",
        "Scope Name",
        "Resolved Source References",
        "Resolved Destination References",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "NAT Rules": (
        "Source Order",
        "Rulebase Position",
        "Effective Order",
        "Name",
        "From Zones",
        "To Zones",
        "Source Addresses",
        "Destination Addresses",
        "Service",
        "NAT Type",
        "To Interface",

        "Source Translation Type",
        "Source Translated Addresses",
        "Source Interface Address",
        "Source Interface",
        "Source IP",
        "Source Bi-Directional",

        "Destination Translation Type",
        "Destination Translated Address",
        "Destination Translated Port",
        "Destination DNS Rewrite",
        "DNS Rewrite Direction",

        "Dynamic Destination Address",
        "Dynamic Destination Port",
        "Dynamic Destination Distribution",

        "Derived Source Translation Mode",
        "Derived Destination Translation Mode",
        "Resolved Translation References",

        "Disabled",
        "Tags",
        "Description",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    # ------------------------------------------------------------------
    # Security profiles
    # ------------------------------------------------------------------

    "Vulnerability Profiles": (
        "Name",
        "Rule Count",
        "Exception Count",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "Vulnerability Rules": (
        "Profile",
        "Rule Name",
        "Threat Name",
        "Host",
        "Vendor IDs",
        "Severities",
        "Category",
        "Action",
        "Block IP Track By",
        "Block IP Duration",
        "Packet Capture",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "Vulnerability Exceptions": (
        "Profile",
        "Exception Name",
        "Action",
        "Block IP Track By",
        "Block IP Duration",
        "Packet Capture",
        "Time Interval",
        "Time Threshold",
        "Time Track By",
        "Exempt IP Configuration",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "Security Profile Groups": (
        "Name",
        "Antivirus",
        "Anti-Spyware",
        "Vulnerability",
        "URL Filtering",
        "File Blocking",
        "WildFire Analysis",
        "Data Filtering",
        "GTP",
        "SCTP",
        "AI Security",
        "Disable Override",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    # ------------------------------------------------------------------
    # Interfaces / zones
    # ------------------------------------------------------------------

    "Interfaces": (
        "Name",
        "Kind",
        "Parent Interface",
        "Aggregate Interface",
        "Topology Path",
        "Physical Interfaces",
        "Attached Tunnels",
        "Unit / Subinterface",
        "Layer",
        "IPv4 Addresses",
        "IPv6 Addresses",
        "Imported VSYS",
        "Zone",
        "Virtual Router",
        "Topology Issues",
        "Description",
        "SD-WAN Enabled",
        "IPv6 SD-WAN Enabled",
        "SD-WAN Interface Profile",
        "Upstream NAT",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "Zones": (
        "Name",
        "Network Type",
        "Members",
        "Zone Protection Profile",
        "Packet Buffer Protection",
        "Network Inspection",
        "Pre-NAT User Identification",
        "Pre-NAT Device Identification",
        "Pre-NAT Source Policy Lookup",
        "Pre-NAT Source IP Downstream",
        "Log Setting",
        "User Identification",
        "Device Identification",
        "User ACL Include",
        "User ACL Exclude",
        "Device ACL Include",
        "Device ACL Exclude",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    "Virtual Router Routes": (
        "Virtual Router",
        "Route Name",
        "Address Family",
        "Destination",
        "Next Hop Type",
        "Next Hop",
        "Interface",
        "Admin Distance",
        "Metric",
        "Route Table",
        "BFD Profile",
        "Path Monitor Enabled",
        "Path Monitor Failure Condition",
        "Path Monitor Hold Time",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "Logical Router Routes": (
        "Logical Router",
        "VRF",
        "Route Name",
        "Address Family",
        "Destination",
        "Next Hop Type",
        "Next Hop",
        "Interface",
        "Admin Distance",
        "Metric",
        "Route Table",
        "BFD Profile",
        "Path Monitor Enabled",
        "Path Monitor Failure Condition",
        "Path Monitor Hold Time",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "Route Path Monitors": (
        "Router Type",
        "Router",
        "VRF",
        "Route Name",
        "Monitor Name",
        "Enabled",
        "Source",
        "Destination",
        "Destination FQDN",
        "Interval",
        "Count",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    # ------------------------------------------------------------------
    # DHCP
    # ------------------------------------------------------------------

    "DHCP Servers": (
        "Interface",
        "Mode",
        "Probe IP",
        "Lease Type",
        "Lease Timeout",
        "Inheritance Source",
        "Gateway",
        "Subnet Mask",
        "DNS Primary",
        "DNS Secondary",
        "WINS",
        "NTP",
        "POP3 Server",
        "SMTP Server",
        "DNS Suffix",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "DHCP IP Pools": (
        "Interface",
        "Pool Entry",
        "Start IP",
        "End IP",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "DHCP Reservations": (
        "Interface",
        "Reservation Name",
        "IP Address",
        "MAC Address",
        "Description",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "DHCP Options": (
        "Interface",
        "Option Name",
        "Code",
        "Vendor Class Identifier",
        "Inherited",
        "Value Type",
        "IP Values",
        "ASCII Values",
        "Hex Values",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    # ------------------------------------------------------------------
    # SD-WAN
    # ------------------------------------------------------------------

    "SD-WAN Interface Profiles": (
        "Name",
        "Link Tag",
        "Link Type",
        "VPN Data Tunnel Support",
        "Maximum Download",
        "Maximum Upload",
        "Error Correction",
        "Path Monitoring",
        "VPN Failover Metric",
        "Probe Frequency",
        "Probe Idle Time",
        "Failback Hold Time",
        "Comment",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "SD-WAN Interface Bindings": (
        "Interface",
        "Parent Interface",
        "SD-WAN Enabled",
        "IPv6 Enabled",
        "Interface Profile",
        "Upstream NAT",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "SD-WAN Path Quality": (
        "Name",
        "Latency Threshold",
        "Latency Sensitivity",
        "Packet Loss Threshold",
        "Packet Loss Sensitivity",
        "Jitter Threshold",
        "Jitter Sensitivity",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "SD-WAN Traffic Distribution": (
        "Name",
        "Distribution Mode",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "SD-WAN Traffic Distribution Links": (
        "Profile",
        "Link Tag",
        "Weight",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "SD-WAN SaaS Quality": (
        "Name",
        "Monitor Mode",
        "Probe Configuration",
        "Targets",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "SD-WAN Error Correction": (
        "Name",
        "Activation Threshold",
        "Mode",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "SD-WAN Rules": (
        "Rule Order",
        "Name",
        "From Zones",
        "To Zones",
        "Source Addresses",
        "Source Users",
        "Destination Addresses",
        "Applications",
        "Services",
        "Tags",
        "Source Negate",
        "Destination Negate",
        "Disabled",
        "Path Quality Profile",
        "SaaS Quality Profile",
        "Error Correction Profile",
        "Traffic Distribution Profile",
        "NAT Session Failover Action",
        "Group Tag",
        "Description",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    # ------------------------------------------------------------------
    # Users / identity
    # ------------------------------------------------------------------

    "Local Users": (
        "Name",
        "Disabled",
        "Password Configured",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "Local User Groups": (
        "Name",
        "Members",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "Group Mappings": (
        "Name",
        "Server Profile",
        "Disabled",
        "LDAP Serial Number Check",
        "Use Modify Timestamp",
        "Limited Group Search",
        "Nested Group Level",
        "Group Object Attributes",
        "Group Member Attributes",
        "Group Name Attributes",
        "User Object Attributes",
        "User Name Attributes",
        "User Email Attributes",
        "Group Email Attributes",
        "Alternate Username 1",
        "Alternate Username 2",
        "Alternate Username 3",
        "Container Object Attributes",
        "Last Modify Attribute",
        "Group Include List",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    # ------------------------------------------------------------------
    # Administration
    # ------------------------------------------------------------------

    "Administrators": (
        "Name",
        "Role Type",
        "Built-In Role",
        "Custom Admin Role",
        "Authentication Profile",
        "Password Configured",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "Admin Roles": (
        "Name",
        "Role Scope",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "Admin Role Permissions": (
        "Role",
        "Role Scope",
        "Channel",
        "Permission Path",
        "Setting",
        "Value",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    # ------------------------------------------------------------------
    # IPsec VPN
    # ------------------------------------------------------------------

    "IKE Gateways": (
        "Name",
        "Local Interface",
        "Local IP",
        "Peer Address Type",
        "Peer Address",
        "IKE Version",
        "IKEv1 Exchange Mode",
        "IKEv1 Crypto Profile",
        "IKEv2 Crypto Profile",
        "Authentication Method",
        "Pre-Shared Key Configured",
        "Local ID",
        "Peer ID",
        "IKEv1 DPD Enabled",
        "IKEv1 DPD Interval",
        "IKEv1 DPD Retry",
        "IKEv2 DPD Enabled",
        "IKEv2 DPD Interval",
        "NAT Traversal",
        "NAT Traversal Keepalive",
        "Passive Mode",
        "Fragmentation",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "IKE Crypto Profiles": (
        "Name",
        "Encryption Algorithms",
        "Authentication Algorithms",
        "DH / AKE Groups",
        "Lifetime Value",
        "Lifetime Unit",
        "Authentication Multiple",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "IPsec Crypto Profiles": (
        "Name",
        "Protocol",
        "ESP Encryption",
        "ESP Authentication",
        "AH Authentication",
        "DH Group",
        "Lifetime Value",
        "Lifetime Unit",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "IPsec Tunnels": (
        "Name",
        "Tunnel Interface",
        "Key Type",
        "IKE Gateways",
        "IPsec Crypto Profile",
        "Tunnel Monitor",
        "GlobalProtect Satellite",
        "Manual Key Configured",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "IPsec Proxy IDs": (
        "Tunnel",
        "Name",
        "Address Family",
        "Local",
        "Remote",
        "Protocol",
        "Protocol Number",
        "Local Port",
        "Remote Port",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    # ------------------------------------------------------------------
    # GlobalProtect
    # ------------------------------------------------------------------

    "GlobalProtect Portals": (
        "Name",
        "SSL/TLS Service Profile",
        "Certificate Profile",
        "Clientless VPN Enabled",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "GP Portal Client Configs": (
        "Portal",
        "Config Name",
        "Internal Host Detection IP",
        "Internal Host Detection Hostname",
        "Authentication Override",
        "Agent UI Settings",
        "HIP Collection Settings",
        "Agent Configuration",
        "GP App Configuration",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "GP Portal Gateway Entries": (
        "Portal",
        "Client Config",
        "Gateway Type",
        "Gateway",
        "Priority",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "GP Clientless VPN": (
        "Portal",
        "Hostname",
        "Security Zone",
        "Login Lifetime",
        "Inactivity Logout",
        "Maximum Users",
        "DNS Proxy",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "GlobalProtect Gateways": (
        "Name",
        "Tunnel Mode",
        "Local Interface",
        "Local Address",
        "IP Address Family",
        "SSL/TLS Service Profile",
        "Certificate Profile",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Source Explicit Fields",
        "Additional Settings",
    ),

    "GP Gateway Client Auth": (
        "Gateway",
        "Auth Name",
        "OS",
        "Authentication Profile",
        "Auto Retrieve Passcode",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    "GP Remote User Tunnels": (
        "Gateway",
        "Config Name",
        "IP Pools",
        "Authentication Server IP Pools",
        "Split Tunneling",
        "No Direct Access To Local Network",
        "Retrieve Framed IP",
        "Scope Type",
        "Scope Name",
        "Analysis Status",
        "Review Reasons",
        "Additional Settings",
    ),

    # ------------------------------------------------------------------
    # Technical / source preservation
    # ------------------------------------------------------------------

    "Unresolved References": (
        "Source Scope Type",
        "Source Scope Name",
        "Source Object Type",
        "Source Object",
        "Field",
        "Reference",
        "Expected Type",
        "Status",
        "Resolved Scope",
        "Resolved Object",
        "Reason",
    ),

    "Unsupported": (
        "Source Path",
        "Status",
        "Reason",
    ),

    "PAN-OS Source Inventory": (
        "Scope Type",
        "Scope Name",
        "Device",
        "Serial",
        "Device Group",
        "Source Path",
        "Kind",
        "Object",
        "Rulebase Position",
        "Source Order",
        "Values",
        "Extraction Status",
    ),

    "Extraction Coverage": (
        "Source Domain",
        "Found",
        "Source Records",
        "Typed Objects",
        "Status",
        "Unknown Paths",
        "Notes",
    ),
}


DERIVED_COLUMNS_BY_SHEET: dict[str, tuple[str, ...]] = {
    # Keep this intentionally small.
    #
    # Add entries here only when the current relationship / transform layer
    # actually calculates the value. Do not expose inferred PAN-OS defaults
    # as derived fields.

    "Vulnerability Profiles": (
        "Rule Count",
        "Exception Count",
    ),
    "Security Policies": (
        "Effective Order",
        "Resolved Source References",
        "Resolved Destination References",
    ),
    "NAT Rules": (
        "Effective Order",
        "Derived Source Translation Mode",
        "Derived Destination Translation Mode",
        "Resolved Translation References",
    ),
    "Interfaces": (
        "Imported VSYS",
        "Zone",
        "Virtual Router",
        "Topology Issues",
    ),
}


TECHNICAL_COLUMNS_BY_SHEET: dict[str, tuple[str, ...]] = {
    sheet: tuple(
        column
        for column in headers
        if column in {
            "Source Explicit Fields",
            "Additional Settings",
        }
    )
    for sheet, headers in SHEET_HEADERS.items()
}


HIDDEN_COLUMNS_BY_DEFAULT = TECHNICAL_COLUMNS_BY_SHEET


SHEET_IMPLEMENTATION_STATUS: dict[str, str] = {
    sheet: "NOT_IMPLEMENTED"
    for sheet in SHEET_ORDER
}
SHEET_IMPLEMENTATION_STATUS.update({
    "Summary": "IMPLEMENTED",
    "Review Required": "IMPLEMENTED",
    "Validation": "IMPLEMENTED",
    "Tags": "IMPLEMENTED",
    "Addresses": "IMPLEMENTED",
    "Address Groups": "IMPLEMENTED",
    "Services": "IMPLEMENTED",
    "Service Groups": "IMPLEMENTED",
    "Schedules": "IMPLEMENTED",
    "Security Policies": "IMPLEMENTED",
    "NAT Rules": "IMPLEMENTED",
    "Security Profile Groups": "IMPLEMENTED",
    "Interfaces": "IMPLEMENTED",
    "Zones": "IMPLEMENTED",
    "Virtual Router Routes": "IMPLEMENTED",
    "Logical Router Routes": "IMPLEMENTED",
    "Unresolved References": "IMPLEMENTED",
    "Unsupported": "IMPLEMENTED",
    "PAN-OS Source Inventory": "IMPLEMENTED",
    "Extraction Coverage": "IMPLEMENTED",
    "Vulnerability Profiles": "IMPLEMENTED",
    "Vulnerability Rules": "IMPLEMENTED",
    "Vulnerability Exceptions": "IMPLEMENTED",
    "Administrators": "IMPLEMENTED",
    "Admin Roles": "IMPLEMENTED",
    "Admin Role Permissions": "IMPLEMENTED",
    "IKE Gateways": "IMPLEMENTED",
    "IKE Crypto Profiles": "IMPLEMENTED",
    "IPsec Crypto Profiles": "IMPLEMENTED",
    "IPsec Tunnels": "IMPLEMENTED",
    "IPsec Proxy IDs": "IMPLEMENTED",
})

ACTIVE_SHEET_ORDER: tuple[str, ...] = tuple(
    sheet
    for sheet in SHEET_ORDER
    if SHEET_IMPLEMENTATION_STATUS[sheet] != "NOT_IMPLEMENTED"
)
