"""FortiGate-only Excel presentation schema."""

from __future__ import annotations


SHEET_ORDER: tuple[str, ...] = (
    "Summary", "Review Required",
    "DNS Settings", "NTP Settings", "NTP Servers",
    "Interfaces", "Interface Secondary IPs", "Zones",
    "Addresses", "Wildcard FQDN", "Address Groups", "Services", "Service Groups", "Schedules", "Schedule Groups",
    "Policies", "Security Policies", "NAT Rules", "IP Pools", "Virtual IPs", "VIP Real Servers", "VIP Groups",
    "Routes", "VPN Tunnels", "Policy IPsec Phase 1", "VPN Phase 2", "Policy IPsec Phase 2",
    "DHCP Servers", "DHCP IP Ranges", "DHCP Exclude Ranges", "DHCP Reservations",
    "SD-WAN", "SD-WAN Zones", "SD-WAN Members", "SD-WAN Health Checks", "SD-WAN Rules",
    "SSL VPN Settings", "SSL VPN Realms", "SSL VPN Clients", "SSL VPN Bookmark Owners", "SSL VPN Bookmarks", "SSL VPN Portals", "SSL VPN Authentication Rules",
    "Local Users", "User Groups", "User Group Matches",
    "Administrators", "Admin Profiles", "Admin Profile Permissions",
    "IPS Sensors", "IPS Sensor Entries", "IPS Exempt IPs", "Security Profiles",
    "External Resources", "Unresolved References", "Unsupported", "FortiGate Source Inventory",
    "Extraction Coverage",
)


SHEET_HEADERS: dict[str, tuple[str, ...]] = {
    "Summary": (),
    "Review Required": ("Severity", "Category", "Object", "VDOM", "Field", "Issue / Review Reason", "Source Sheet"),
    "DNS Settings": ("Setting", "Value", "Source Path", "Analysis Status", "Review Reasons"),
    "NTP Settings": ("Setting", "Value", "Source Path", "Analysis Status", "Review Reasons"),
    "NTP Servers": ("Server ID", "Setting", "Value", "Source Path", "Analysis Status", "Review Reasons"),
    "Interfaces": (
        "Name", "Alias", "Type", "Role", "IP / Prefix", "Secondary IPv4 Addresses", "Addressing Mode",
        "Management Access", "VLAN ID", "Parent Interface", "Aggregate", "Physical Interfaces", "Topology Path",
        "Zone", "Members", "Status", "Description", "VDOM", "Topology Issues", "Analysis Status", "Review Reasons",
        "Source Explicit Fields", "Additional Settings",
    ),
    "Interface Secondary IPs": ("Interface", "ID", "IP / Prefix", "Management Access", "HA Priority", "Analysis Status", "Review Reasons", "Additional Settings"),
    "Zones": ("Name", "Members", "Intrazone", "Description", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "Addresses": ("Name", "Type", "Value", "Address Family", "Associated Interface", "Allow Routing", "Tags", "Description", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "Wildcard FQDN": ("Name", "Wildcard FQDN", "Description", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "Address Groups": ("Name", "Address Family", "Group Type", "Members", "Exclusion Enabled", "Exclude Members", "Allow Routing", "Tags", "Description", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "Services": ("Name", "Source Service", "Protocol", "Destination Port", "Source Port", "Protocol Number", "ICMP Type", "ICMP Code", "Generated", "Description", "VDOM", "Analysis Status", "Review Reasons"),
    "Service Groups": ("Name", "Members", "Generated", "Description", "VDOM", "Analysis Status", "Review Reasons"),
    "Schedules": ("Name", "Type", "Days", "Start", "End", "Start UTC", "End UTC", "Expiration Days", "VDOM", "Analysis Status", "Review Reasons", "Source Explicit Fields", "Additional Settings"),
    "Schedule Groups": ("Name", "Members", "VDOM", "Analysis Status", "Review Reasons", "Source Explicit Fields", "Additional Settings"),
    "Policies": (
        "Rule #", "Policy Name", "Source Name", "Source Interface", "Source Addresses", "Source Address Negate",
        "Source IPv6 Addresses", "Source IPv6 Address Negate", "Destination Interface", "Destination Addresses",
        "Destination Address Negate", "Destination IPv6 Addresses", "Destination IPv6 Address Negate", "Services", "Service Negate",
        "Action", "Schedule", "Status", "NAT Enabled", "SNAT Type", "SNAT Address", "IP Pool Name", "VPN Tunnel",
        "User Groups", "Users", "UTM Status", "Security Profile Group", "Antivirus", "IPS Sensor", "Web Filter",
        "Application List", "DNS Filter", "SSL/SSH Profile", "Log Setting", "Comments", "VDOM", "Analysis Status",
        "Protocol Options", "Per-IP Shaper", "Review Reasons", "Source Explicit Fields", "Additional Settings",
    ),
    "Security Policies": ("Policy ID", "Action", "Application Categories", "VDOM", "Analysis Status", "Review Reasons", "Source Explicit Fields", "Additional Settings"),
    "NAT Rules": ("Rule #", "Policy Name", "Source Interface", "Destination Interface", "Source Addresses", "Source IPv6 Addresses", "Destination Addresses", "Destination IPv6 Addresses", "Services", "NAT Enabled", "SNAT Type", "SNAT Address", "IP Pool Name", "Egress Interfaces", "VDOM", "Analysis Status", "Review Reasons"),
    "IP Pools": ("Name", "Address Family", "Type", "Start IP", "End IP", "Source Start IP", "Source End IP", "Start Port", "End Port", "Associated Interface", "ARP Reply", "ARP Interface", "Permit Any Host", "Excluded IPs", "NAT64", "Add NAT64 Route", "NAT46", "Add NAT46 Route", "Description", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "Virtual IPs": ("Name", "Address Family", "Type", "Status", "External IP", "External Address Objects", "External Interface", "Mapped IPs", "Real Servers", "Real Server Count", "Port Forward", "Protocol", "External Port", "Mapped Port", "ARP Reply", "NAT Source VIP", "NAT64", "NAT66", "NDP Reply", "Services", "Load Balance Method", "Server Type", "Monitors", "Description", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "VIP Real Servers": ("VIP Name", "Server ID", "IP", "Address", "Port", "Status", "Weight", "Monitors", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "VIP Groups": ("Name", "Address Family", "Interface", "Members", "Comments", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "Routes": ("Route ID", "Destination", "Destination Address Object", "Interface", "Gateway", "Distance", "Priority", "Status", "SD-WAN Zone", "Preferred Source", "Source Prefix", "Dynamic Gateway", "Blackhole", "Description", "Address Family", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "VPN Tunnels": ("Name", "Type", "Local Interface", "Attached Physical Interfaces", "Aggregate", "Topology Path", "Remote Gateway IPv4", "Remote Gateway DDNS", "IKE Version", "IKE Mode", "Authentication Method", "Remote Authentication Method", "PSK Configured", "PPK Secret Configured", "Auth Password Configured", "Group Authentication Secret Configured", "Phase 1 Proposal", "Phase 1 DH Groups", "Key Lifetime (Seconds)", "NAT Traversal", "DPD Mode", "DPD Retry Count", "DPD Retry Interval", "Local Gateway", "Local ID", "Local ID Type", "Peer ID", "Certificate", "Description", "VDOM", "Topology Issues", "Analysis Status", "Review Reasons", "Additional Settings"),
    "Policy IPsec Phase 1": ("Name", "Remote Gateway IPv4", "Remote Gateway DDNS", "IKE Version", "IKE Mode", "Authentication Method", "Remote Authentication Method", "PSK Configured", "PPK Secret Configured", "Auth Password Configured", "Group Authentication Secret Configured", "Phase 1 Proposal", "Phase 1 DH Groups", "Key Lifetime (Seconds)", "NAT Traversal", "DPD Mode", "DPD Retry Count", "DPD Retry Interval", "Local Gateway", "Local ID", "Peer ID", "Certificate", "Description", "VDOM", "Analysis Status", "Review Reasons", "Source Explicit Fields", "Additional Settings"),
    "VPN Phase 2": ("Name", "Phase 1", "Proposal", "PFS", "DH Groups", "Key Lifetime Seconds", "Key Lifetime KB", "Source Range", "Destination Range", "Source Range IPv6", "Destination Range IPv6", "Protocol", "Source Port", "Destination Port", "Auto Negotiate", "Comments", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "Policy IPsec Phase 2": ("Name", "Phase 1", "Proposal", "PFS", "DH Groups", "Key Lifetime Seconds", "Key Lifetime KB", "Source Range", "Destination Range", "Source Range IPv6", "Destination Range IPv6", "Protocol", "Source Port", "Destination Port", "Auto Negotiate", "Comments", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "DHCP Servers": ("Server ID", "Interface", "Status", "Server Type", "IP Mode", "Default Gateway", "Netmask", "Lease Time", "DNS Service", "DNS Server 1", "DNS Server 2", "DNS Server 3", "DNS Server 4", "Timezone Option", "Timezone", "Relay Agent", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "DHCP IP Ranges": ("Server ID", "Interface", "Range ID", "Start IP", "End IP", "Lease Time", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "DHCP Exclude Ranges": ("Server ID", "Interface", "Range ID", "Start IP", "End IP", "Lease Time", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "DHCP Reservations": ("Server ID", "Interface", "Reservation ID", "IP Address", "MAC Address", "Description", "Action", "Type", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "SD-WAN": ("Status", "Load Balance Mode", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "SD-WAN Zones": ("Zone Name", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "SD-WAN Members": ("ID", "Interface", "Zone", "Gateway", "Source", "Cost", "Weight", "Priority", "Status", "Aggregate", "Physical Interfaces", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "SD-WAN Health Checks": ("Name", "Server", "Members", "Protocol", "Interval", "Fail Time", "Recovery Time", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "SD-WAN Rules": ("ID", "Name", "Status", "Mode", "Source", "Destination", "Priority Members", "Health Checks", "Priority Zones", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "SSL VPN Settings": ("Status", "Minimum Protocol", "Maximum Protocol", "Authentication Timeout", "Idle Timeout", "Port", "DNS Server 1", "DNS Server 2", "Server Certificate", "Source Interfaces", "Source Addresses", "Tunnel IP Pools", "Default Portal", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "SSL VPN Realms": ("URL Path", "Login Page Configured", "Login Page Length", "Maximum Concurrent Users", "NAS IP", "RADIUS Port", "RADIUS Server", "Virtual Host", "Virtual Host Only", "Virtual Host Server Certificate", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "SSL VPN Clients": ("Name", "Certificate", "Class ID", "Comment", "Distance", "Interface", "IPv4 Subnets", "IPv6 Subnets", "Peer", "Port", "Priority", "PSK Configured", "Realm", "Server", "Source IP", "Status", "User", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "SSL VPN Bookmark Owners": ("Owner Type", "Owner Name", "Custom Language", "Bookmark Count", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "SSL VPN Bookmarks": ("Owner Type", "Owner Name", "Bookmark", "Application Type", "URL", "Host", "Port", "Domain", "Folder", "Description", "Logon User", "Logon Password Configured", "SSO Password Configured", "Form Data", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "SSL VPN Portals": ("Name", "Tunnel Mode", "IPv6 Tunnel Mode", "IP Pools", "IPv6 Pools", "Split Tunneling", "Split Tunneling Routing Addresses", "Limit User Logins", "FortiClient Download", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "SSL VPN Authentication Rules": ("ID", "Auth", "Cipher", "Client Certificate", "Realm", "Source Interfaces", "Source Addresses", "Source Address Negate", "Users", "User Peer", "Groups", "Portal", "Analysis Status", "Review Reasons", "Additional Settings"),
    "Local Users": ("Name", "ID", "Status", "Type", "Password Configured", "Password Time", "Two Factor", "Two Factor Authentication", "Two Factor Notification", "FortiToken", "Email", "LDAP Server", "RADIUS Server", "TACACS+ Server", "Authentication Timeout", "Password Policy", "Workstation", "Username Sensitivity", "PPK Identity", "PPK Secret Configured", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "User Groups": ("Name", "ID", "Group Type", "Members", "Match Count", "Authentication Timeout", "Auth Concurrent Override", "Auth Concurrent Value", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "User Group Matches": ("User Group", "Match ID", "Server Name", "Group Name", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "Administrators": ("Name", "Access Profile", "VDOMs", "IPv4 Trusted Hosts", "Two Factor", "Two Factor Authentication", "Two Factor Notification", "Remote Auth", "Remote Group", "Credential Configured", "FortiToken", "Guest User Groups", "Schedule", "Peer Auth", "Peer Group", "SSH Certificate", "Analysis Status", "Review Reasons", "Additional Settings"),
    "Admin Profiles": ("Name", "Analysis Status", "Review Reasons", "Additional Settings"),
    "Admin Profile Permissions": ("Profile", "Permission Group", "Setting", "Value", "Analysis Status", "Review Reasons", "Additional Settings"),
    "IPS Sensors": ("Name", "Description", "Block Malicious URL", "Scan Botnet Connections", "Extended Log", "Replacement Message Group", "Entry Count", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "IPS Sensor Entries": ("Sensor", "Entry ID", "Signature IDs", "CVEs", "Applications", "OS", "Protocols", "Severities", "Location", "Default Action Filter", "Default Status Filter", "Action", "Status", "Log", "Log Packet", "Log Attack Context", "Rate Count", "Rate Duration", "Rate Mode", "Rate Track", "Quarantine", "Quarantine Expiry", "Quarantine Log", "Vulnerability Types", "Last Modified Filter", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "IPS Exempt IPs": ("Sensor", "Entry ID", "Exempt IP ID", "Source IP", "Destination IP", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "Security Profiles": ("Name", "Antivirus", "IPS Sensor", "Application List", "Web Filter", "DNS Filter", "File Filter", "SSL/SSH Profile", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "External Resources": ("Name", "Resource", "Type", "Refresh Rate", "Comments", "VDOM", "Analysis Status", "Review Reasons", "Additional Settings"),
    "Unresolved References": ("Source VDOM", "Source Type", "Source Object", "Field", "Reference", "Expected Type", "Reason"),
    "Unsupported": ("Section", "Source Records", "Primitive Registration", "Model Coverage", "Reason", "Raw Capture Location"),
    "FortiGate Source Inventory": ("Domain", "VDOM", "Scope Type", "Source Path", "Object", "Parent / Subsection", "Operation", "Setting", "Value", "Primitive Registration", "Extraction Status", "Raw Extra Entries"),
    "Extraction Coverage": ("Source Section", "Found", "Source Records", "Primitive Registration", "Model Coverage", "Typed Objects", "Raw Extra Objects", "Raw Extra Entries", "Model Gaps", "Source-only Records", "Line Start", "Line End", "Notes"),
}


DERIVED_COLUMNS_BY_SHEET: dict[str, tuple[str, ...]] = {
    "Interfaces": ("Aggregate", "Physical Interfaces", "Topology Path", "Topology Issues"),
    "Policies": ("SNAT Type", "SNAT Address", "IP Pool Name"),
    "NAT Rules": ("SNAT Type", "SNAT Address", "Egress Interfaces"),
    "Routes": ("Destination Address Object", "SD-WAN Zone", "Preferred Source"),
    "VPN Tunnels": ("Attached Physical Interfaces", "Aggregate", "Topology Path", "Topology Issues"),
    "VPN Phase 2": ("Source Range", "Destination Range", "Source Range IPv6", "Destination Range IPv6"),
    "SD-WAN Members": ("Aggregate", "Physical Interfaces"),
}

TECHNICAL_COLUMNS_BY_SHEET: dict[str, tuple[str, ...]] = {
    sheet: tuple(column for column in headers if column in {"Source Explicit Fields", "Additional Settings"})
    for sheet, headers in SHEET_HEADERS.items()
}

HIDDEN_COLUMNS_BY_DEFAULT = TECHNICAL_COLUMNS_BY_SHEET
