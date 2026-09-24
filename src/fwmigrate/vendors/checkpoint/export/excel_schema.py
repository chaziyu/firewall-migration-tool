"""Presentation metadata for typed Check Point source and derived views."""

SOURCE_SHEETS = {
    "Domains": "domains", "Hosts": "hosts", "Networks": "networks",
    "Address Ranges": "address_ranges", "DNS Domains": "dns_domains",
    "Wildcard Addresses": "wildcard_addresses", "Dynamic Objects": "dynamic_addresses",
    "Updatable Objects": "updatable_objects", "Address Groups": "groups",
    "Groups With Exclusion": "groups_with_exclusion", "Services": "services",
    "Service Groups": "service_groups", "Applications": "applications",
    "Times": "times", "Time Groups": "time_groups", "Security Zones": "security_zones",
    "Users": "users", "User Groups": "user_groups", "Access Roles": "access_roles",
    "Permission Profiles": "permission_profiles", "Administrators": "administrators",
    "Gateways": "gateways", "Clusters": "clusters", "Interoperable Devices": "interoperable_devices",
    "VPN Communities": "vpn_communities", "VPN Domains": "vpn_domains",
    "Policy Packages": "policy_packages", "Access Layers": "access_layers",
    "Access Sections": "access_sections", "Access Rules": "access_rules",
    "NAT Sections": "nat_sections", "NAT Rules": "nat_rules",
    "Threat Profiles": "threat_profiles", "Threat Layers": "threat_layers",
    "Threat Sections": "threat_sections", "Threat Rules": "threat_rules",
    "Threat Exceptions": "threat_rule_exceptions", "HTTPS Inspection": "https_inspection_rules",
    "Gaia Interfaces": "gaia_interfaces", "Gaia Routes": "gaia_static_routes",
    "Gaia DHCP Servers": "gaia_dhcp_servers", "Gaia Users": "gaia_users",
    "Gaia RBA Roles": "gaia_rba_roles", "Gaia RBA Assignments": "gaia_rba_user_assignments",
    "VTIs": "vtis",
}
DERIVED_SHEETS = ("NAT Migration Views", "Policy Traversal", "Interface Views", "VPN Views", "Unresolved References")
SHEET_ORDER = ("Summary", "Review Required", "Collection", "Scope", *SOURCE_SHEETS,
               *DERIVED_SHEETS, "Check Point Source Inventory", "Unsupported")
SHEET_HEADERS = {
    "Collection": ("Command", "Source Plane", "Status", "Complete", "Error"),
    "Scope": ("Selected Scope", "Value"),
    "Review Required": ("Severity", "Category", "Code", "Domain", "Object Type", "Object", "UID", "Field", "Issue / Review Reason", "Reference", "Source Sheet"),
    "NAT Migration Views": ("Source Kind", "Source Owner", "Translation Classification", "Resolved Source", "Resolved Destination", "Resolved Translation", "Issues"),
    "Policy Traversal": ("Package", "Layer", "Section", "Rule", "Source Rule Order", "Derived Traversal Position", "Parent Rule", "Inline Depth", "Issues"),
    "Interface Views": ("Device", "Device Kind", "Interface", "Resolved Zone", "Zone Assignment Source", "Management Source Present", "Gaia Source Present", "Topology Issues"),
    "VPN Views": ("Community", "Community Type", "Gateways", "Clusters", "Interoperable Devices", "Centers", "Satellites", "VPN Domains", "VTIs", "Route Based", "Issues"),
    "Unresolved References": ("Source", "Field", "Reference", "Status", "Issue"),
    "Check Point Source Inventory": ("Source Plane", "Domain", "Domain UID", "Command", "Object Type", "UID", "Name", "Package", "Layer", "Gateway", "Order", "Explicit Fields", "Source Values", "Additional Settings"),
    "Unsupported": ("Source Area / Command", "Scope", "Object Count", "Reason / Status", "Inventory Reference"),
}
TECHNICAL_COLUMNS_BY_SHEET = {sheet: ("Source Explicit Fields", "Additional Settings") for sheet in SOURCE_SHEETS}
HIDDEN_COLUMNS_BY_DEFAULT = TECHNICAL_COLUMNS_BY_SHEET
DERIVED_COLUMNS_BY_SHEET = {sheet: headers for sheet, headers in SHEET_HEADERS.items() if sheet in DERIVED_SHEETS}
