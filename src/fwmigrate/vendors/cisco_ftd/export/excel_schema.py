SHEET_ORDER = (
    "Summary", "Managed Objects", "Object Groups", "Services", "Zones",
    "Interfaces", "Routes", "ACP Rules", "NAT Rules", "Native Sources", "Source Evidence", "Validation",
)

SHEET_HEADERS = {
    "Managed Objects": ("Name", "ID", "Type", "Value", "Description", "Address Family", "FQDN Lookup Type", "Overrides", "Source Plane"),
    "Object Groups": ("Name", "Members", "Literal Members", "Description", "Overrides", "Source Plane"),
    "Services": ("Name", "Protocol", "Port", "End Port", "ICMP Type", "ICMP Code", "Description", "Overrides", "Members", "Source Plane"),
    "Zones": ("Name", "Interfaces", "Source Plane"),
    "Interfaces": ("Name", "Type", "Address", "Zone", "Source Plane", "Derived Kind", "Derived Parent", "Explicit VLAN ID"),
    "Routes": ("Name", "Interface", "Destination", "Gateway", "SLA Monitor", "Source Plane", "Address Family", "Mask", "Normalized Destination"),
    "ACP Rules": ("Policy", "Rule", "Rule ID", "Enabled", "Position", "Section", "Category", "Action",
        "Source Zones", "Destination Zones", "Source Networks", "Destination Networks", "Source Ports", "Destination Ports",
        "Realm Users", "Users", "User Groups", "Applications", "Application Filters", "Inline Application Filters",
        "URLs", "URL Categories", "Time Range", "Intrusion Policy", "Variable Set", "File Policy",
        "Log Begin", "Log End", "Comments", "Source Plane", "Source Context"),
    "NAT Rules": ("Policy", "Rule", "Rule ID", "Rule Type", "Enabled", "Section", "Position",
        "Source Interface", "Destination Interface", "Original Source", "Translated Source",
        "Original Destination", "Translated Destination", "Original Source Service", "Translated Source Service",
        "Original Destination Service", "Translated Destination Service", "NAT Type", "Interface PAT",
          "DNS", "Route Lookup", "Proxy ARP", "Source Plane", "Source Context", "Additional Settings",
          "FDM Service", "Source Translation Mode", "Destination Translation Mode"),
    "Source Evidence": ("Path", "Reason"),
    "Native Sources": ("Collection", "Name", "ID", "Source Context", "Source Attributes", "Raw Source"),
    "Validation": ("Severity", "Category", "Message", "Source Plane", "Object"),
}
