SHEET_ORDER = (
    "Summary", "Source Inventory", "Interfaces", "Network Objects",
    "Network Groups", "ACL Rules", "NAT Rules", "Routes", "VPN",
    "Validation",
)

SHEET_HEADERS = {
    "Interfaces": ("Name", "Nameif", "Context", "IP", "Mask", "Security Level"),
    "Network Objects": ("Name", "Type", "Value", "Context"),
    "Network Groups": ("Name", "Members", "Context"),
    "ACL Rules": ("ACL", "Order", "Action", "Protocol", "Source", "Destination", "Service", "Context", "Raw"),
    "NAT Rules": ("Name", "Order", "Section", "Source Interface", "Destination Interface", "Real Source", "Mapped Source", "Context", "Raw"),
    "Routes": ("Interface", "Destination", "Mask", "Gateway", "Context", "Raw"),
    "VPN": ("Crypto Map", "Sequence", "Tunnel Group", "Access List", "Context"),
    "Validation": ("Severity", "Category", "Message", "Context", "Object"),
}

