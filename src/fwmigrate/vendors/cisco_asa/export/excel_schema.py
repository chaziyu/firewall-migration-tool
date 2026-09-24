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
    "NAT Rules": ("Name", "Source Order", "Effective Order", "Order Status", "Section", "Translation Type", "Source Interface", "Destination Interface", "Real Source", "Mapped Source", "Context", "Raw"),
    "Routes": ("Interface", "Destination", "Mask", "Destination Prefix (Normalized)", "Gateway", "Configured Administrative Distance", "Effective Administrative Distance", "Track", "Context", "Raw"),
    "VPN": ("Type", "Source", "Crypto Map", "Sequence", "Crypto ACL", "Peer(s)", "Tunnel Group(s)", "Interface", "Transform Set(s)", "IKEv2 Proposal(s)", "VTI / Tunnel Interface", "IPsec Profile", "Group Policy", "Address Pool(s)", "Context", "Issues"),
    "Validation": ("Severity", "Category", "Message", "Context", "Object"),
}

