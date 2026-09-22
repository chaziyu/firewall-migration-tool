SHEET_ORDER = (
    "Summary", "Managed Objects", "Object Groups", "Services", "Zones",
    "Interfaces", "Routes", "ACP Rules", "NAT Rules", "Source Evidence", "Validation",
)

SHEET_HEADERS = {
    "Managed Objects": ("Name", "ID", "Type", "Source Plane"),
    "Object Groups": ("Name", "Members", "Source Plane"),
    "Services": ("Name", "Protocol", "Ports", "Source Plane"),
    "Zones": ("Name", "Interfaces", "Source Plane"),
    "Interfaces": ("Name", "Type", "Address", "Zone", "Source Plane"),
    "Routes": ("Name", "Interface", "Destination", "Gateway", "Source Plane"),
    "ACP Rules": ("Name", "Policy", "Action", "Source", "Destination", "Services", "Source Plane"),
    "NAT Rules": ("Name", "Policy", "Source Interface", "Destination Interface", "Original", "Translated", "Source Plane"),
    "Source Evidence": ("Path", "Reason"),
    "Validation": ("Severity", "Category", "Message", "Source Plane", "Object"),
}
