SHEET_ORDER = (
    "Summary", "Collection", "Domains", "Packages", "Access Layers",
    "Network Objects", "Groups", "Services", "Applications", "Schedules",
    "Access Rules", "NAT Rules", "VPN Communities", "Gateways", "Gaia",
    "NAT Migration View", "Validation",
)

SHEET_HEADERS = {
    "Domains": ("UID", "Name", "Source Plane", "Command"),
    "Packages": ("UID", "Name", "Domain", "Command"),
    "Access Layers": ("UID", "Name", "Package", "Parent Layer UID", "Command"),
    "Network Objects": ("UID", "Name", "Type", "Domain", "Command"),
    "Groups": ("UID", "Name", "Members", "Domain", "Command"),
    "Services": ("UID", "Name", "Type", "Domain", "Command"),
    "Applications": ("UID", "Name", "Type", "Domain", "Command"),
    "Schedules": ("UID", "Name", "Type", "Domain", "Command"),
    "Access Rules": ("UID", "Name", "Order", "Package", "Layer", "Domain", "Command"),
    "NAT Rules": ("UID", "Name", "Order", "Package", "Domain", "Command"),
    "NAT Migration View": (
        "Source Kind", "Source UID", "Source Name", "Domain", "Rule Order", "Enabled",
        "Original Source", "Original Destination", "Original Service", "Translated Source",
        "Translated Destination", "Translated Service", "Translation Method", "Owner UID",
        "Owner Name", "Install On", "Issues",
    ),
    "VPN Communities": ("UID", "Name", "Domain", "Command"),
    "Gateways": ("UID", "Name", "Domain", "Gateway", "Command"),
    "Gaia": ("Name", "Type", "Gateway", "Command"),
    "Validation": ("Severity", "Category", "Message", "Command", "Reference"),
}
