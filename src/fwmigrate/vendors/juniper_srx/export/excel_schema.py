SHEET_ORDER = ("Summary", "Source Inventory", "Interfaces", "Zones", "Routing Instances",
               "Address Books", "Applications", "Policies", "NAT", "VPN", "Validation")

SHEET_HEADERS = {
    "Interfaces": ("Context", "Interface", "Unit", "Parent", "Name"),
    "Zones": ("Context", "Zone", "Interface"),
    "Routing Instances": ("Context", "Name", "Interfaces"),
    "Address Books": ("Context", "Name", "Zones", "Addresses", "Address Sets"),
    "Applications": ("Context", "Name", "Terms"),
    "Policies": ("Context", "Name", "Order", "From Zones", "To Zones"),
    "NAT": ("Context", "Type", "Name", "Rules"),
    "VPN": ("Context", "Type", "Name"),
    "Validation": ("Severity", "Category", "Message", "Context", "Object"),
}
