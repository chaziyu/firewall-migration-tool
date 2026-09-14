from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


def _selection_from_details(details: Any) -> dict[str, Any] | None:
    if not isinstance(details, dict) or details.get("interface_cardinality") == "multiple":
        return None
    interface = details.get("resolved_interface") or details.get("interface")
    if not interface:
        return None
    return {
        "address_source": "interface-address",
        "interface": interface,
        "ipv4_addresses": list(details.get("ipv4_addresses", details.get("ip", [])) or []),
        "ipv6_addresses": list(details.get("ipv6_addresses", []) or []),
        "floating_ips": list(details.get("floating_ips", []) or []),
    }


def migrate_1_65_to_1_66(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.65":
        return dict(payload)

    migrated = dict(payload)
    metadata = migrated.get("metadata")
    source_vendor = str(metadata.get("source_vendor", "") if isinstance(metadata, dict) else "").lower()
    is_pan = source_vendor in {"palo_alto", "palo-alto", "pan_os", "pan-os"}

    for rule in migrated.get("nat_rules", []):
        if not isinstance(rule, dict):
            continue
        rule.setdefault("translated_source_address_references", [])
        rule.setdefault("translated_destination_address_references", [])
        if not is_pan:
            continue

        rule["translated_source_address_references"] = list(dict.fromkeys(
            rule["translated_source_address_references"]
            + list(rule.get("source_pool_references", []) or [])
        ))
        rule["translated_destination_address_references"] = list(dict.fromkeys(
            rule["translated_destination_address_references"]
            + list(rule.get("destination_pool_references", []) or [])
        ))
        rule["source_pool_references"] = []
        rule["destination_pool_references"] = []

        source_attributes = rule.get("source_attributes")
        if "source_translation_address_selection" not in rule and isinstance(source_attributes, dict):
            selection = _selection_from_details(source_attributes.get("pan_interface_address_details"))
            if selection is not None:
                rule["source_translation_address_selection"] = selection

        fallback = rule.get("source_translation_fallback")
        if isinstance(fallback, dict) and fallback.get("mode") == "interface-address":
            fallback["mode"] = "dynamic-ip-and-port"
            selection = {
                "address_source": "interface-address",
                "interface": fallback.get("interface"),
                "ipv4_addresses": list(fallback.get("interface_ips", []) or []),
                "ipv6_addresses": [],
                "floating_ips": [],
            }
            if isinstance(source_attributes, dict):
                details_container = source_attributes.get("pan_source_translation_fallback_details", {})
                details = details_container.get("interface_address") if isinstance(details_container, dict) else None
                selection.update(_selection_from_details(details) or {})
            fallback.setdefault("address_selection", selection)

    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
