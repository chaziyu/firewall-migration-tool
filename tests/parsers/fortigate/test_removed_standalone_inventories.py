from fwmigrate.parsers.fortigate import extract_fortigate_config


REMOVED_INVENTORY_SECTIONS = {
    "ips sensor",
    "firewall internet-service-custom",
    "web-proxy global",
}


def test_removed_standalone_inventories_are_ignored_and_supported_sections_survive():
    result = extract_fortigate_config(
        """
config ips sensor
    edit "sensor"
        set extended-log enable
    next
end
config firewall internet-service-custom
    edit "custom"
        set comment "inventory"
    next
end
config web-proxy global
    set status enable
end
config system interface
    edit "port1"
        set ip 192.0.2.1 255.255.255.0
    next
end
"""
    )

    inventory = {
        item.source_path: item
        for item in result.inventory_items
        if item.source_path in REMOVED_INVENTORY_SECTIONS
    }
    assert set(inventory) == REMOVED_INVENTORY_SECTIONS
    assert all(item.status.value == "IGNORED_BY_POLICY" for item in inventory.values())
    assert any(interface.name == "port1" for interface in result.canonical_ir.interfaces)


def test_policy_references_to_removed_inventories_are_preserved_as_external():
    result = extract_fortigate_config(
        """
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set ips-sensor "sensor"
        set internet-service enable
        set internet-service-name "custom"
    next
end
"""
    )

    policy = result.canonical_ir.policies[0]
    assert policy.ips_sensor == "sensor"
    assert policy.internet_service == ["custom"]
    dependencies = {
        item.source_field: item
        for item in result.dependencies
        if item.source_path == "firewall policy"
        and item.source_field in {"ips-sensor", "internet-service-name"}
    }
    assert dependencies["ips-sensor"].result == "EXTERNAL"
    assert dependencies["internet-service-name"].result == "EXTERNAL"
