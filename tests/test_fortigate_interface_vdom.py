from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def test_explicit_interface_vdom_overrides_root_parser_context():
    config = """
config system interface
    edit "port1"
        set vdom "tenant-a"
    next
end
"""

    interface = parse_fortigate_config(config).interfaces[0]

    assert interface.vdom == "tenant-a"
    assert interface.source_context == "tenant-a"


def test_interface_without_explicit_vdom_uses_root_parser_context():
    config = """
config system interface
    edit "port1"
    next
end
"""

    interface = parse_fortigate_config(config).interfaces[0]

    assert interface.vdom == "root"
    assert interface.source_context == "root"


def test_interface_without_explicit_vdom_uses_vdom_parser_context():
    config = """
config vdom
    edit "tenant-a"
        config system interface
            edit "port1"
            next
        end
    next
end
"""

    interface = parse_fortigate_config(config).interfaces[0]

    assert interface.vdom == "tenant-a"
    assert interface.source_context == "tenant-a"


def test_same_interface_name_resolves_within_each_vdom():
    config = """
config vdom
    edit "tenant-a"
        config system interface
            edit "port1"
                set ip 10.0.1.1 255.255.255.0
            next
        end
        config system zone
            edit "inside-a"
                set interface "port1"
            next
        end
        config firewall policy
            edit 101
                set srcintf "port1"
                set dstintf "port1"
                set srcaddr "all"
                set dstaddr "all"
                set service "ALL"
                set action accept
            next
        end
    next
    edit "tenant-b"
        config system interface
            edit "port1"
                set ip 10.0.2.1 255.255.255.0
            next
        end
        config system zone
            edit "inside-b"
                set interface "port1"
            next
        end
        config firewall policy
            edit 201
                set srcintf "port1"
                set dstintf "port1"
                set srcaddr "all"
                set dstaddr "all"
                set service "ALL"
                set action accept
            next
        end
    next
end
"""

    ir = FGToIRTransformer(parse_fortigate_config(config)).transform()

    interfaces = {
        (interface.source_context, interface.name): interface
        for interface in ir.interfaces
    }
    assert interfaces["tenant-a", "port1"].ip == "10.0.1.1/24"
    assert interfaces["tenant-a", "port1"].zone == "inside-a"
    assert interfaces["tenant-b", "port1"].ip == "10.0.2.1/24"
    assert interfaces["tenant-b", "port1"].zone == "inside-b"

    policies = {policy.source_rule_id: policy for policy in ir.policies}
    assert policies["101"].source_context == "tenant-a"
    assert policies["101"].from_zone == ["inside-a"]
    assert policies["101"].to_zone == ["inside-a"]
    assert policies["201"].source_context == "tenant-b"
    assert policies["201"].from_zone == ["inside-b"]
    assert policies["201"].to_zone == ["inside-b"]

    assert not any(
        entry.category == "Policy Zone Resolution"
        for entry in ir.audit_entries
    )
