"""Tests for FortiGate system virtual-wire-pair and system vdom-link parsing.

Covers:
- Multiple outer-vlan-ids on virtual-wire-pair (list typing, not scalar).
- set, append, and unset operations on members and outer-vlan-ids.
- Link type, status, interface/VDOM references, and vcluster on vdom-link.
- Preservation of unknown future settings in extra_settings without silent loss.
"""

from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_virtual_wire_pair_multiple_outer_vlan_ids_set_append_unset() -> None:
    config = """
config system virtual-wire-pair
    edit "vwp1"
        set member "port1" "port2"
        set outer-vlan-id 100 200
        append outer-vlan-id 300
        set wildcard-vlan enable
        set vlan-filtering enable
        set ingress-filtering enable
        set power-save disable
        set custom-future-flag test_value
    next
    edit "vwp2"
        set member "port3" "port4"
        set outer-vlan-id 400 500
        unset outer-vlan-id
        set wildcard-vlan disable
    next
    edit "vwp3"
        set member "port5"
        append member "port6"
        set outer-vlan-id 10 20 30 40
    next
end
"""
    cfg = parse_fortigate_config(config)
    assert len(cfg.virtual_wire_pairs) == 3

    vwp1 = cfg.virtual_wire_pairs[0]
    assert vwp1.name == "vwp1"
    assert vwp1.members == ["port1", "port2"]
    assert vwp1.outer_vlan_id == [100, 200, 300]
    assert vwp1.wildcard_vlan == "enable"
    assert vwp1.vlan_filtering == "enable"
    assert vwp1.ingress_filtering == "enable"
    assert vwp1.power_save == "disable"
    assert vwp1.extra_settings["custom_future_flag"] == "test_value"
    assert "outer_vlan_id" in vwp1.source_explicit_fields

    vwp2 = cfg.virtual_wire_pairs[1]
    assert vwp2.name == "vwp2"
    assert vwp2.members == ["port3", "port4"]
    assert vwp2.outer_vlan_id == []
    assert vwp2.wildcard_vlan == "disable"

    vwp3 = cfg.virtual_wire_pairs[2]
    assert vwp3.name == "vwp3"
    assert vwp3.members == ["port5", "port6"]
    assert vwp3.outer_vlan_id == [10, 20, 30, 40]


def test_vdom_link_typed_fields_and_vcluster() -> None:
    config = """
config system vdom-link
    edit "vlink0"
        set type ethernet
        set status up
        set vcluster vcluster1
        set vdom "root"
        set peer "vlink1"
        set interface "vlink0_if"
        set future-link-option "keep_me"
    next
    edit "vlink_ppp"
        set type ppp
        set status down
        set vcluster vcluster2
        set vdom "tenant-a"
    next
end
"""
    cfg = parse_fortigate_config(config)
    assert len(cfg.vdom_links) == 2

    l1 = cfg.vdom_links[0]
    assert l1.name == "vlink0"
    assert l1.type == "ethernet"
    assert l1.status == "up"
    assert l1.vcluster == "vcluster1"
    assert l1.vdom == "root"
    assert l1.peer == "vlink1"
    assert l1.interface == "vlink0_if"
    assert l1.extra_settings["future_link_option"] == "keep_me"
    assert {"type", "status", "vcluster", "vdom", "peer"} <= l1.source_explicit_fields

    l2 = cfg.vdom_links[1]
    assert l2.name == "vlink_ppp"
    assert l2.type == "ppp"
    assert l2.status == "down"
    assert l2.vcluster == "vcluster2"
    assert l2.vdom == "tenant-a"
    assert l2.peer is None


def test_virtual_wire_and_vdom_link_unset_members_and_vcluster() -> None:
    config = """
config system virtual-wire-pair
    edit "vwp_unset"
        set member "port1" "port2"
        unset member
    next
end
config system vdom-link
    edit "vlink_unset"
        set type ethernet
        set vcluster vcluster1
        unset vcluster
    next
end
"""
    cfg = parse_fortigate_config(config)
    assert len(cfg.virtual_wire_pairs) == 1
    assert cfg.virtual_wire_pairs[0].members == []

    assert len(cfg.vdom_links) == 1
    assert cfg.vdom_links[0].type == "ethernet"
    assert cfg.vdom_links[0].vcluster is None
