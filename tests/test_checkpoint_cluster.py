import json

from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config


def test_cluster_management_object_preserves_members_and_vip():
    result = extract_checkpoint_config(json.dumps({"responses": [{"command": "show-gateways-and-servers", "data": {"objects": [{
        "uid": "c1", "name": "Cluster", "type": "cluster", "cluster-mode": "HA",
        "members": [{"uid": "m1"}], "virtual-ips": ["192.0.2.10"], "sync-network": "10.0.0.0/30",
    }]}}]}))
    cluster = result.canonical_ir.high_availability[0]
    assert cluster.cluster_uid == "c1"
    assert cluster.member_references == ["m1"]
    assert cluster.virtual_ips == ["192.0.2.10"]
    assert cluster.sync_network == "10.0.0.0/30"


def _result(cluster, *extra):
    return extract_checkpoint_config(json.dumps({"responses": [
        {"command": "show-simple-clusters", "data": {"objects": [cluster]}}, *extra
    ]}))


def test_cluster_interface_keeps_vip_and_member_addresses_separate():
    cluster = {"uid": "c1", "name": "C", "type": "simple-cluster", "cluster-mode": "high-availability",
               "members": [{"uid": "m1", "name": "M1"}, {"uid": "m2", "name": "M2"}],
               "interfaces": [{"name": "eth0", "virtual-ipv4": "10.0.0.1", "members": [
                   {"uid": "m1", "ipv4-address": "10.0.0.2"}, {"uid": "m2", "ipv4-address": "10.0.0.3"}], "sync": True}],
               "sync-network": "10.0.1.0/30", "sync-interfaces": ["eth1"]}
    result = _result(cluster, {"command": "show-gateways-and-servers", "data": {"objects": []}})
    item = result.canonical_ir.high_availability[0]
    assert item.mode == "high-availability"
    assert item.member_references == ["m1", "m2"]
    assert item.cluster_interfaces[0].virtual_ipv4 == "10.0.0.1"
    assert item.cluster_interfaces[0].member_addresses == {"m1": ["10.0.0.2"], "m2": ["10.0.0.3"]}
    assert item.member_interface_ips["m1"] == ["10.0.0.2"]


def test_load_sharing_and_ipv6_are_preserved():
    item = _result({"uid": "c1", "name": "C", "type": "checkpoint-cluster", "cluster-mode": "load-sharing",
                    "members": [{"uid": "m1", "interfaces": [{"ipv6-address": "2001:db8::2"}]}],
                    "interfaces": [{"name": "eth0", "virtual-ipv6": "2001:db8::1"}]}) .canonical_ir.high_availability[0]
    assert item.mode == "load-sharing"
    assert item.cluster_interfaces[0].virtual_ipv6 == "2001:db8::1"
    assert item.member_interface_ips["m1"] == ["2001:db8::2"]


def test_duplicate_uid_and_unresolved_member_are_accounted_once():
    cluster = {"uid": "c1", "name": "C", "type": "cluster", "members": [{"uid": "missing"}]}
    result = _result(cluster, {"command": "show-gateways-and-servers", "data": {"objects": [cluster]}})
    assert len(result.canonical_ir.high_availability) == 1
    assert result.canonical_ir.high_availability[0].member_references == ["missing"]
    assert result.canonical_ir.high_availability[0].requires_manual_review


def test_operational_clusterxl_state_does_not_change_persistent_mode():
    result = _result({"uid": "c1", "name": "C", "type": "cluster", "cluster-mode": "HA"},
                     {"command": "cphaprob state", "data": {"active-member": "m1"}})
    assert result.canonical_ir.high_availability[0].mode == "high-availability"
    assert any(i.source_type == "checkpoint-cluster-operational-state" for i in result.inventory_items)


def test_invalid_cluster_address_is_not_put_in_ir():
    result = _result({"uid": "c1", "name": "C", "type": "cluster", "virtual-ips": ["not-an-ip"],
                      "sync-network": "bad-network"})
    item = result.canonical_ir.high_availability[0]
    assert item.virtual_ips == []
    assert item.sync_network is None
    assert any(i.status.value == "PARSE_ERROR" for i in result.inventory_items)


def test_gaia_member_conflict_is_visible_without_overwrite():
    result = _result({"uid": "c1", "name": "C", "type": "cluster", "members": [{"uid": "m1"}],
                      "interfaces": [{"name": "eth0", "members": [{"uid": "m1", "ipv4-address": "10.0.0.2"}]}]},
                     {"command": "gaia/show-configuration", "cluster_member": "m1",
                      "data": {"cli_text": "set interface eth0 ipv4-address 10.0.0.22 mask-length 24"}})
    cluster = result.canonical_ir.high_availability[0]
    assert cluster.member_interface_ips["m1"] == ["10.0.0.2"]
    assert any(i.ip == "10.0.0.22/24" for i in result.canonical_ir.interfaces)
    assert "cluster-member-topology-conflict" in cluster.source_attributes["review_reasons"]
