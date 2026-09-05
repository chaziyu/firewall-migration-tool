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
