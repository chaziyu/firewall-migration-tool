from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def _parse_and_transform(pool_body: str):
    config = f"""
config firewall ippool
    edit "pool1"
{pool_body}
    next
end
"""
    parsed = parse_fortigate_config(config)
    return parsed, FGToIRTransformer(parsed).transform()


def test_basic_overload_ip_pool_is_preserved_separately_from_nat_rule():
    _, ir = _parse_and_transform("""
        set startip 1.1.1.10
        set endip 1.1.1.20
        set comments "Internet SNAT pool"
""")

    assert len(ir.ip_pools) == 1
    pool = ir.ip_pools[0]
    assert pool.name == "pool1"
    assert pool.pool_type == "overload"
    assert pool.start_ip == "1.1.1.10"
    assert pool.end_ip == "1.1.1.20"
    assert pool.description == "Internet SNAT pool"

    assert ir.nat_rules == []


def test_one_to_one_ip_pool_preserves_translated_and_source_ranges():
    _, ir = _parse_and_transform("""
        set type one-to-one
        set startip 203.0.113.10
        set endip 203.0.113.20
        set source-startip 10.0.0.1
        set source-endip 10.0.0.11
""")

    pool = ir.ip_pools[0]
    assert pool.pool_type == "one-to-one"
    assert pool.start_ip == "203.0.113.10"
    assert pool.end_ip == "203.0.113.20"
    assert pool.source_start_ip == "10.0.0.1"
    assert pool.source_end_ip == "10.0.0.11"


def test_ip_pool_preserves_interface_arp_and_multi_value_exclusions():
    parsed, ir = _parse_and_transform("""
        set startip 203.0.113.10
        set endip 203.0.113.20
        set associated-interface "wan1"
        set arp-reply disable
        set arp-intf "wan2"
        set permit-any-host enable
        set exclude-ip 203.0.113.11 203.0.113.12
""")

    assert parsed.ip_pools[0].exclude_ip == ["203.0.113.11", "203.0.113.12"]
    pool = ir.ip_pools[0]
    assert pool.associated_interface == "wan1"
    assert pool.arp_reply is False
    assert pool.arp_interface == "wan2"
    assert pool.permit_any_host is True
    assert pool.excluded_ips == ["203.0.113.11", "203.0.113.12"]


def test_ip_pool_preserves_pba_and_official_port_settings():
    _, ir = _parse_and_transform("""
        set type port-block-allocation
        set startip 203.0.113.10
        set endip 203.0.113.20
        set startport 5117
        set endport 65533
        set block-size 128
        set num-blocks-per-user 8
        set pba-timeout 300
        set pba-interim-log 600
        set port-per-user 256
        set nat64 enable
        set add-nat64-route disable
        set subnet-broadcast-in-ippool enable
""")

    pool = ir.ip_pools[0]
    assert pool.pool_type == "port-block-allocation"
    assert (pool.start_port, pool.end_port) == (5117, 65533)
    assert pool.block_size == 128
    assert pool.blocks_per_user == 8
    assert pool.pba_timeout == 300
    assert pool.pba_interim_log == 600
    assert pool.ports_per_user == 256
    assert pool.nat64 is True
    assert pool.add_nat64_route is False
    assert pool.include_subnet_broadcast is True


def test_fixed_port_range_ip_pool_preserves_746_port_range():
    _, ir = _parse_and_transform("""
        set type fixed-port-range
        set startip 203.0.113.30
        set endip 203.0.113.39
        set source-startip 10.0.0.30
        set source-endip 10.0.0.39
        set startport 5117
        set endport 65533
        set port-per-user 30208
    """)

    pool = ir.ip_pools[0]
    assert pool.pool_type == "fixed-port-range"
    assert (pool.start_port, pool.end_port) == (5117, 65533)
    assert (pool.source_start_ip, pool.source_end_ip) == ("10.0.0.30", "10.0.0.39")
    assert pool.ports_per_user == 30208
    assert "outside FortiOS" not in (pool.audit_note or "")


def test_ip_pool_preserves_version_specific_fields_and_requires_review():
    result = extract_fortigate_config('''
# config-version = 7.4.6
config firewall ippool
    edit "POOL746"
        set type overload
        set startip 203.0.113.10
        set endip 203.0.113.20
        set source-prefix6 64:ff9b::/96
        set privileged-port-use-pba enable
        set client-prefix-length 64
        set tcp-session-quota 1000
        set udp-session-quota 500
        set icmp-session-quota 100
    next
end
''')

    pool = result.canonical_ir.ip_pools[0]
    assert pool.source_prefix6 == "64:ff9b::/96"
    assert pool.privileged_port_use_pba is True
    assert pool.client_prefix_length == 64
    assert (pool.tcp_session_quota, pool.udp_session_quota, pool.icmp_session_quota) == (1000, 500, 100)
    assert pool.migration_status == "PARTIALLY_NORMALIZED"
    assert pool.requires_manual_review is True
    assert all(field in pool.audit_note for field in (
        "source_prefix6", "privileged_port_use_pba", "client_prefix_length",
        "tcp_session_quota", "udp_session_quota", "icmp_session_quota",
    ))
