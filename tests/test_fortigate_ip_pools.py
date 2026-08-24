from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


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

    # Keep the existing compatibility NAT output unchanged.
    assert len(ir.nat_rules) == 1
    assert ir.nat_rules[0].name == "pool1"
    assert ir.nat_rules[0].translated_source == "1.1.1.10-1.1.1.20"


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


def test_ip_pool_preserves_pba_nat64_and_session_quota_settings():
    _, ir = _parse_and_transform("""
        set startip 203.0.113.10
        set endip 203.0.113.20
        set source-prefix6 64:ff9b::/96
        set startport 1024
        set endport 65535
        set block-size 128
        set num-blocks-per-user 8
        set pba-timeout 300
        set pba-interim-log 60
        set port-per-user 256
        set privileged-port-use-pba enable
        set nat64 enable
        set add-nat64-route disable
        set client-prefix-length 64
        set subnet-broadcast-in-ippool enable
        set tcp-session-quota 1000
        set udp-session-quota 500
        set icmp-session-quota 100
""")

    pool = ir.ip_pools[0]
    assert pool.source_prefix6 == "64:ff9b::/96"
    assert (pool.start_port, pool.end_port) == (1024, 65535)
    assert pool.block_size == 128
    assert pool.blocks_per_user == 8
    assert pool.pba_timeout == 300
    assert pool.pba_interim_log == 60
    assert pool.ports_per_user == 256
    assert pool.privileged_port_use_pba is True
    assert pool.nat64 is True
    assert pool.add_nat64_route is False
    assert pool.client_prefix_length == 64
    assert pool.include_subnet_broadcast is True
    assert pool.tcp_session_quota == 1000
    assert pool.udp_session_quota == 500
    assert pool.icmp_session_quota == 100
