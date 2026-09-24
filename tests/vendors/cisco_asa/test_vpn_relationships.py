from fwmigrate.vendors.cisco_asa.source_report import extract_cisco_asa_source


def test_policy_vpn_chain_resolves_to_context_local_source_objects():
    result = extract_cisco_asa_source(
        "access-list CRYPTO extended permit ip any any\n"
        "crypto ipsec ikev1 transform-set TS esp-aes esp-sha-hmac\n"
        "crypto ipsec ikev2 ipsec-proposal P2\n protocol esp encryption aes-256\n"
        "crypto map VPN 10 match address CRYPTO\n"
        "crypto map VPN 10 set peer 192.0.2.1\n"
        "crypto map VPN 10 set transform-set TS\n"
        "crypto map VPN 10 set ikev2 ipsec-proposal P2\n"
        "crypto map VPN interface outside\n"
        "interface Ethernet0/0\n nameif outside\n"
        "tunnel-group 192.0.2.1 type ipsec-l2l\n"
        "tunnel-group 192.0.2.1 general-attributes\n default-group-policy GP\n"
        "group-policy GP internal\n"
    )
    relationships = result.derived.vpn_relationships
    crypto = next(row for row in relationships.relationships if row.source.name == "VPN")
    targets = dict(crypto.targets)

    assert getattr(targets["crypto-acl"], "acl_name", targets["crypto-acl"]) == "CRYPTO"
    assert targets["transform-set"].name == "TS"
    assert targets["ikev2-proposal"].name == "P2"
    assert targets["interface"].nameif == "outside"
    assert targets["peer"].name == "192.0.2.1"
    tunnel_group = next(row for row in relationships.relationships if row.source.name == "192.0.2.1")
    assert dict(tunnel_group.targets)["group-policy"].name == "GP"
    assert not relationships.issues
    assert crypto.source.name == "VPN"
