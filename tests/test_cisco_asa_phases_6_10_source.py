from fwmigrate.parsers.cisco_asa.extractor import extract_cisco_asa_config
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def test_phase_6_and_7_keep_raw_service_and_schedule_values():
    config = CiscoASAParser("""
object service WEB
 service tcp source range low high destination eq https
time-range BUSINESS
 periodic weekdays 08:00 to 17:00
 periodic weekend 09:00 to 12:00
""").parse_raw()
    assert config.service_objects[0].source_attributes["raw_lines"] == ["service tcp source range low high destination eq https"]
    assert [clause.raw for clause in config.time_ranges[0].clauses] == [
        "periodic weekdays 08:00 to 17:00", "periodic weekend 09:00 to 12:00"
    ]


def test_phases_8_to_10_capture_hierarchies_as_extract_only_records():
    config = CiscoASAParser("""
crypto ikev2 policy 10
 encryption aes
crypto map OUTSIDE 10 match address VPN_ACL
tunnel-group peer type ipsec-l2l
 ipsec-attributes
  ikev2 remote-authentication pre-shared-key secret
aaa-server RAD protocol radius
aaa-server RAD host 192.0.2.10
class-map INSPECT
 match access-list INSPECT_ACL
policy-map GLOBAL
 class INSPECT
  inspect dns
service-policy GLOBAL interface outside
""").parse_raw()
    assert config.ike_policies[0].source_attributes["raw_command"] == "crypto ikev2 policy 10"
    assert config.crypto_maps[0].acl_name == "VPN_ACL"
    assert config.tunnel_groups[0].ipsec_attributes["has_pre_shared_key"] is True
    assert len(config.aaa_records) == 2
    assert config.class_maps[0].match_lines == ["match access-list INSPECT_ACL"]
    assert config.policy_maps[0].class_sections == ["class INSPECT"]
    assert config.service_policies[0].interface == "outside"


def test_phase_8_to_10_source_inventory_is_secret_safe_and_visible():
    result = extract_cisco_asa_config("""
username admin password plaintext-secret
tunnel-group peer ipsec-attributes pre-shared-key plaintext-secret
class-map INSPECT
 match access-list ACL
""")
    serialized = result.model_dump_json()
    assert "plaintext-secret" not in serialized
    assert "class-map" in serialized


def test_phase_7_vpn_records_are_structured_and_crypto_map_lines_merge():
    config = CiscoASAParser("""
crypto ikev1 policy 10
 authentication pre-share
 encryption aes-256
 hash sha256
 group 14
 lifetime 86400
crypto ikev2 policy 20
 authentication pre-share
 encryption aes-gcm
 integrity sha256
 group 19
 lifetime 7200
crypto ipsec ikev2 ipsec-proposal PROPOSAL
 protocol esp encryption aes-256 aes-128 integrity sha-256 sha1
crypto ipsec transform-set TS esp-aes esp-sha-hmac
crypto map OUTSIDE 10 match address VPN_ACL
crypto map OUTSIDE 10 set peer vpn-peer
crypto map OUTSIDE 10 set transform-set TS
crypto map OUTSIDE 10 set ikev2 ipsec-proposal PROPOSAL
crypto map OUTSIDE 10 set pfs group14
crypto map OUTSIDE 10 set security-association lifetime seconds 3600
crypto map OUTSIDE 20 match address VPN_ACL_2
crypto map OUTSIDE 20 ipsec-isakmp dynamic DYN
""").parse_raw()
    ike1, ike2 = config.ike_policies
    assert (ike1.authentication, ike1.encryption, ike1.hash_algorithm, ike1.dh_group, ike1.lifetime_seconds) == ("pre-share", "aes-256", "sha256", "14", 86400)
    assert (ike2.version, ike2.integrity, ike2.lifetime_seconds) == ("ikev2", "sha256", 7200)
    assert config.ikev2_proposals[0].encryption_algorithms == ["aes-256", "aes-128"]
    assert config.ikev2_proposals[0].integrity_algorithms == ["sha-256", "sha1"]
    maps = {(item.map_name, item.sequence): item for item in config.crypto_maps}
    assert len(maps) == 2
    assert maps[("OUTSIDE", 10)].transform_sets == ["TS"]
    assert maps[("OUTSIDE", 10)].ikev2_proposals == ["PROPOSAL"]
    assert maps[("OUTSIDE", 10)].pfs_group == "group14"
    assert maps[("OUTSIDE", 10)].security_association_lifetime_seconds == 3600
    assert maps[("OUTSIDE", 20)].dynamic_map == "DYN"


def test_phase_7_tunnel_group_policy_references_and_psk_are_safe():
    config = CiscoASAParser("""
crypto ca trustpoint VPN_TP
ip local pool VPN_POOL 10.0.0.10 10.0.0.20
access-list VPN_ACL extended permit ip any any
tunnel-group vpn-peer type ipsec-l2l
 general-attributes
  default-group-policy VPN_POLICY
  address-pool VPN_POOL
  trust-point VPN_TP
 ipsec-attributes
  ikev1 pre-shared-key secret-value
group-policy VPN_POLICY internal
group-policy VPN_POLICY attributes
 vpn-tunnel-protocol ikev1 ikev2
 split-tunnel-policy tunnelspecified
 split-tunnel-network-list VPN_ACL
 dns-server value 192.0.2.53
 vpn-idle-timeout 30
 vpn-session-timeout 60
""").parse_raw()
    tunnel = config.tunnel_groups[0]
    policy = config.group_policies[0]
    assert tunnel.default_group_policy == "VPN_POLICY"
    assert tunnel.address_pools == ["VPN_POOL"]
    assert tunnel.trustpoint == "VPN_TP"
    assert tunnel.ikev1_psk_present
    assert policy.vpn_protocols == ["ikev1", "ikev2"]
    assert policy.split_tunnel_acl == "VPN_ACL"
    assert policy.dns_servers == ["192.0.2.53"]
    assert "secret-value" not in str(config.model_dump())
    assert not [issue for issue in config.reference_issues if not issue["resolved"]]


def test_phase_7_missing_vpn_references_are_reported():
    config = CiscoASAParser("""
crypto map OUTSIDE 10 match address MISSING_ACL
tunnel-group peer type ipsec-l2l
 general-attributes
  default-group-policy MISSING_POLICY
  address-pool MISSING_POOL
  trust-point MISSING_TP
""").parse_raw()
    missing = {issue["reference_name"] for issue in config.reference_issues if not issue["resolved"]}
    assert {"MISSING_ACL", "MISSING_POLICY", "MISSING_POOL", "MISSING_TP"} <= missing
