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
