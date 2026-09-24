from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser
from fwmigrate.vendors.cisco_asa.relationships.mpf import build_mpf_relationships
from fwmigrate.vendors.cisco_asa.relationships.references import build_asa_reference_index


def test_ips_sensor_is_external_source_reference():
    config = CiscoASAParser("""class-map inspection_default
 match default-inspection-traffic
policy-map global_policy
 class inspection_default
  ips inline fail-close sensor edge_sensor
""").parse_raw()
    action = config.policy_maps[0].classes[0].ips_actions[0]
    assert (action.mode, action.failure_mode, action.sensor) == ("inline", "fail-close", "edge_sensor")
    result = build_mpf_relationships(config, build_asa_reference_index(config))
    assert result.external_ips_actions[0][2] is action
    assert not any("sensor" in issue.reference_name for issue in result.issues)
