from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config


def test_application_objects_and_policy_dimension_are_not_services():
    result = extract_checkpoint_config("""{
      "responses": [
        {"command": "show-application-sites", "data": {"objects": [
          {"uid": "app-1", "name": "Example", "type": "application-site",
           "category": "Business", "url": ["https://example.test"], "risk": 2}
        ]}},
        {"command": "show-application-site-groups", "data": {"objects": [
          {"uid": "grp-1", "name": "Web Apps", "type": "application-site-group", "members": ["app-1"]}
        ]}},
        {"command": "show-access-rulebase", "package": "P", "layer": "L", "data": {"rulebase": [{
          "uid": "rule-1", "rule-number": 1, "name": "allow-web", "type": "access-rule",
          "source": ["any"], "destination": ["any"], "service": ["grp-1"],
          "action": "Accept", "enabled": true, "vpn": ["Any"], "time": ["Any"]
        }]}}
      ]
    }""")

    assert result.canonical_ir.applications[0].urls == ["https://example.test"]
    assert result.canonical_ir.application_groups[0].members == ["Example"]
    policy = result.canonical_ir.policies[0]
    assert policy.applications == ["Web Apps"]
    assert policy.service == ["any"]
    assert result.canonical_ir.services == []
