from fwmigrate.vendors.checkpoint.extraction import extract_checkpoint_config
from fwmigrate.vendors.checkpoint.models import CheckPointExportBundle


def test_explicit_fields_and_unknown_leaves_are_source_faithful():
    config = extract_checkpoint_config(CheckPointExportBundle.model_validate({"responses": [{
        "command": "show-hosts",
        "data": {"objects": [{
            "uid": "h1", "name": "host", "type": "host",
            "ipv4-address": "192.0.2.1", "comments": "source comment",
            "tags": ["prod"], "color": "red", "future-leaf": "keep-me",
        }]},
    }]})).config
    host = config.hosts[0]

    assert host.ipv4_address == "192.0.2.1"
    assert host.comments == "source comment"
    assert host.tags == ["prod"]
    assert host.color == "red"
    assert {"ipv4_address", "comments", "tags", "color"} <= set(host.explicit_fields)
    assert "ipv6_address" not in host.explicit_fields
    assert host.ipv6_address is None
    assert host.raw_extra["future-leaf"] == "keep-me"


def test_policy_context_is_not_source_data_or_input_mutation():
    rulebase = [{
        "type": "access-section", "name": "Web", "rulebase": [{
            "type": "access-rule", "uid": "r1", "source": [{"uid": "h1"}],
        }],
    }]
    original = [{**rulebase[0], "rulebase": [dict(rulebase[0]["rulebase"][0])] }]
    bundle = CheckPointExportBundle.model_validate({"responses": [{
        "command": "show-access-rulebase", "data": {"rulebase": rulebase},
    }]})

    result = extract_checkpoint_config(bundle)

    assert rulebase == original
    rule = result.config.access_rules[0]
    assert rule.section_path == ["Web"]
    assert rule.source[0].uid == "h1"
    assert "_checkpoint_section_path" not in rule.raw_extra
    assert "_checkpoint_section_path" not in rule.explicit_fields
