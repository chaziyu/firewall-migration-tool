import json
from fwmigrate.vendors.checkpoint.extraction import extract_checkpoint_config
from fwmigrate.vendors.checkpoint.models import CheckPointExportBundle


def test_legacy_rulebases_keep_missing_ownership_and_report_scope():
    from fwmigrate.vendors.checkpoint.loader import load_checkpoint_input
    from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source

    source = json.dumps({"access-rulebase": [{"uid": "a", "type": "access-rule"}],
                         "nat-rulebase": [{"uid": "n", "type": "nat-rule"}]})
    bundle, scope = load_checkpoint_input(source)
    assert all(response.package is None and response.layer is None for response in bundle.responses)
    assert scope.ambiguous
    assert {"missing-package-ownership", "missing-access-layer-ownership"} <= set(scope.reasons)
    result = extract_checkpoint_source(source)
    for rule in (*result.config.access_rules, *result.config.nat_rules):
        assert rule.package is None and rule.layer is None
    assert any(issue.code == "scope_ambiguous" for issue in result.validation.issues)


def test_bundle_validation_errors_contain_only_safe_paths_and_codes():
    import pytest
    from fwmigrate.vendors.checkpoint.loader import load_checkpoint_input
    from fwmigrate.vendors.checkpoint.errors import CheckPointParseError

    with pytest.raises(CheckPointParseError) as error:
        load_checkpoint_input(json.dumps({"responses": [{"data": {"password": "ERROR_SECRET_SENTINEL"}}]}))
    assert "responses.0.command (missing)" in str(error.value)
    assert "ERROR_SECRET_SENTINEL" not in str(error.value)
    assert "input_value" not in str(error.value)


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
    context = next(item for item in result.policy_context if item.source is rule)
    assert context.section_path == ("Web",)
    assert "section_path" not in type(rule).model_fields
    assert "section_path" not in rule.model_dump()
    assert rule.source[0].uid == "h1"
    assert "_checkpoint_section_path" not in rule.raw_extra
    assert "_checkpoint_section_path" not in rule.explicit_fields
from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source


def test_legacy_input_does_not_invent_omitted_vpn_state():
    result = extract_checkpoint_source(json.dumps({
        "access-rulebase": [{"uid": "r1", "type": "access-rule", "name": "rule"}],
    }))

    rule = result.config.access_rules[0]
    assert rule.vpn is None
    assert "vpn" not in rule.explicit_fields


def test_absent_and_explicit_empty_source_collections_stay_distinct():
    config = extract_checkpoint_config(CheckPointExportBundle.model_validate({"responses": [{
        "command": "show-groups",
        "data": {"objects": [
            {"uid": "missing", "name": "missing", "type": "group"},
            {"uid": "empty", "name": "empty", "type": "group", "members": []},
        ]},
    }]})).config

    missing, empty = config.groups
    assert missing.members is None
    assert "members" not in missing.explicit_fields
    assert empty.members == []
    assert "members" in empty.explicit_fields
