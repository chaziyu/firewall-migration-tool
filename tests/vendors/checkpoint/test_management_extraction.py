from pathlib import Path

from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source


def test_management_objects_rules_and_domains_are_extracted():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "multidomain_full.json").read_text()
    result = extract_checkpoint_source(source)
    config = result.config
    assert config.hosts and config.access_rules
    assert all(item.source_plane == "management" for item in config.hosts)
    assert {(item.domain_uid, item.name) for item in config.hosts} >= {
        ("domain-a", "SharedName"),
        ("domain-b", "SharedName"),
    }
    assert len(result.derived.references.by_name[("domain-a", "SharedName")]) == 1
    assert len(result.derived.references.by_name[("domain-b", "SharedName")]) == 1


def test_nested_domain_metadata_sets_object_scope_and_preserves_source():
    result = extract_checkpoint_source('{"responses":[{"command":"show-hosts","domain":"response-domain","domain_uid":"response-uid","data":{"objects":[{"uid":"h","name":"host","type":"host","domain":{"uid":"object-uid","name":"Object Domain","domain-type":"mds"}}]}}]}')

    host = result.config.hosts[0]
    assert (host.domain_uid, host.domain) == ("object-uid", "Object Domain")
    assert host.raw_extra["domain_metadata"] == {"uid": "object-uid", "name": "Object Domain", "domain-type": "mds"}
    assert any(issue.code == "domain_scope_conflict" for issue in result.validation.issues)


def test_nested_domain_without_identity_uses_response_scope_and_reports_unknown():
    result = extract_checkpoint_source('{"responses":[{"command":"show-hosts","domain":"response-domain","data":{"objects":[{"uid":"h","name":"host","type":"host","domain":{"domain-type":"mds"}}]}}]}')

    host = result.config.hosts[0]
    assert host.domain == "response-domain"
    assert host.raw_extra["domain_scope_unresolved"] is True
    assert any(issue.code == "domain_scope_unresolved" for issue in result.validation.issues)
