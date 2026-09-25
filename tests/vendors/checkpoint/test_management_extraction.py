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
