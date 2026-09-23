from pathlib import Path

from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source


def test_management_objects_rules_and_domains_are_extracted():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "multidomain_full.json").read_text()
    config = extract_checkpoint_source(source).config
    assert config.network_objects and config.access_rules
    assert all(item.source_plane == "management" for item in config.network_objects)
