from fwmigrate.vendors.checkpoint.model.address import CPHost
from fwmigrate.vendors.checkpoint.model.source import CheckPointConfig
from fwmigrate.vendors.checkpoint.relationships.references import CPReferenceKind, build_reference_index
from fwmigrate.vendors.checkpoint.derived import build_checkpoint_derived_views


def test_uid_and_domain_scoped_name_resolution():
    a = CPHost(uid="a", name="same", domain_uid="d1")
    b = CPHost(uid="b", name="same", domain_uid="d2")
    index = build_reference_index(CheckPointConfig(hosts=[a, b]))
    assert index.resolve("a", expected_kinds=(CPReferenceKind.HOST,)).target is a
    assert index.resolve("same", owner=CPHost(domain_uid="d1"), expected_kinds=(CPReferenceKind.HOST,)).target is a
    assert index.resolve("same", owner=CPHost(domain_uid="d2"), expected_kinds=(CPReferenceKind.HOST,)).target is b
    assert index.resolve("same", owner=CPHost(domain_uid="d3"), expected_kinds=(CPReferenceKind.HOST,)).status == "cross_scope"
    assert index.resolve("a", expected_kinds=(CPReferenceKind.SERVICE,)).status == "wrong_type"


def test_relationship_building_does_not_mutate_source():
    config = CheckPointConfig(hosts=[CPHost(uid="h", name="host")])
    before = config.model_dump()
    build_checkpoint_derived_views(config)
    assert config.model_dump() == before
