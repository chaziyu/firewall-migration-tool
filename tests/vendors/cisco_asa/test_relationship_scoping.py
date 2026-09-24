from copy import deepcopy

from fwmigrate.vendors.cisco_asa.derived import build_asa_derived_views
from fwmigrate.vendors.cisco_asa.model import CiscoASAConfig, CiscoInterface, CiscoNetworkObject
from fwmigrate.vendors.cisco_asa.relationships.references import (
    ASAReferenceKind,
    ASAReferenceStatus,
    build_asa_reference_index,
)
from fwmigrate.vendors.cisco_asa.source_report import extract_cisco_asa_source


def test_named_references_are_context_local_and_duplicates_are_ambiguous():
    config = CiscoASAConfig(network_objects=[
        CiscoNetworkObject(name="WEB", source_context="customer-a"),
        CiscoNetworkObject(name="WEB", source_context="customer-b"),
        CiscoNetworkObject(name="ONLY-IN-B", source_context="customer-b"),
        CiscoNetworkObject(name="DUP", source_context="customer-a"),
        CiscoNetworkObject(name="DUP", source_context="customer-a"),
        CiscoNetworkObject(name="SYSTEM", source_context=None),
    ])
    references = build_asa_reference_index(config)

    assert references.resolve("customer-a", ASAReferenceKind.NETWORK_OBJECT, "WEB").status is ASAReferenceStatus.RESOLVED
    assert references.resolve("customer-a", ASAReferenceKind.NETWORK_OBJECT, "ONLY-IN-B").status is ASAReferenceStatus.UNRESOLVED
    assert references.resolve("customer-a", ASAReferenceKind.NETWORK_OBJECT, "SYSTEM").status is ASAReferenceStatus.UNRESOLVED
    assert references.resolve("customer-a", ASAReferenceKind.NETWORK_OBJECT, "DUP").status is ASAReferenceStatus.AMBIGUOUS


def test_interface_aliases_and_topology_are_context_local():
    config = CiscoASAConfig(interfaces=[
        CiscoInterface(name="GigabitEthernet0/1", source_context="customer-a", nameif="inside"),
        CiscoInterface(name="GigabitEthernet0/1", source_context="customer-b", nameif="inside"),
        CiscoInterface(name="GigabitEthernet0/3", source_context="customer-a", nameif="inside"),
        CiscoInterface(name="GigabitEthernet0/2", source_context="customer-a", parent_interface="GigabitEthernet0/1"),
    ])
    references = build_asa_reference_index(config)

    assert references.resolve("customer-a", ASAReferenceKind.INTERFACE, "inside").status is ASAReferenceStatus.AMBIGUOUS
    assert references.resolve("customer-b", ASAReferenceKind.INTERFACE, "inside").target.source_context == "customer-b"
    assert references.resolve(None, ASAReferenceKind.INTERFACE, "inside").status is ASAReferenceStatus.UNRESOLVED
    topology = build_asa_derived_views(config).interface_topology
    child = next(item for item in topology.interfaces if item.name.endswith("0/2"))
    assert child.parent.source_context == "customer-a"
    assert not topology.issues


def test_relationship_building_does_not_mutate_mpf_source_fields():
    config = extract_cisco_asa_source(
        "class-map CM\n match access-list MISSING\n"
        "policy-map PM\n class MISSING-CLASS\n inspect dns\n"
    ).config
    before = deepcopy(config)

    build_asa_derived_views(config)

    assert config == before
    match = config.class_maps[0].matches[0]
    assert match.resolved is None
    assert match.review_reasons == []
