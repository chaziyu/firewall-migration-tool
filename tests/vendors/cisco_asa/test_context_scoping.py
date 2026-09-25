from fwmigrate.vendors.cisco_asa.relationships.references import ASAReferenceKind, ASAReferenceStatus, build_asa_reference_index

from fwmigrate.vendors.cisco_asa.source_report import extract_cisco_asa_source
from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser


def parse(text):
    return CiscoASAParser(text).parse_raw()

from copy import deepcopy

from fwmigrate.vendors.cisco_asa.derived import build_asa_derived_views

from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser

from fwmigrate.vendors.cisco_asa.validation import validate_asa_config

from fwmigrate.vendors.cisco_asa.model import CiscoASAConfig, CiscoInterface, CiscoNetworkObject

from fwmigrate.vendors.cisco_asa.relationships.references import (
    ASAReferenceKind,
    ASAReferenceStatus,
    build_asa_reference_index,
)

def test_duplicate_names_and_nat_references_stay_inside_their_context():
    result = extract_cisco_asa_source(
        "changeto context customer-a\nobject network WEB\n host 10.0.0.1\n"
        "object network ONLY_A\n host 10.0.0.2\n"
        "nat (inside,outside) source static WEB interface\n"
        "changeto context customer-b\nobject network WEB\n host 192.0.2.1\n"
        "object network ONLY_B\n host 192.0.2.2\n"
        "nat (inside,outside) source static WEB interface\n"
        "changeto context customer-a\nnat (inside,outside) source static ONLY_B interface\n"
    )
    refs = build_asa_reference_index(result.config)

    a = refs.resolve("customer-a", ASAReferenceKind.NETWORK_OBJECT, "WEB")
    b = refs.resolve("customer-b", ASAReferenceKind.NETWORK_OBJECT, "WEB")
    assert a.target.value == "10.0.0.1" and b.target.value == "192.0.2.1"
    assert refs.resolve("customer-a", ASAReferenceKind.NETWORK_OBJECT, "ONLY_B").status is ASAReferenceStatus.UNRESOLVED
    contexts = [row.source_context for row in result.derived.nat_relationships.rules]
    assert contexts.count("customer-a") == 2
    assert contexts.count("customer-b") == 1
    assert [(row.source_context, row.effective_order) for row in result.derived.nat.rules] == [
        ("customer-a", 1), ("customer-b", 1), ("customer-a", 2)]
    assert any(issue.source_context == "customer-a" and issue.reference_name == "ONLY_B"
               for issue in result.derived.relationship_issues)

def test_dhcp_and_context_interface_resolution_stays_in_derived_relationships():
    config = parse("\n".join([
        "interface GigabitEthernet0/0", " nameif outside", " dhcprelay server 192.0.2.1",
        "context blue", " allocate-interface GigabitEthernet0/0 mapped",
    ]))
    before = deepcopy(config)

    assert config.dhcp_relays[0].server_entries[0].interface == "GigabitEthernet0/0"
    assert config.dhcp_relays[0].server_entries[0].explicit_fields == {"server", "interface"}
    assert config.contexts[0].allocated_interface_entries[0].physical_interface == "GigabitEthernet0/0"
    assert config.contexts[0].allocated_interface_entries[0].explicit_fields == {"physical_interface", "mapped_name"}

    derived = build_asa_derived_views(config)
    routing = derived.routing_relationships
    assert routing.dhcp_relay_interfaces[0].interface is config.interfaces[0]
    assert routing.allocated_interfaces[0].interface is config.interfaces[0]
    assert config == before

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
