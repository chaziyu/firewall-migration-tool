import io

from openpyxl import load_workbook

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.dependencies import build_dependency_registry
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.model import FGInterface
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.report.excel_exporter import IRExcelExporter


def _interface(config: str, name: str) -> FGInterface:
    parsed = parse_fortigate_config(config)
    return next(interface for interface in parsed.interfaces if interface.name == name)


def _aggregate_config(interface_type: str = "aggregate", members: str = '"port2" "port1"') -> str:
    return f'''
config system interface
    edit "{interface_type}0"
        set type {interface_type}
        set member {members}
    next
    edit "port1"
    next
    edit "port2"
    next
end
'''


def test_aggregate_interface_members_are_typed_in_source_order():
    config = _aggregate_config(members='"port2" "port1"')

    interface = _interface(config, "aggregate0")

    assert interface.type == "aggregate"
    assert interface.members == ["port2", "port1"]
    assert "member" not in interface.source_attributes
    assert "members" not in interface.source_attributes


def test_redundant_interface_members_are_typed_in_source_order():
    interface = _interface(
        _aggregate_config("redundant", '"port4" "port3"'),
        "redundant0",
    )

    assert interface.type == "redundant"
    assert interface.members == ["port4", "port3"]


def test_interface_member_with_one_value_remains_a_one_item_list():
    interface = _interface(
        _aggregate_config("aggregate", '"port1"'),
        "aggregate0",
    )

    assert interface.members == ["port1"]


def test_aggregate_interface_without_member_has_an_empty_list():
    interface = _interface(
        '''
config system interface
    edit "aggregate0"
        set type aggregate
    next
end
''',
        "aggregate0",
    )

    assert interface.members == []


def test_aggregate_settings_are_typed_with_explicit_provenance():
    interface = _interface(
        '''
config system interface
    edit "aggregate0"
        set type aggregate
        set member "port1" "port2"
        set min-links 2
        set min-links-down operational
        set algorithm L4
        set lacp-mode active
        set lacp-speed fast
        set lacp-ha-secondary enable
    next
end
''',
        "aggregate0",
    )

    assert interface.members == ["port1", "port2"]
    assert interface.source_attributes == {
        "type": "aggregate",
        "source_context": "root",
        "vdom": "root",
    }
    assert {
        "member",
        "lacp_mode",
        "lacp_ha_secondary",
        "min_links",
        "min_links_down",
        "algorithm",
        "lacp_speed",
    } <= interface.source_explicit_fields


def test_legacy_lacp_ha_slave_is_preserved_as_unknown_source_setting():
    interface = _interface(
        '''
config system interface
    edit "aggregate0"
        set type aggregate
        set lacp-ha-slave enable
    next
end
''',
        "aggregate0",
    )

    assert interface.lacp_ha_secondary == "enable"
    assert interface.source_attributes["lacp_ha_slave"] == "enable"
    assert "lacp_ha_slave" not in interface.source_explicit_fields


def test_aggregate_unset_restores_effective_defaults_and_clears_provenance():
    interface = _interface(
        '''
config system interface
    edit "aggregate0"
        set type aggregate
        set lacp-mode passive
        set lacp-ha-secondary disable
        set system-id-type local
        set system-id 00:11:22:33:44:55
        set lacp-speed fast
        set min-links 2
        set min-links-down operational
        set algorithm L2
        set aggregate-type count
        set priority-override disable
        unset lacp-mode
        unset lacp-ha-secondary
        unset system-id-type
        unset system-id
        unset lacp-speed
        unset min-links
        unset min-links-down
        unset algorithm
        unset aggregate-type
        unset priority-override
    next
end
''',
        "aggregate0",
    )

    assert (
        interface.lacp_mode,
        interface.lacp_ha_secondary,
        interface.system_id_type,
        interface.system_id,
        interface.lacp_speed,
        interface.min_links,
        interface.min_links_down,
        interface.algorithm,
        interface.aggregate_type,
        interface.priority_override,
    ) == (
        "active", "enable", "auto", None, "slow", 1, "operational", "L4",
        "physical", "enable",
    )
    assert not interface.source_explicit_fields
    assert "source_unset_settings" in interface.source_attributes


def test_member_set_append_and_unset_preserve_order_and_clear_members():
    interface = _interface(
        '''
config system interface
    edit "aggregate0"
        set type aggregate
        set member "port3" "port1"
        append member "port2"
    next
end
''',
        "aggregate0",
    )
    assert interface.members == ["port3", "port1", "port2"]

    cleared = _interface(
        '''
config system interface
    edit "aggregate0"
        set type aggregate
        set member "port3"
        unset member
    next
end
''',
        "aggregate0",
    )
    assert cleared.members == []


def test_aggregate_defaults_are_effective_but_not_source_explicit():
    interface = _interface(
        '''
config system interface
    edit "aggregate0"
        set type aggregate
    next
end
''',
        "aggregate0",
    )

    assert (
        interface.lacp_mode,
        interface.lacp_ha_secondary,
        interface.system_id_type,
        interface.system_id,
        interface.lacp_speed,
        interface.min_links,
        interface.min_links_down,
        interface.algorithm,
        interface.aggregate_type,
        interface.priority_override,
    ) == (
        "active", "enable", "auto", None, "slow", 1, "operational", "L4",
        "physical", "enable",
    )
    assert not interface.source_explicit_fields


def test_aggregate_relationships_use_unambiguous_source_model_fields():
    interface = _interface(
        '''
config system interface
    edit "aggregate0"
        set type aggregate
        set aggregate "parent0"
        set redundant-interface "redundant0"
    next
end
''',
        "aggregate0",
    )

    assert interface.aggregate_parent == "parent0"
    assert interface.redundant_interface_parent == "redundant0"
    assert {"aggregate", "redundant_interface"} <= interface.source_explicit_fields


def test_malformed_min_links_preserves_evidence_and_effective_default():
    interface = _interface(
        '''
config system interface
    edit "aggregate0"
        set type aggregate
        set min-links invalid
    next
end
''',
        "aggregate0",
    )

    assert interface.min_links == 1
    assert interface.source_attributes["unparsed_min_links"] == "invalid"
    assert "min_links" in interface.source_explicit_fields


def test_aggregate_transform_preserves_topology_and_requires_review():
    ir = FGToIRTransformer(
        parse_fortigate_config(_aggregate_config())
    ).transform()
    interface = next(item for item in ir.interfaces if item.name == "aggregate0")

    assert interface.interface_type == "aggregate"
    assert interface.members == ["port2", "port1"]
    assert interface.migration_status == "PARTIALLY_NORMALIZED"
    assert interface.requires_manual_review is True
    assert (
        "FortiGate aggregate or redundant interface topology requires "
        "target-platform review"
    ) in interface.review_reasons
    assert interface.zone is None
    assert interface.parent is None


def test_aggregate_transform_projects_typed_source_semantics():
    ir = FGToIRTransformer(parse_fortigate_config('''
config system interface
    edit "aggregate0"
        set type aggregate
        set member "port1" "port2"
        set lacp-mode passive
        set lacp-ha-secondary disable
        set system-id-type local
        set system-id 00:11:22:33:44:55
        set lacp-speed fast
        set min-links 2
        set min-links-down operational
        set algorithm L2
        set aggregate-type count
        set priority-override disable
    next
end
''')).transform()
    interface = ir.interfaces[0]

    assert interface.source_lacp_mode == "passive"
    assert interface.source_lacp_ha_secondary == "disable"
    assert interface.source_lacp_system_id_type == "local"
    assert interface.source_lacp_system_id == "00:11:22:33:44:55"
    assert interface.source_lacp_speed == "fast"
    assert interface.source_min_links == 2
    assert interface.source_min_links_down == "operational"
    assert interface.source_aggregate_algorithm == "L2"
    assert interface.source_aggregate_type == "count"
    assert interface.source_priority_override == "disable"
    assert interface.source_explicit_aggregate_fields == [
        "aggregate_type",
        "algorithm",
        "lacp_ha_secondary",
        "lacp_mode",
        "lacp_speed",
        "member",
        "min_links",
        "min_links_down",
        "priority_override",
        "system_id",
        "system_id_type",
    ]


def test_redundant_transform_preserves_topology_and_requires_review():
    ir = FGToIRTransformer(
        parse_fortigate_config(_aggregate_config("redundant", '"port1" "port2"'))
    ).transform()
    interface = next(item for item in ir.interfaces if item.name == "redundant0")

    assert interface.interface_type == "redundant"
    assert interface.members == ["port1", "port2"]
    assert interface.requires_manual_review is True
    assert interface.migration_status == "PARTIALLY_NORMALIZED"


def test_normal_interface_has_no_topology_review_reason():
    ir = FGToIRTransformer(parse_fortigate_config('''
config system interface
    edit "port1"
        set type physical
    next
end
''')).transform()
    interface = ir.interfaces[0]

    assert interface.interface_type == "physical"
    assert interface.members == []
    assert interface.migration_status == "NORMALIZED"
    assert interface.requires_manual_review is False
    assert not any("topology" in reason.lower() for reason in interface.review_reasons)


def test_empty_aggregate_members_require_manual_review():
    ir = FGToIRTransformer(parse_fortigate_config('''
config system interface
    edit "aggregate0"
        set type aggregate
    next
end
''')).transform()
    interface = ir.interfaces[0]

    assert interface.members == []
    assert interface.requires_manual_review is True
    assert interface.migration_status == "PARTIALLY_NORMALIZED"
    assert (
        "FortiGate aggregate or redundant interface has no configured members"
        in interface.review_reasons
    )


def test_self_referencing_aggregate_is_preserved_and_reviewed():
    config = '''
config system interface
    edit "aggregate0"
        set type aggregate
        set member "aggregate0"
    next
end
'''

    result = extract_fortigate_config(config)
    interface = result.canonical_ir.interfaces[0]
    dependency = next(
        item
        for item in result.dependencies
        if item.source_path == "system interface"
    )

    assert interface.members == ["aggregate0"]
    assert interface.requires_manual_review is True
    assert any("itself" in reason for reason in interface.review_reasons)
    assert dependency.result == "UNRESOLVED"
    assert dependency.target_path is None


def test_interface_member_dependencies_resolve_in_same_vdom():
    result = extract_fortigate_config(_aggregate_config())
    dependencies = [
        item
        for item in result.dependencies
        if item.source_path == "system interface"
        and item.source_object == "aggregate0"
    ]

    assert [(item.reference, item.result, item.target_path) for item in dependencies] == [
        ("port2", "RESOLVED", "system interface"),
        ("port1", "RESOLVED", "system interface"),
    ]


def test_missing_interface_member_is_unresolved():
    result = extract_fortigate_config(_aggregate_config(members='"missing-port"'))
    dependency = next(
        item
        for item in result.dependencies
        if item.source_path == "system interface"
    )

    assert dependency.reference == "missing-port"
    assert dependency.result == "UNRESOLVED"
    assert dependency.expected_type == "system interface"
    assert dependency.target_path is None


def test_interface_members_do_not_resolve_across_vdoms():
    config = '''
config vdom
    edit "tenant-a"
        config system interface
            edit "aggregate0"
                set type aggregate
                set member "port1"
            next
        end
    next
    edit "tenant-b"
        config system interface
            edit "port1"
            next
        end
    next
end
'''

    result = extract_fortigate_config(config)
    dependency = next(
        item
        for item in result.dependencies
        if item.source_path == "system interface"
    )

    assert dependency.source_context == "tenant-a"
    assert dependency.result == "UNRESOLVED"
    assert dependency.target_path is None


def test_interface_member_dependency_registry_rejects_self_reference():
    from fwmigrate.extraction.models import SourceCommand, SourceInventoryItem

    dependencies = build_dependency_registry([
        SourceInventoryItem(
            domain="system",
            source_path="system interface",
            name="aggregate0",
            source_context="root",
            commands=[SourceCommand(operation="set", key="member", values=["aggregate0"])],
        ),
    ])

    assert len(dependencies) == 1
    assert dependencies[0].result == "UNRESOLVED"
    assert dependencies[0].notes == "Interface member cannot reference its own interface."


def test_interface_topology_is_exported_with_review_metadata():
    ir = FGToIRTransformer(parse_fortigate_config(_aggregate_config())).transform()
    workbook = load_workbook(io.BytesIO(IRExcelExporter(ir).generate()))
    sheet = workbook["Interfaces"]
    headers = {cell.value: cell.column for cell in sheet[3]}
    values = {
        header: sheet.cell(4, column).value
        for header, column in headers.items()
    }

    assert values["Interface Type"] == "aggregate"
    assert values["Members"] == "port2, port1"
    assert values["Extraction Status"] == "PARTIALLY_NORMALIZED"
    assert values["Manual Review"] == "TRUE"
    assert "target-platform review" in values["Review Reasons"]
    assert "member" not in values["Additional Settings"]


def test_interface_coverage_is_partial_for_aggregate_topology():
    result = extract_fortigate_config(_aggregate_config())
    section = next(
        item for item in result.source_sections if item.path == "system interface"
    )

    assert section.status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert result.requires_manual_review is True
