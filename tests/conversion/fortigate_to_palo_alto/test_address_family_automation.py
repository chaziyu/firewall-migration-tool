from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
from fwmigrate.conversion.fortigate_to_palo_alto.planning.addresses import address_references
from fwmigrate.conversion.fortigate_to_palo_alto.planning.naming import allocate_plan_names
from fwmigrate.vendors.fortigate.model.address import FGAddress, FGAddressGroup
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecisionSet
from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import build_plan_dependency_index, item_key
from fwmigrate.conversion.fortigate_to_palo_alto.pipeline import run_migration_pipeline
from fwmigrate.vendors.fortigate.derived import build_derived_views
from dataclasses import replace
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer


def test_ipv6_all_does_not_shadow_ipv4_builtin():
    source = FGConfig(addresses=[FGAddress(name='all', address_family='ipv6', ip6='::/0')])
    assert address_references(source, 'root', ['all']) == ('0.0.0.0/0',)


def test_cli_pipeline_keeps_ipv6_inventory_without_blocking_ipv4_address():
    source = FGConfig(addresses=[FGAddress(name='all', subnet='0.0.0.0/0'),
                                 FGAddress(name='all', address_family='ipv6', ip6='::/0')])
    result = run_migration_pipeline(source, build_derived_views(source),
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}), workflow_mode='OFFLINE_EXPORT')
    assert any(' address all ip-netmask 0.0.0.0/0' in line for line in result.rendered.commands)
    assert len(result.rendered.report['items']) == 2


def test_address_families_keep_distinct_identity_and_ipv4_group_binding():
    source = FGConfig(addresses=[
        FGAddress(name='all', address_family='ipv4', subnet='0.0.0.0/0'),
        FGAddress(name='all', address_family='ipv6', ip6='::/0'),
    ], address_groups=[FGAddressGroup(name='clients', members=['all'])])
    before = source.model_dump()
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}})
    plan = allocate_plan_names(FortiGateToPaloAltoPlanner().plan(source, object(), options))
    ipv4, ipv6 = plan.addresses
    assert ipv4.target_name != ipv6.target_name
    assert ipv4.source_kind != ipv6.source_kind
    assert plan.address_groups[0].members == (ipv4.target_name,)
    assert plan.address_groups[0].status is PANMigrationStatus.SUPPORTED
    assert ipv6.status is PANMigrationStatus.UNSUPPORTED
    assert source.model_dump() == before


def test_association_requires_consistent_nested_policy_interface_scope():
    address = FGAddress(name='host', subnet='192.0.2.1/32', associated_interface='port1', allow_routing='enable')
    source = FGConfig(addresses=[address], interfaces=[FGInterface(name='port1')],
        address_groups=[FGAddressGroup(name='clients', members=['host'])],
        policies=[FGPolicy(policy_id=1, srcaddr=['clients'], srcintf=['port1'])])
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}})
    plan = FortiGateToPaloAltoPlanner().plan(source, object(), options)
    assert plan.addresses[0].status is PANMigrationStatus.SUPPORTED
    source.policies[0].srcintf = ['port2']
    plan = FortiGateToPaloAltoPlanner().plan(source, object(), options)
    assert plan.addresses[0].status is PANMigrationStatus.UNSUPPORTED


def test_interface_subnet_requires_static_evidence_and_propagates_interface_dependency():
    source = FGConfig(addresses=[FGAddress(name='connected', type='interface-subnet', raw_extra={'interface': 'port1'})],
        interfaces=[FGInterface(name='port1', type='physical', ip='192.0.2.10 255.255.255.0')])
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1', 'virtual_router': 'VR'}},
        interfaces={'root': {'port1': {'target_interface': 'ethernet1/1', 'target_zone': 'inside'}}})
    plan = FortiGateToPaloAltoPlanner().plan(source, object(), options)
    assert plan.addresses[0].value == '192.0.2.0/24'
    assert plan.addresses[0].status is PANMigrationStatus.SUPPORTED
    index = build_plan_dependency_index(plan, PANMigrationDecisionSet())
    assert item_key(plan.addresses[0]) in index.dependents_by_item[item_key(plan.interfaces[0])]
    missing = replace(plan, interfaces=())
    assert not any(' address connected ' in command for command in PANSetRenderer().render(missing).commands)
    invalid = replace(plan, interfaces=(replace(plan.interfaces[0], status=PANMigrationStatus.UNSUPPORTED),))
    assert not any(' address connected ' in command for command in PANSetRenderer().render(invalid).commands)
    mismatched = replace(plan, addresses=(replace(plan.addresses[0], value='198.51.100.0/24'),))
    assert not any(' address connected ' in command for command in PANSetRenderer().render(mismatched).commands)
    source.interfaces[0].mode = 'dhcp'
    assert FortiGateToPaloAltoPlanner().plan(source, object(), options).addresses[0].status is PANMigrationStatus.UNSUPPORTED


def test_pan_os_11_1_does_not_imply_pa820_hardware_ports():
    source = FGConfig(interfaces=[FGInterface(name='port1', type='physical', ip='192.0.2.1/24')])
    fields = {'vdoms': {'root': {'vsys': 'vsys1', 'virtual_router': 'VR'}},
              'interfaces': {'root': {'port1': {'target_interface': 'ethernet1/20', 'target_zone': 'inside'}}}}
    generic = PANMigrationOptions(**fields, conversion_settings={'panos_version': '11.1'})
    interface, = FortiGateToPaloAltoPlanner().plan(source, object(), generic).interfaces
    assert interface.status is PANMigrationStatus.SUPPORTED
    assert 'target_model' not in generic.conversion_settings
    bounded = PANMigrationOptions(**fields, conversion_settings={'panos_version': '11.1', 'target_model': 'PA-820'})
    interface, = FortiGateToPaloAltoPlanner().plan(source, object(), bounded).interfaces
    assert interface.status is PANMigrationStatus.MANUAL_REVIEW
