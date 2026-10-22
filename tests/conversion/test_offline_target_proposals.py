from pathlib import Path

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.conversion.palo_alto_to_juniper_srx.design.proposals import build_target_proposals as srx_proposals
from fwmigrate.conversion.palo_alto_to_cisco_asa.design.proposals import build_target_proposals as asa_proposals
from fwmigrate.conversion.palo_alto_to_juniper_srx.options import SRXMigrationOptions
from fwmigrate.conversion.fortigate_to_cisco_asa.design.proposals import build_target_proposals as fg_asa_proposals
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


def test_panos_proposals_are_repeatable_preserve_overrides_and_require_asa_security_levels():
    source = build_panos_config((Path(__file__).parents[1] / 'fixtures/palo_alto/all_targets_explicit.xml').read_text())
    first, suggested = srx_proposals(source, None, {})
    assert next(row for row in suggested if row['family'] == 'interface')['evidence_source'] == 'ASSUMED_LAYOUT'
    assert first.interfaces['ethernet1/1'].target_interface == 'ge-0/0/0'
    assert srx_proposals(source, None, first)[0] == first
    reversed_source = source.model_copy(update={'interfaces': list(reversed(source.interfaces))})
    assert srx_proposals(reversed_source, None, {})[0] == first
    explicit = SRXMigrationOptions(source_scope=first.source_scope, interfaces={'ethernet1/1': {'target_interface': 'ge-0/0/8'}})
    assert srx_proposals(source, None, explicit)[0].interfaces['ethernet1/1'].target_interface == 'ge-0/0/8'
    asa, rows = asa_proposals(source, None, {})
    assert not asa.interfaces and not asa.new_target_confirmed and not asa.routing_complete
    placements = [row for row in rows if row['family'] == 'interface']
    assert placements and all('security_level' not in row['value'] for row in placements)
    assert all(row['evidence_source'] == 'ASSUMED_LAYOUT' for row in placements)
    assert all(row['review_state'] == 'PENDING' for row in rows)


def test_asa_numbered_proposals_preserve_overrides_and_leave_collisions_and_security_levels_explicit():
    analysis = FortiGateSourceReporter().analyze_source('''config system interface
edit port2
set type physical
next
edit port1
set type physical
next
end
''')
    source = analysis.extracted.config
    before = source.model_dump(mode='json')
    options, rows = fg_asa_proposals(source, {})
    assert options.source_vdom == 'root' and options.target_version == '9.20'
    assert not options.interfaces
    assert [row['value']['interface'] for row in rows] == ['GigabitEthernet0/1', 'GigabitEthernet0/2']
    assert all('security_level' not in row['value'] for row in rows)
    reversed_source = source.model_copy(update={'interfaces': list(reversed(source.interfaces))})
    assert fg_asa_proposals(reversed_source, {}) == (options, rows)
    explicit = {'source_vdom': 'root', 'interfaces': {'root': {'port2': {
        'interface': 'GigabitEthernet0/1', 'nameif': 'trusted', 'security_level': 100}}}}
    kept, collisions = fg_asa_proposals(source, explicit)
    assert kept.interfaces['root']['port2'].nameif == 'trusted'
    assert not collisions
    assert source.model_dump(mode='json') == before


def test_multiple_source_scopes_do_not_receive_implicit_placement():
    text = '''config vdom
edit alpha
config system interface
edit port1
set type physical
next
end
next
edit beta
config system interface
edit port1
set type physical
next
end
next
end
'''
    source = FortiGateSourceReporter().analyze_source(text).extracted.config
    options, rows = fg_asa_proposals(source, {})
    assert options.source_vdom is None and not rows
