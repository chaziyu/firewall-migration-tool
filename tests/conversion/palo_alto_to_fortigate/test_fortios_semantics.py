from copy import deepcopy

import pytest

from fwmigrate.conversion.palo_alto_to_fortigate.application import run_migration_pipeline
from fwmigrate.conversion.palo_alto_to_fortigate.options import FGMigrationOptions
from fwmigrate.conversion.palo_alto_to_fortigate.target.comparison import classify_target_reuse
from fwmigrate.conversion.palo_alto_to_fortigate.target.evidence import build_target_evidence
from fwmigrate.source_reporting import source_reporters

from .conftest import SOURCE


NAT = '''<nat><rules><entry name="outbound"><from><member>trust</member></from><to><member>untrust</member></to>
<source><member>net</member></source><destination><member>any</member></destination><service>any</service><disabled>no</disabled>
<source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/2</interface><ip>192.0.2.1</ip></interface-address></dynamic-ip-and-port></source-translation>
</entry></rules></nat>'''


def test_isolated_interface_snat_keeps_original_matches_and_explicit_egress(analyze, options):
    analysis = analyze(SOURCE.replace('</rulebase>', NAT + '</rulebase>'))
    _, rendered, _ = run_migration_pipeline(analysis, options)
    nat = next(row for row in rendered.report["items"] if row["family"] == "nat")
    assert not nat["blocking_reasons"], nat["blocking_reasons"]
    assert dict(nat["settings"])["srcintf"] == ("port1",)
    assert dict(nat["settings"])["dstintf"] == ("port2",)
    assert dict(nat["settings"])["orig-addr"] == ("net",)
    assert 'config firewall central-snat-map' in rendered.text


@pytest.mark.parametrize("second_prefix,executable", [("10.1.0.0/24", True), ("10.0.0.128/25", False)])
def test_multiple_snat_rules_require_proven_disjoint_source_prefixes(analyze, options, second_prefix, executable):
    second = NAT[NAT.index('<entry'):NAT.index('</rules>')].replace('name="outbound"', 'name="second"').replace('<member>net</member>', '<member>second-net</member>')
    nat = NAT.replace('</rules>', second + '</rules>')
    source = SOURCE.replace('</address>', f'<entry name="second-net"><ip-netmask>{second_prefix}</ip-netmask></entry></address>', 1)
    plan, rendered, _ = run_migration_pipeline(analyze(source.replace('</rulebase>', nat + '</rulebase>')), options)
    assert ('config firewall central-snat-map' in rendered.text) is executable
    if executable:
        items = [row for row in plan.items if row.family == 'nat']
        assert [item.source_name for item in items] == ['outbound', 'second']
        assert [item.target_name for item in items] == ['1', '2']


@pytest.mark.parametrize("change", [
    lambda n: n.replace('<ip>192.0.2.1</ip>', ''),
    lambda n: n.replace('<ip>192.0.2.1</ip>', '<ip>192.0.2.2</ip>'),
    lambda n: n.replace('</entry></rules>', '<destination-translation><translated-address>10.0.0.2</translated-address></destination-translation></entry></rules>'),
    lambda n: n.replace('<disabled>no</disabled>', ''),
    lambda n: n.replace('<service>any</service>', '<service>web</service>'),
])
def test_unverified_nat_blocks_consuming_security_policies(analyze, options, change):
    _, rendered, _ = run_migration_pipeline(analyze(SOURCE.replace('</rulebase>', change(NAT) + '</rulebase>')), options)
    assert 'config firewall central-snat-map' not in rendered.text
    assert 'config firewall policy' not in rendered.text
    assert any(row["family"] == "nat" and row["render_disposition"] == "BLOCK" for row in rendered.report["items"])


def test_multiple_nat_rules_do_not_silently_drop_no_nat_precedence(analyze, options):
    nat = NAT.replace('</rules>', '<entry name="no-nat"><from><member>trust</member></from><to><member>untrust</member></to><source><member>any</member></source><destination><member>any</member></destination><service>any</service><disabled>no</disabled></entry></rules>')
    _, rendered, _ = run_migration_pipeline(analyze(SOURCE.replace('</rulebase>', nat + '</rulebase>')), options)
    assert 'config firewall central-snat-map' not in rendered.text
    assert 'config firewall policy' not in rendered.text


def test_pool_requires_confirmed_return_routing_and_never_enables_proxy_arp(analyze, options):
    nat = NAT.replace('<interface-address><interface>ethernet1/2</interface><ip>192.0.2.1</ip></interface-address>', '<translated-address><member>203.0.113.10</member></translated-address>')
    analysis = analyze(SOURCE.replace('</rulebase>', nat + '</rulebase>'))
    _, rendered, _ = run_migration_pipeline(analysis, options)
    assert 'config firewall central-snat-map' not in rendered.text
    opts = deepcopy(options)
    opts['profile']['pool_return_routing'] = 'confirmed'
    _, rendered, _ = run_migration_pipeline(analysis, opts)
    assert 'set arp-reply "disable"' in rendered.text
    assert 'config firewall central-snat-map' in rendered.text


@pytest.mark.parametrize('interval,expected', [('08:00-17:00', True), ('22:00-05:00', False), ('99:00-17:00', False)])
def test_recurring_schedule_requires_timezone_and_supported_interval(analyze, options, interval, expected):
    schedule = f'<schedule><entry name="hours"><schedule-type><recurring><daily><member>{interval}</member></daily></recurring></schedule-type></entry></schedule>'
    analysis = analyze(SOURCE.replace('<address>', schedule + '<address>', 1))
    _, rendered, _ = run_migration_pipeline(analysis, options)
    assert 'config firewall schedule recurring' not in rendered.text
    _, rendered, _ = run_migration_pipeline(analysis, {**options, 'timezone': 'Asia/Kuala_Lumpur'})
    assert ('config firewall schedule recurring' in rendered.text) is expected, [(r['source_name'], r['blocking_reasons']) for r in rendered.report['items'] if r['family'] == 'schedule']


def test_destination_reuse_is_exact_and_absence_is_not_assumed(analysis, options):
    plan, _, parsed = run_migration_pipeline(analysis, options)
    address = next(i for i in plan.items if i.family == 'address')
    text = '''#config-version=FGT-7.4.6-FW-build0001-1
config system global
 set vdom-mode no-vdom
end
config system settings
 set opmode nat
 set ngfw-mode profile-based
 set central-nat enable
end
config firewall address
 edit net
  set type ipmask
  set subnet 10.0.0.0 255.255.255.0
 next
end
'''
    evidence = build_target_evidence(source_reporters.get('fortigate').analyze_source(text), 'target')
    compared = classify_target_reuse((address,), evidence, parsed)
    assert compared[0].disposition == 'REUSE'
    assert not compared[0].reasons
    for bad in (text.replace('10.0.0.0', '10.1.0.0'), text.replace('set opmode nat', 'set opmode transparent'), text.replace('set vdom-mode no-vdom', ''), text.replace('7.4.6', '7.4.8')):
        evidence = build_target_evidence(source_reporters.get('fortigate').analyze_source(bad), 'target')
        compared = classify_target_reuse((address,), evidence, parsed)
        assert compared[0].reasons
    unknown = text[:text.index('config firewall address')]
    evidence = build_target_evidence(source_reporters.get('fortigate').analyze_source(unknown), 'target')
    assert classify_target_reuse((address,), evidence, parsed)[0].reasons
    evidence = build_target_evidence(source_reporters.get('fortigate').analyze_source(unknown + 'config firewall address\nend\n'), 'target')
    assert not classify_target_reuse((address,), evidence, parsed)[0].reasons


def test_additive_interface_configuration_requires_explicit_unassigned_unreferenced_port(analysis, options):
    plan, _, parsed = run_migration_pipeline(analysis, options)
    interface = next(i for i in plan.items if i.family == 'interface' and i.target_name == 'port1')
    text = '''#config-version=FGT-7.4.6-FW-build0001-1
config system global
 set vdom-mode no-vdom
end
config system settings
 set opmode nat
 set ngfw-mode profile-based
 set central-nat enable
end
config system interface
 edit port1
  set type physical
  set ip 0.0.0.0 0.0.0.0
 next
end
'''
    evidence = build_target_evidence(source_reporters.get('fortigate').analyze_source(text), 'target')
    compared = classify_target_reuse((interface,), evidence, parsed)[0]
    assert not compared.reasons
    assert compared.disposition == 'CONFIGURE'
    assert dict(compared.settings) == {'ip': ('10.0.0.1', '255.255.255.0')}
    for changed in (text.replace('0.0.0.0 0.0.0.0', '192.0.2.1 255.255.255.0'), text.replace('set ip 0.0.0.0 0.0.0.0', ''),
                    text + 'config system zone\n edit used\n set interface port1\n next\nend\n'):
        evidence = build_target_evidence(source_reporters.get('fortigate').analyze_source(changed), 'target')
        assert classify_target_reuse((interface,), evidence, parsed)[0].reasons


@pytest.mark.parametrize('field,value', [('zones', {'trust': 'any'}), ('interfaces', {'ethernet1/1': 'all'}), ('zones', {'trust': 'port1'})])
def test_wildcards_and_shared_placement_names_are_rejected(options, field, value):
    with pytest.raises(ValueError):
        FGMigrationOptions(**{**options, field: value})


def test_static_route_preserves_explicit_next_hop_and_requires_routing_mapping(analyze, options):
    router = '''<virtual-router><entry name="vr"><interface><member>ethernet1/2</member></interface><routing-table><ip><static-route><entry name="default"><destination>0.0.0.0/0</destination><interface>ethernet1/2</interface><nexthop><ip-address>192.0.2.254</ip-address></nexthop><admin-dist>10</admin-dist></entry></static-route></ip></routing-table></entry></virtual-router>'''
    source = SOURCE.replace('</interface></network>', '</interface>' + router + '</network>', 1).replace('</interface></network></import>', '</interface><virtual-router><member>vr</member></virtual-router></network></import>')
    analysis = analyze(source)
    _, rendered, _ = run_migration_pipeline(analysis, options)
    assert 'config router static' not in rendered.text
    _, rendered, _ = run_migration_pipeline(analysis, {**options, 'routers': {'vr': 0}})
    route = next(r for r in rendered.report['items'] if r['family'] == 'static_route')
    assert not route['blocking_reasons'], route['blocking_reasons']
    assert 'set gateway "192.0.2.254"' in rendered.text
    assert 'set distance "10"' in rendered.text


def dnat_source():
    nat = '''<nat><rules><entry name="publish"><from><member>untrust</member></from><to><member>untrust</member></to><source><member>any</member></source><destination><member>public</member></destination><service>any</service><disabled>no</disabled><destination-translation><translated-address>10.0.0.10</translated-address></destination-translation></entry></rules></nat>'''
    source = SOURCE.replace('</address>', '<entry name="public"><ip-netmask>203.0.113.10/32</ip-netmask></entry></address>')
    source = source.replace('<from><member>trust</member></from><to><member>untrust</member></to>', '<from><member>untrust</member></from><to><member>trust</member></to>')
    source = source.replace('<source><member>clients</member></source><destination><member>any</member></destination>', '<source><member>any</member></source><destination><member>public</member></destination>')
    source = source.replace('<service><member>web</member></service>', '<service><member>any</member></service>')
    return source.replace('</rulebase>', nat + '</rulebase>')


def test_static_dnat_rewrites_postnat_match_and_excludes_direct_private_packets(analyze, options):
    from .conftest import options as mapping_fixture

    analysis = analyze(dnat_source())
    opts = mapping_fixture.__wrapped__(analysis)
    opts['profile'].update({'traffic_baseline': 'empty', 'vip_arp_reply': 'enable'})
    _, rendered, _ = run_migration_pipeline(analysis, opts)
    nat = next(r for r in rendered.report['items'] if r['family'] == 'nat')
    policy = next(r for r in rendered.report['items'] if r['family'] == 'policy')
    host = next(r for r in rendered.report['items'] if r['family'] == 'dnat_address')
    assert not nat['blocking_reasons'], nat['blocking_reasons']
    assert not policy['blocking_reasons'], policy['blocking_reasons']
    assert dict(nat['settings'])['extip'] == ('203.0.113.10',)
    assert dict(nat['settings'])['mappedip'] == ('10.0.0.10',)
    assert dict(nat['settings'])['srcintf-filter'] == ('port2',)
    assert dict(policy['settings'])['dstaddr'] == (host['target_name'],)
    assert dict(policy['settings'])['match-vip-only'] == ('enable',)
    assert dict(host['settings'])['subnet'] == ('10.0.0.10', '255.255.255.255')
    assert rendered.text.index('config firewall vip') < rendered.text.index('config firewall policy')


@pytest.mark.parametrize('change', [
    lambda s: s.replace('<translated-address>10.0.0.10</translated-address>', '<translated-address>10.0.0.10</translated-address><translated-port>8443</translated-port>'),
    lambda s: s.replace('<translated-address>10.0.0.10</translated-address>', '<translated-address>10.20.0.10</translated-address>'),
    lambda s: s.replace('203.0.113.10/32', '203.0.113.0/24'),
    lambda s: s.replace('<negate-destination>no</negate-destination>', '<negate-destination>yes</negate-destination>'),
])
def test_dnat_never_broadens_unverified_address_port_or_negated_matches(analyze, options, change):
    from .conftest import options as mapping_fixture

    analysis = analyze(change(dnat_source()))
    opts = mapping_fixture.__wrapped__(analysis)
    opts['profile'].update({'traffic_baseline': 'empty', 'vip_arp_reply': 'disable'})
    _, rendered, _ = run_migration_pipeline(analysis, opts)
    assert 'config firewall vip' not in rendered.text
    assert 'config firewall policy' not in rendered.text
