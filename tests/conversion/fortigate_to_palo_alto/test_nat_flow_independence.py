from dataclasses import replace

from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedNATRule
from fwmigrate.conversion.fortigate_to_palo_alto.planning.nat import _packet_disjoint_test
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


def test_independence_requires_a_proof_including_the_translated_destination():
    analysis = FortiGateSourceReporter().analyze_source('''config system interface
edit inside
set type physical
next
edit outside
set type physical
next
end
config firewall vip
edit published
set type static-nat
set extintf outside
set extip 192.0.2.1
set mappedip 198.51.100.1
next
end
config firewall policy
edit 1
set srcintf inside
next
end
config firewall address
edit clients
set subnet 10.0.0.0 255.255.255.0
next
edit others
set subnet 10.0.1.0 255.255.255.0
next
edit translated
set subnet 198.51.100.1 255.255.255.255
next
end
config firewall addrgrp
edit nested
set member clients
next
end
''')
    independent = _packet_disjoint_test(analysis.extracted.config)
    snat = PlannedNATRule(source_vdom='root', source_kind='source_nat', source_policy_id=1,
        from_zones=('inside',), source_addresses=('nested',), destination_addresses=('any',))
    dnat = PlannedNATRule(source_vdom='root', source_kind='vip', source_name='published', from_zones=('outside',), source_addresses=('any',),
        destination_addresses=('192.0.2.1',), destination_translated_address='198.51.100.1')
    assert not independent(snat, dnat), 'VIP extintf does not bind DNAT to that ingress'
    analysis.extracted.config.policies[0].srcintf = ['outside']
    independent = _packet_disjoint_test(analysis.extracted.config)
    assert not independent(snat, dnat)
    assert not independent(snat, replace(dnat, source_addresses=('others',)))
    assert not independent(snat, replace(dnat, source_addresses=('missing',)))
    assert not independent(replace(snat, destination_addresses=('translated',)), dnat)
    assert independent(replace(snat, destination_addresses=('203.0.113.0/24',)), dnat)
    assert not independent(replace(snat, source_addresses=('any',), destination_addresses=('203.0.113.0/24',)), dnat), 'Mapped servers can use VIP reverse-SNAT'
    assert not independent(replace(snat, source_addresses=('unknown.example',)), dnat)


def test_cycles_duplicates_and_unknown_scopes_cannot_prove_separation():
    analysis = FortiGateSourceReporter().analyze_source('''config firewall addrgrp
edit cycle
set member cycle
next
end
''')
    independent = _packet_disjoint_test(analysis.extracted.config)
    first = PlannedNATRule(source_vdom='root', from_zones=('any',), source_addresses=('cycle',))
    second = replace(first, source_addresses=('192.0.2.1',))
    assert not independent(first, second)
    assert not independent(replace(first, source_addresses=('missing',)), second)
    assert not independent(replace(first, from_zones=()), second)
