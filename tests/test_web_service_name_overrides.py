import io
from copy import deepcopy
import pytest

from fwmigrate.web import create_app
from tests.approved_design import approved_payload
from types import SimpleNamespace


SOURCE = b'''config firewall service custom
 edit "web"
  set tcp-portrange 443
 next
end
config firewall service group
 edit "web-group"
  set member "web"
 next
end
config firewall policy
 edit 1
  set name "allow-web"
  set srcintf "any"
  set dstintf "any"
  set srcaddr "all"
  set dstaddr "all"
  set service "web-group"
  set schedule "always"
  set action accept
 next
end
'''
TARGET = b'''<config><devices><entry name="fw"><vsys><entry name="vsys1">
<service><entry name="web"><protocol><tcp><port>80</port></tcp></protocol></entry></service>
</entry></vsys></entry></devices></config>'''


def payload(client):
    def upload(text, vendor):
        response = client.post('/api/preview', data={'source_vendor': vendor,
            'file': (io.BytesIO(text), 'source.conf' if vendor == 'fortigate' else 'target.xml')})
        assert response.status_code == 200
        return response.get_json()['source_evidence']
    return {'source': upload(SOURCE, 'fortigate'), 'target_source': upload(TARGET, 'palo_alto'),
            'reference_role': 'DESTINATION'}


def test_service_conflict_rename_rebinds_group_policy_and_export_only_after_approval():
    client = create_app({'TESTING': True}).test_client()
    request = payload(client)
    draft = client.post('/api/migration/design/prepare', json=request).get_json()['draft']
    service = next(row for row in draft['configuration'] if row['family'] == 'service')
    assert service['status'] == 'CONFLICT'
    assert service['target_comparison']['status'] == 'NAME_CONFLICT'
    assert service['target_comparison']['evidence']
    assert not any(row['source_name'] == 'any' for row in draft['decisions'])
    request['service_name_overrides'] = {'root': {'web': 'FG-web'}}
    proposed = client.post('/api/migration/design/prepare', json=request).get_json()
    assert next(row for row in proposed['draft']['configuration'] if row['family'] == 'service')['target_name'] == 'FG-web'
    assert client.post('/api/migrate', json={**request, 'decision_document': proposed['decision_document']}).status_code == 400
    approved = approved_payload(client, request)
    result = client.post('/api/migrate', json=approved)
    assert result.status_code == 200, result.get_json()
    plan = result.get_json()
    assert plan['artifact']['mapping']['service_names'] == {'root': {'web': 'FG-web'}}
    assert any('service FG-web protocol tcp port 443' in c for c in plan['commands'])
    assert any('service-group web-group members [ FG-web ]' in c for c in plan['commands'])
    assert any('rulebase security rules allow-web from [ any ]' in c for c in plan['commands'])
    assert not any('root-any' in c for c in plan['commands'])
    altered = deepcopy(approved)
    altered['service_name_overrides']['root']['web'] = 'tampered'
    assert client.post('/api/migrate', json=altered).status_code == 400
    export = client.post('/api/migration/bundle', json={'source': request['source'], 'artifact': plan['artifact']})
    assert export.status_code == 200


@pytest.mark.parametrize('names', [{'root': {'missing': 'new'}}, {'blue': {'web': 'new'}},
    {'root': {'web': 'any'}}, {'root': {'web': 'a'*64}}, {'root': {'web': 'bad\nname'}}, []])
def test_service_name_overrides_reject_invalid_or_unknown_identity(names):
    client = create_app({'TESTING': True}).test_client()
    request = {**payload(client), 'service_name_overrides': names}
    assert client.post('/api/migration/design/prepare', json=request).status_code == 400


def test_service_rename_keeps_vdom_group_policy_and_nat_references_consistent():
    from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.services import plan_services
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.policies import plan_policies
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.nat import plan_nat
    from fwmigrate.vendors.fortigate.model.source import FGConfig
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    from fwmigrate.vendors.fortigate.model.service import FGService, FGServiceGroup
    from fwmigrate.vendors.fortigate.transform.services import transform_services
    source = FGConfig(
        services=[FGService(vdom=vdom, name='web', tcp_portrange='443') for vdom in ('root', 'blue')],
        service_groups=[FGServiceGroup(vdom=vdom, name='web-group', members=['web']) for vdom in ('root', 'blue')],
        policies=[FGPolicy(vdom=vdom, policy_id=1, name='allow', srcintf=['any'], dstintf=['wan'],
        srcaddr=['all'], dstaddr=['all'], service=['web'], schedule='always', action='accept') for vdom in ('root', 'blue')])
    derived = SimpleNamespace(services=transform_services(source), nat=[SimpleNamespace(
        vdom='root', policy_id=1, policy_name='allow', issues=[], translation_type='ip_pool',
        pool_names=['POOL'], pool_types=['overload'], translated_addresses=['203.0.113.10'],
        egress_interfaces=['wan'])])
    options = PANMigrationOptions(service_names={'root': {'web': 'FG-web'}},
        vdoms={'root': {'vsys': 'vsys1'}, 'blue': {'vsys': 'vsys2'}},
        interfaces={vdom: {'wan': {'target_interface': 'ethernet1/1', 'target_zone': 'outside'}} for vdom in ('root', 'blue')})
    before = deepcopy(source)
    planned, members = plan_services(derived, options, source)
    assert [s.target_name for s in planned] == ['FG-web', 'web']
    assert [g.members for g in members] == [('FG-web',), ('web',)]
    assert [p.services for p in plan_policies(source, options, derived)] == [('FG-web',), ('web',)]
    assert plan_nat(source, derived, options)[0].service == 'FG-web'
    assert source == before
