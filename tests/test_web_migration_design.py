from copy import deepcopy
import io
import pytest

from fwmigrate.web import create_app


@pytest.mark.parametrize('legacy', ['mapping', 'decisions', 'decision_set', 'decision_document'])
def test_legacy_inputs_cannot_issue_executable_artifacts(legacy):
    client, payload = setup()
    data, payload = allocate(client, payload)
    document = payload.pop('decision_document')
    payload[legacy] = ({'vdoms': {'root': {'vsys': 'vsys1'}}} if legacy == 'mapping' else
                       document if legacy == 'decision_document' else {'decisions': document['decisions']})
    response = client.post('/api/migrate', json=payload)
    assert response.status_code == 400
    assert 'artifact' not in response.get_json()


@pytest.mark.parametrize('change', ['legacy', 'forged', 'digest', 'source', 'target', 'unapproved', 'configuration', 'expired'])
def test_signed_artifact_requires_matching_approved_design_before_deployment(monkeypatch, change):
    import fwmigrate.web as web
    from fwmigrate.web_support.artifact_signing import sign_envelope
    from tests.test_web_candidate_sessions import CREDS
    client, payload = setup(TARGET.replace('name="fw"', 'name="fw" serial="012345678901"'))
    data, payload = allocate(client, payload)
    payload['decision_document'] = approve(client, payload, data).get_json()['decision_document']
    artifact = client.post('/api/migrate', json=payload).get_json()['artifact']
    if change == 'legacy':
        artifact['decision_document'].pop('design_approval')
    elif change == 'forged':
        artifact['decision_document']['design_approval']['signature'] = 'forged'
    elif change == 'digest':
        artifact['report']['approved_design_digest'] = 'different'
    elif change == 'source':
        artifact['report']['source']['digest'] = 'different'
    elif change == 'target':
        artifact['report']['target_evidence']['serial'] = 'different'
    elif change == 'expired':
        approval = artifact['decision_document']['design_approval']
        approval['expires_at'] = 0
        artifact['decision_document']['design_approval'] = sign_envelope(approval, b'd' * 32)
    elif change == 'configuration':
        artifact['report']['items'][0]['target_name'] = 'unapproved-name'
    else:
        approval = artifact['decision_document']['design_approval']
        approval['configuration'] = {}
        artifact['decision_document']['design_approval'] = sign_envelope(approval, b'd' * 32)
    artifact = sign_envelope(artifact, b'd' * 32)
    monkeypatch.setattr(web, 'PANSSHDeployer', lambda *_: pytest.fail('Invalid approval must not connect'))
    response = client.post('/api/deploy', json={**CREDS, 'artifact': artifact})
    assert response.status_code == 400
    if change == 'expired':
        assert response.get_json()['error_code'] == 'artifact_ineligible'
        assert 'expired' in response.get_json()['error']


def test_hostname_evidence_does_not_allow_live_candidate_preparation(monkeypatch):
    import fwmigrate.web as web
    from tests.test_web_candidate_sessions import CREDS
    client, payload = setup()
    data, payload = allocate(client, payload)
    payload['decision_document'] = approve(client, payload, data).get_json()['decision_document']
    artifact = client.post('/api/migrate', json=payload).get_json()['artifact']
    assert artifact['report']['plan_status'] == 'READY'
    assert artifact['report']['deployment_eligibility']['eligible'] is False
    assert 'serial evidence' in artifact['report']['deployment_eligibility']['reason']
    monkeypatch.setattr(web, 'PANSSHDeployer', lambda *_: pytest.fail('Hostname must not be used as serial'))
    response = client.post('/api/deploy', json={**CREDS, 'artifact': artifact})
    assert response.status_code == 400
    assert 'serial evidence' in response.get_json()['error']


def test_serial_evidence_enables_candidate_preparation():
    client, payload = setup(TARGET.replace('name="fw"', 'name="fw" serial="012345678901"'))
    data, payload = allocate(client, payload)
    payload['decision_document'] = approve(client, payload, data).get_json()['decision_document']
    payload['compact_response'] = True
    result = client.post('/api/migrate', json=payload).get_json()
    assert result['artifact']['report']['deployment_eligibility'] == {'eligible': True, 'reason': None}


SOURCE = '''config system interface
    edit "port1"
        set type physical
        set ip 192.0.2.1 255.255.255.0
    next
    edit "vlan10"
        set interface "port1"
        set vlanid 10
        set ip 198.51.100.1 255.255.255.0
    next
end
config firewall address
    edit "net"
        set subnet 192.0.2.0 255.255.255.0
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 192.0.2.254
        set device "port1"
    next
end
'''


def test_conversion_settings_are_bound_to_approval_and_rechecked_at_export():
    client, payload = setup(None)
    data, payload = allocate(client, {**payload, 'workflow_mode': 'OFFLINE_EXPORT',
        'conversion_settings': {'target_model': 'PA-820', 'panos_version': '11.1'}})
    response = approve(client, payload, data)
    assert response.status_code == 200, response.get_json()
    approved = {**payload, 'decision_document': response.get_json()['decision_document']}
    assert client.post('/api/migrate', json=approved).status_code == 200
    changed = {**approved, 'conversion_settings': {'panos_version': '11.1'}}
    assert client.post('/api/migrate', json=changed).status_code == 400
    rebuilt = client.post('/api/migration/design/prepare', json=changed).get_json()
    assert not rebuilt['approval_readiness']['current']
    assert all(not row['approved'] for row in rebuilt['draft']['decisions'])


def test_automatic_names_profile_mapping_and_split_nat_export_the_approved_values():
    from tests.conversion.fortigate_to_palo_alto.test_policy_nat_automation import SOURCE as NAT_SOURCE
    source = NAT_SOURCE.replace('web', 'web/8443')
    client, payload = setup(None, source=source)
    data, payload = prepare(client, {**payload, 'workflow_mode': 'OFFLINE_EXPORT'})
    group = next(row for row in data['draft']['findings'] if row['code'] == 'SECURITY_PROFILE_REQUIRED')
    data, payload = prepare(client, {**payload, 'conversion_settings': {'panos_version': '11.1',
        'security_profiles': {group['identity']: 'reviewed-protection'}}})
    service = next(row for row in data['draft']['configuration'] if row['source_name'] == 'web/8443')
    assert service['status'] == 'READY' and '/' not in service['target_name']
    nat = [row for row in data['draft']['configuration'] if row['family'] == 'nat_rule']
    assert len(nat) == 2 and all(row['status'] == 'READY' for row in nat)
    response = approve(client, payload, data)
    assert response.status_code == 200, response.get_json()
    payload['decision_document'] = response.get_json()['decision_document']
    response = client.post('/api/migrate', json=payload)
    assert response.status_code == 200, response.get_json()
    result = response.get_json()
    assert any(command.endswith('profile-setting group [ reviewed-protection ]') for command in result['commands'])
    assert any(command.endswith('service ' + service['target_name']) for command in result['commands'])
    downloaded = client.post('/api/migration/download', json={'source': payload['source'], 'artifact': result['artifact']})
    assert downloaded.status_code == 200
    assert downloaded.data == '\n'.join(result['commands']).encode()


@pytest.mark.parametrize('settings', [{'target_model': 'guessed'}, {'panos_version': '99'},
    {'vpn_parameters': {'root/ipsec_phase1/site': {'psk': 'must-not-be-accepted'}}},
    {'existing_vpns': ['root/missing']}, {'excluded_interfaces': ['root/missing']},
    {'security_profiles': {'root/missing': 'unreviewed'}}])
def test_conversion_settings_reject_unsupported_fields_and_stale_source_identities(settings):
    client, payload = setup(None)
    response = client.post('/api/migration/design/prepare', json={**payload, 'workflow_mode': 'OFFLINE_EXPORT', 'conversion_settings': settings})
    assert response.status_code == 400
TARGET = '''<config><devices><entry name="fw"><network><interface><ethernet>
<entry name="ethernet1/1"><layer3/></entry></ethernet></interface></network>
<vsys><entry name="vsys1"/></vsys></entry></devices></config>'''


def setup(target=TARGET, role='DESTINATION', source=SOURCE):
    client = create_app({'TESTING': True, 'WEB_MODE': 'local', 'WORKSPACE_SIGNING_KEY': 'd' * 32}).test_client()
    def upload(text, vendor, name):
        result = client.post('/api/preview', data={'source_vendor': vendor,
            'file': (io.BytesIO(text.encode()), name)}, content_type='multipart/form-data')
        assert result.status_code == 200, result.get_json()
        return result.get_json()['source_evidence']
    payload = {'source': upload(source, 'fortigate', 'source.conf')}
    if target is not None:
        payload.update(target_source=upload(target, 'palo_alto', 'target.xml'), reference_role=role)
    return client, payload


def test_offline_source_upload_approval_and_identical_exports(monkeypatch):
    import hashlib
    import zipfile
    import fwmigrate.web as web
    from tests.test_web_candidate_sessions import CREDS

    client, payload = setup(None)
    payload['workflow_mode'] = 'OFFLINE_EXPORT'
    data, payload = allocate(client, payload)
    assert data['draft']['context']['workflow_mode'] == 'OFFLINE_EXPORT'
    assert not data['draft']['destination_verified']
    assert all(row['review_state'] == 'PENDING' for row in data['decisions']['decisions'])
    assert not any(row['operation'] in {'REUSE', 'CONFIGURE'} for row in data['draft']['decisions'])
    assert client.post('/api/migrate', json=payload).status_code == 400
    approved = approve(client, payload, data)
    assert approved.status_code == 200, approved.get_json()
    payload['decision_document'] = approved.get_json()['decision_document']
    response = client.post('/api/migrate', json=payload)
    assert response.status_code == 200, response.get_json()
    plan = response.get_json()
    assert plan['plan_status'] == 'READY'
    assert plan['report']['readiness']['migration']['complete']
    assert not plan['report']['destination_verified']
    assert not plan['report']['deployment_eligibility']['eligible']
    assert plan['target_object_reuse'] == []
    assert any('units ethernet1/1.10 tag 10' in command for command in plan['commands'])
    artifact = plan['artifact']
    request = {'source': payload['source'], 'artifact': artifact}
    preview = client.post('/api/migration/command-preview', json=request)
    download = client.post('/api/migration/download', json=request)
    bundle = client.post('/api/migration/bundle', json=request)
    assert preview.status_code == download.status_code == bundle.status_code == 200
    expected = '\n'.join(plan['commands']).encode()
    assert download.data == expected
    assert hashlib.sha256(expected).hexdigest() == artifact['command_sha256']
    assert preview.get_json()['commands'] == plan['commands']
    with zipfile.ZipFile(io.BytesIO(bundle.data)) as archive:
        commands = next(name for name in archive.namelist() if name.endswith('.set'))
        assert archive.read(commands) == expected
    monkeypatch.setattr(web, 'PANSSHDeployer', lambda *_: pytest.fail('Offline artifacts must not connect'))
    for endpoint in ('deploy', 'validate-candidate', 'commit'):
        assert client.post('/api/' + endpoint, json={**CREDS, 'artifact': artifact}).status_code == 400


def test_generated_management_profile_is_signed_with_its_interface_dependencies():
    source = SOURCE.replace('set type physical', 'set type physical\nset allowaccess ping ssh')
    client, payload = setup(None, source=source)
    data, payload = prepare(client, {**payload, 'workflow_mode': 'OFFLINE_EXPORT', 'conversion_settings': {
        'generated_management_profiles': {'root/ping,ssh': {'permitted_ips': ['192.0.2.0/24']}}}})
    profile = next(row for row in data['draft']['configuration'] if row['family'] == 'management_profile')
    interface = next(row for row in data['draft']['configuration'] if row['family'] == 'interface' and row['source_name'] == 'port1')
    assert profile['status'] == interface['status'] == 'READY'
    assert profile['group_key'] in interface['dependencies']
    approved = approve(client, payload, data)
    assert approved.status_code == 200, approved.get_json()
    request = {**payload, 'decision_document': approved.get_json()['decision_document']}
    generated = client.post('/api/migrate', json=request)
    assert generated.status_code == 200, generated.get_json()
    result = generated.get_json()
    assert any('interface-management-profile' in command and 'permitted-ip 192.0.2.0/24' in command for command in result['commands'])
    changed = {**request, 'conversion_settings': {'generated_management_profiles': {'root/ping,ssh': {'permitted_ips': ['198.51.100.0/24']}}}}
    assert client.post('/api/migrate', json=changed).status_code == 400


def test_vip_address_can_be_approved_while_its_interface_and_nat_remain_blocked():
    source = SOURCE.replace('set ip 192.0.2.1 255.255.255.0', 'set ip malformed-primary') + '''config firewall vip
edit published
set type static-nat
set extintf port1
set extip 203.0.113.10
set mappedip 198.51.100.10
next
end
config firewall policy
edit 1
set srcintf port1
set dstintf vlan10
set srcaddr all
set dstaddr published
set action accept
set schedule always
set service ALL
next
end
'''
    client, payload = setup(None, source=source)
    data, payload = prepare(client, {**payload, 'workflow_mode': 'OFFLINE_EXPORT'})
    address = next(row for row in data['draft']['configuration'] if row['family'] == 'address' and row['source_name'] == 'published')
    assert address['status'] == 'READY'
    assert next(row for row in data['draft']['configuration'] if row['family'] == 'nat_rule')['status'] != 'READY'
    approved = approve(client, payload, data, [address['group_key'], *address['dependencies']])
    assert approved.status_code == 200, approved.get_json()
    result = client.post('/api/migrate', json={**payload, 'decision_document': approved.get_json()['decision_document']}).get_json()
    assert result['commands'] == ['set vsys vsys1 address published ip-netmask 203.0.113.10/32']
    assert not any(row['rendered'] for row in result['report']['items'] if row['source_object_type'] in {'nat_rule', 'security_rule', 'interface'})


def test_partial_approval_explains_supported_unselected_and_unsupported_items():
    source = SOURCE + '''config firewall address
edit another
set subnet 198.51.100.0 255.255.255.0
next
edit unsupported
set wildcard-fqdn *.example.com
next
end
'''
    client, payload = setup(None, source=source)
    payload['workflow_mode'] = 'OFFLINE_EXPORT'
    data, payload = prepare(client, payload)
    address = next(row for row in data['draft']['configuration'] if row['family'] == 'address' and row['source_name'] == 'net')
    approved = approve(client, payload, data, [address['group_key'], *address['dependencies']])
    assert approved.status_code == 200
    payload['decision_document'] = approved.get_json()['decision_document']
    result = client.post('/api/migrate', json={**payload, 'compact_response': True}).get_json()
    report = result['artifact']['report']
    addresses = {row['source_name']: row for row in report['items'] if row['source_object_type'] == 'address'}
    assert addresses['net']['export_category'] == 'INCLUDED'
    assert addresses['another']['export_category'] == 'NOT_APPROVED'
    assert addresses['unsupported']['export_category'] == 'UNSUPPORTED'
    assert addresses['another']['commands'] == addresses['unsupported']['commands'] == []
    assert sum(report['export_counts'].values()) == len(report['items'])
    assert len(result['artifact']['commands']) == 1
    downloaded = client.post('/api/migration/download', json={'artifact': result['artifact']})
    assert downloaded.status_code == 200
    assert downloaded.data.decode() == result['artifact']['commands'][0]


@pytest.mark.parametrize('change', ['mode', 'source', 'mapping', 'configuration'])
def test_offline_approval_rejects_changed_context(change):
    client, payload = setup(None)
    payload['workflow_mode'] = 'OFFLINE_EXPORT'
    data, payload = allocate(client, payload)
    payload['decision_document'] = approve(client, payload, data).get_json()['decision_document']
    if change == 'mode':
        payload['workflow_mode'] = 'DESTINATION_AWARE'
    elif change == 'source':
        payload['source'] = {**payload['source'], 'source_text': SOURCE.replace('192.0.2.0', '203.0.113.0')}
    elif change == 'mapping':
        payload['draft_overrides'] = {key: 'ethernet1/2' for key in payload['draft_overrides']}
    else:
        payload['service_name_overrides'] = {'root': {'new': 'changed'}}
    assert client.post('/api/migrate', json=payload).status_code == 400


def test_offline_unapproved_port_proposals_allow_only_independently_approved_objects():
    client, payload = setup(None)
    data, payload = prepare(client, {**payload, 'workflow_mode': 'OFFLINE_EXPORT'})
    port = next(row for row in data['draft']['decisions'] if row['source_name'] == 'port1'
                and row['target_field'] == 'target_interface')
    assert port['proposed_value'] == 'ethernet1/1' and port['status'] == 'READY'
    assert not port['approved']
    assert next(row for row in data['draft']['configuration'] if row['family'] == 'address')['status'] == 'READY'
    selected = [row['decision_key'] for row in data['draft']['decisions'] if row['target_field'] == 'vsys']
    selected += [row['group_key'] for row in data['draft']['configuration'] if row['family'] == 'address']
    payload['decision_document'] = approve(client, payload, data, selected).get_json()['decision_document']
    response = client.post('/api/migrate', json=payload)
    assert response.status_code == 200, response.get_json()
    plan = response.get_json()
    assert plan['plan_status'] == 'NEEDS_MAPPING'
    assert not plan['report']['readiness']['migration']['complete']
    assert plan['commands'] == ['set vsys vsys1 address net ip-netmask 192.0.2.0/24']


def test_offline_does_not_parse_or_discover_supplied_destination(monkeypatch):
    import fwmigrate.web_api.migration as api
    client, payload = setup(None)
    analyze = api.analyze_request_source
    def source_only(payload, vendor, **kwargs):
        assert vendor == 'fortigate'
        return analyze(payload, vendor, **kwargs)
    monkeypatch.setattr(api, 'analyze_request_source', source_only)
    data, _ = prepare(client, {**payload, 'workflow_mode': 'OFFLINE_EXPORT',
                              'target_source': {'source_text': 'not XML'}, 'target_device': 'unused'})
    assert not data['draft']['destination_verified']
    assert data['target_evidence'] is None


@pytest.mark.parametrize('offline', [True, False])
def test_subinterface_identifier_is_independent_of_vlan_tag(offline):
    client, payload = setup(None if offline else TARGET)
    if offline:
        payload['workflow_mode'] = 'OFFLINE_EXPORT'
    data, payload = allocate(client, payload)
    vlan = next(row['decision_key'] for row in data['draft']['decisions']
                if row['source_name'] == 'vlan10' and row['target_field'] == 'target_interface')
    data, payload = prepare(client, {**payload, 'draft_overrides': {**payload['draft_overrides'], vlan: 'ethernet1/1.200'}})
    approved = approve(client, payload, data)
    assert approved.status_code == 200, approved.get_json()
    plan = client.post('/api/migrate', json={**payload, 'decision_document': approved.get_json()['decision_document']})
    assert plan.status_code == 200, plan.get_json()
    assert 'set network interface ethernet ethernet1/1 layer3 units ethernet1/1.200 tag 10' in plan.get_json()['commands']


def test_offline_address_service_only_and_unsupported_coverage():
    client, payload = setup(None)
    source = '''config firewall address
 edit Web_Server
  set subnet 192.0.2.10 255.255.255.255
 next
end
config firewall service custom
 edit TCP_8443
  set tcp-portrange 8443
 next
end
'''
    for unsupported in ('', 'config user local\n edit manual\n set type password\n next\nend\n'):
        evidence = client.post('/api/preview', data={'source_vendor': 'fortigate',
            'file': (io.BytesIO((source + unsupported).encode()), 'objects.conf')}).get_json()['source_evidence']
        data, payload = prepare(client, {'source': evidence, 'workflow_mode': 'OFFLINE_EXPORT'})
        scope = next(row for row in data['draft']['decisions'] if row['target_field'] == 'vsys')
        assert scope['proposed_value'] == 'vsys1' and not scope['approved']
        assert not any(row['target_field'] == 'target_interface' for row in data['draft']['decisions'])
        approved = approve(client, payload, data)
        assert approved.status_code == 200, approved.get_json()
        plan = client.post('/api/migrate', json={**payload, 'decision_document': approved.get_json()['decision_document']}).get_json()
        assert plan['plan_status'] == ('PARTIAL' if unsupported else 'READY')
        assert any('address Web_Server ip-netmask' in command for command in plan['commands'])
        assert any('service TCP_8443 protocol tcp port 8443' in command for command in plan['commands'])
        if unsupported:
            assert plan['report']['coverage']['unplanned']


@pytest.mark.parametrize('mode', ['', 'unknown', False, [], {}])
def test_invalid_workflow_mode_is_rejected(mode):
    client, payload = setup(None)
    assert client.post('/api/migration/design/prepare', json={**payload, 'workflow_mode': mode}).status_code == 400


def test_offline_service_name_collisions_block_approval():
    client, _ = setup(None)
    source = '''config firewall service custom
 edit source-service
 set tcp-portrange 8443
 next
end
config firewall service group
 edit bundle
 set member source-service
 next
end
'''
    evidence = client.post('/api/preview', data={'source_vendor': 'fortigate',
        'file': (io.BytesIO(source.encode()), 'services.conf')}).get_json()['source_evidence']
    data, payload = prepare(client, {'source': evidence, 'workflow_mode': 'OFFLINE_EXPORT',
        'service_name_overrides': {'root': {'source-service': 'bundle'}}})
    services = [row for row in data['draft']['configuration'] if row['family'] in {'service', 'service_group'}]
    assert len(services) == 2 and all(row['status'] == 'CONFLICT' for row in services)
    assert approve(client, payload, data, [row['group_key'] for row in services]).status_code == 409


def test_offline_parent_proposal_unlocks_policy_nat_dhcp_and_routing_but_requires_approval():
    client, _ = setup(None)
    source = SOURCE + '''config firewall policy
 edit 1
  set name outbound
  set srcintf port1
  set dstintf vlan10
  set srcaddr all
  set dstaddr all
  set service ALL
  set schedule always
  set action accept
  set nat enable
 next
end
config system dhcp server
 edit 1
  set interface vlan10
  set status enable
  set server-type regular
  set ip-mode range
  set default-gateway 198.51.100.1
  set netmask 255.255.255.0
  config ip-range
   edit 1
    set start-ip 198.51.100.10
    set end-ip 198.51.100.50
   next
  end
 next
end
'''
    evidence = client.post('/api/preview', data={'source_vendor': 'fortigate',
        'file': (io.BytesIO(source.encode()), 'forwarding.conf')}).get_json()['source_evidence']
    data, payload = prepare(client, {'source': evidence, 'workflow_mode': 'OFFLINE_EXPORT'})
    dependent_families = {'security_rule', 'nat_rule', 'dhcp_server', 'static_route', 'zone'}
    assert client.post('/api/migrate', json=payload).status_code == 400
    assert all(row['review_state'] == 'PENDING' for row in data['decisions']['decisions'])
    assert not data['draft']['context']['overrides']
    rows = [row for row in data['draft']['configuration'] if row['family'] in dependent_families]
    assert {row['family'] for row in rows} == dependent_families
    assert all(row['status'] == 'READY' for row in rows), [(row['family'], row['status'], row['blocking_reasons']) for row in rows]
    approved = approve(client, payload, data)
    assert approved.status_code == 200, approved.get_json()
    response = client.post('/api/migrate', json={**payload, 'decision_document': approved.get_json()['decision_document']})
    assert response.status_code == 200, response.get_json()
    plan = response.get_json()
    assert plan['plan_status'] == 'READY'
    for section in ('rulebase security rules', 'rulebase nat rules', 'network dhcp interface',
                    'routing-table ip static-route', 'zone root-'):
        assert any(section in command for command in plan['commands']), section


def prepare(client, payload):
    response = client.post('/api/migration/design/prepare', json=payload)
    assert response.status_code == 200, response.get_json()
    data = response.get_json()
    return data, {**payload, 'decision_document': data['decision_document']}


@pytest.mark.parametrize('unsupported', [False, True])
def test_offline_loopbacks_require_approval_and_gate_dependent_routes_and_policies(unsupported):
    source = '''config system interface
edit lo1
set type loopback
set ip 192.0.2.1 255.255.255.255
%s
next
edit lo2
set type loopback
set ip 198.51.100.1 255.255.255.255
next
end
config router static
edit 1
set dst 203.0.113.0 255.255.255.0
set gateway 192.0.2.254
set device lo1
next
end
config firewall policy
edit 1
set srcintf lo1
set dstintf lo2
set srcaddr all
set dstaddr all
set service ALL
set schedule always
set action accept
next
end
''' % ('set allowaccess ping' if unsupported else '')
    client, payload = setup(None, source=source)
    data, payload = prepare(client, {**payload, 'workflow_mode': 'OFFLINE_EXPORT'})
    identifiers = [row['proposed_value'] for row in data['draft']['decisions'] if row['target_field'] == 'target_interface']
    assert identifiers == ['loopback.1', 'loopback.2']
    assert all(row['review_state'] == 'PENDING' for row in data['decisions']['decisions'])
    assert client.post('/api/migrate', json=payload).status_code == 400
    response = approve(client, payload, data)
    assert response.status_code == 200, response.get_json()
    payload['decision_document'] = response.get_json()['decision_document']
    response = client.post('/api/migrate', json=payload)
    assert response.status_code == 200, response.get_json()
    commands = response.get_json()['commands']
    assert any('loopback units loopback.2' in command for command in commands)
    assert any('loopback units loopback.1' in command for command in commands) == (not unsupported)
    assert any('static-route' in command for command in commands) == (not unsupported)
    assert any('rulebase security' in command for command in commands) == (not unsupported)
    assert not response.get_json()['report']['deployment_eligibility']['eligible']


def allocate(client, payload):
    data, payload = prepare(client, payload)
    key = next(row['decision_key'] for row in data['draft']['decisions']
               if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')
    return prepare(client, {**payload, 'draft_overrides': {key: 'ethernet1/1'}})


def test_offline_aggregate_member_allocations_are_signed_dependencies_of_vlan_export():
    source = '''config system interface
edit port1
set type physical
next
edit port2
set type physical
next
edit bond
set type aggregate
set member port1 port2
set lacp-mode active
next
edit vlan10
set interface bond
set vlanid 10
set ip 198.51.100.1 255.255.255.0
next
end
'''
    client, payload = setup(None, source=source)
    data, payload = prepare(client, {**payload, 'workflow_mode': 'OFFLINE_EXPORT'})
    values = {row['decision_key']: 'ethernet1/' + row['source_name'][-1]
              for row in data['draft']['decisions'] if row['source_name'] in {'port1', 'port2'}}
    data, payload = prepare(client, {**payload, 'draft_overrides': values})
    aggregate = next(row for row in data['draft']['configuration'] if row['source_name'] == 'bond' and row['family'] == 'interface')
    assert aggregate['status'] == 'READY', aggregate
    assert set(values) <= set(aggregate['dependencies'])
    assert aggregate['configuration']['lacp_mode'] == 'active'
    assert not any(row['target_field'] == 'target_zone' and row['source_name'] in {'port1', 'port2'} for row in data['draft']['decisions'])
    approval = approve(client, payload, data)
    assert approval.status_code == 200, approval.get_json()
    payload['decision_document'] = approval.get_json()['decision_document']
    response = client.post('/api/migrate', json=payload)
    assert response.status_code == 200, response.get_json()
    plan = response.get_json()
    assert 'set network interface ethernet ethernet1/1 aggregate-group ae1' in plan['commands']
    assert any('aggregate-ethernet ae1 layer3 units ae1.10 tag 10' in command for command in plan['commands'])
    assert not plan['report']['deployment_eligibility']['eligible']
    # Stale member allocations cannot reuse the signed design.
    payload['draft_overrides'][next(iter(values))] = 'ethernet1/9'
    assert client.post('/api/migrate', json=payload).status_code == 400


def test_offline_vpn_crypto_profile_export_stays_partial_and_never_exports_authentication(monkeypatch):
    source = '''config vpn ipsec phase1-interface
edit peer
set ike-version 2
set authmethod psk
set psksecret test-secret-must-not-export
set proposal aes256-sha256
set dhgrp 14
set keylife 28800
set remote-gw 203.0.113.2
next
end
config vpn ipsec phase2-interface
edit traffic
set phase1name peer
set proposal aes128-sha256
set pfs enable
set dhgrp 14
set keylifeseconds 3600
set src-subnet 192.0.2.0 255.255.255.0
set dst-subnet 198.51.100.0 255.255.255.0
next
end
'''
    client, payload = setup(None, source=source)
    data, payload = prepare(client, {**payload, 'workflow_mode': 'OFFLINE_EXPORT'})
    profiles = [row for row in data['draft']['configuration'] if row['family'] in {'ike_crypto_profile', 'ipsec_crypto_profile'}]
    assert len(profiles) == 2 and all(row['status'] == 'READY' for row in profiles), profiles
    assert client.post('/api/migrate', json=payload).status_code == 400
    approved = approve(client, payload, data)
    assert approved.status_code == 200, approved.get_json()
    payload['decision_document'] = approved.get_json()['decision_document']
    response = client.post('/api/migrate', json=payload)
    assert response.status_code == 200, response.get_json()
    plan = response.get_json()
    assert len([command for command in plan['commands'] if 'crypto-profiles' in command]) == 8
    assert not any(' gateway ' in command or 'tunnel ipsec' in command for command in plan['commands'])
    assert 'test-secret-must-not-export' not in response.get_data(as_text=True)
    assert not plan['report']['readiness']['migration']['complete']
    assert not plan['report']['deployment_eligibility']['eligible']
    download = client.post('/api/migration/download', json={'source': payload['source'], 'artifact': plan['artifact']})
    assert download.status_code == 200
    assert download.data == '\n'.join(plan['commands']).encode()
    import hashlib
    import zipfile
    import fwmigrate.web as web
    from tests.test_web_candidate_sessions import CREDS
    request = {'source': payload['source'], 'artifact': plan['artifact']}
    assert hashlib.sha256(download.data).hexdigest() == plan['artifact']['command_sha256']
    assert client.post('/api/migration/command-preview', json=request).get_json()['commands'] == plan['commands']
    bundle = client.post('/api/migration/bundle', json=request)
    assert bundle.status_code == 200
    with zipfile.ZipFile(io.BytesIO(bundle.data)) as archive:
        assert archive.read(next(name for name in archive.namelist() if name.endswith('.set'))) == download.data
    monkeypatch.setattr(web, 'PANSSHDeployer', lambda *_: pytest.fail('Offline VPN profiles must not connect'))
    for endpoint in ('deploy', 'validate-candidate', 'commit'):
        assert client.post('/api/' + endpoint, json={**CREDS, 'artifact': plan['artifact']}).status_code == 400


def test_existing_destination_crypto_profile_is_not_overwritten_or_assumed_reusable():
    source = '''config vpn ipsec phase1-interface
edit peer
set proposal aes256-sha256
set dhgrp 14
set keylife 28800
next
end
'''
    target = TARGET.replace('<network>', '<network><ike><crypto-profiles><ike-crypto-profiles>'
        '<entry name="root-peer-ike"/></ike-crypto-profiles></crypto-profiles></ike>')
    client, payload = setup(target, source=source)
    data, payload = prepare(client, payload)
    profile = next(row for row in data['draft']['configuration'] if row['family'] == 'ike_crypto_profile')
    assert profile['status'] != 'READY'
    assert profile['target_comparison']['status'] == 'AMBIGUOUS'
    assert approve(client, payload, data, groups=[profile['group_key']]).status_code == 409


def approve(client, payload, data, groups=None):
    draft = data['draft']
    keys = groups if groups is not None else [row['decision_key'] for row in draft['decisions'] if row['status'] == 'READY'] + [
        row['group_key'] for row in draft['configuration'] if row['status'] == 'READY']
    return client.post('/api/migration/design/approve', json={**payload, 'draft': draft,
        'draft_digest': draft['digest'], 'selected_groups': keys})


def test_prepare_repeatable_no_authoritative_confirmation():
    client, payload = setup()
    data, payload = prepare(client, payload)
    again, _ = prepare(client, payload)
    assert again['draft'] == data['draft']
    assert all(row['review_state'] == 'PENDING' for row in data['decisions']['decisions'])
    assert 'commands' not in data['draft'] and 'artifact' not in data
    assert any(row['family'] == 'address' and row['status'] == 'READY' for row in data['draft']['configuration'])
    assert any(row['source_name'] == 'port1' and row['status'] == 'NEEDS_INPUT' for row in data['draft']['decisions'])
    port = next(row['decision_key'] for row in data['draft']['decisions']
                if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')
    route = next(row for row in data['draft']['configuration'] if row['family'] == 'static_route')
    assert port in route['dependencies']


def test_parent_allocation_unlocks_vlan_and_approved_additive_commands():
    client, payload = setup()
    data, payload = allocate(client, payload)
    rows = data['draft']['decisions']
    assert next(row for row in rows if row['source_name'] == 'vlan10' and row['target_field'] == 'target_interface')['proposed_value'] == 'ethernet1/1.10'
    assert next(row for row in rows if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')['operation'] == 'CONFIGURE'
    response = approve(client, payload, data)
    assert response.status_code == 200, response.get_json()
    document = response.get_json()['decision_document']
    result = client.post('/api/migrate', json={**payload, 'decision_document': document})
    assert result.status_code == 200, result.get_json()
    plan = result.get_json()
    commands = plan['commands']
    assert 'set network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24' in commands
    assert 'set network interface ethernet ethernet1/1 layer3' not in commands
    assert any('units ethernet1/1.10 tag 10' in command for command in commands)
    assert 'set network virtual-router vr-root' in commands
    assert plan['render_dispositions']['CONFIGURE'] >= 1
    assert plan['report']['approved_design_digest'] == data['draft']['digest']
    assert plan['report']['destination_verified']
    for path in ['/api/migration/command-preview', '/api/migration/download', '/api/migration/bundle']:
        response = client.post(path, json={'source': payload['source'], 'artifact': plan['artifact']})
        assert response.status_code == 200, response.get_json()


@pytest.mark.parametrize('change', ['signature', 'role', 'override', 'selection', 'parent'])
def test_approval_rejects_forged_stale_and_incomplete_selection_atomically(change):
    client, payload = setup()
    data, payload = allocate(client, payload)
    if change == 'signature':
        data['draft']['decisions'][0]['operation'] = 'REUSE'
    elif change == 'role':
        payload['reference_role'] = 'TEMPLATE'
    elif change == 'override':
        payload['draft_overrides'] = {key: 'ethernet1/2' for key in payload['draft_overrides']}
    elif change == 'parent':
        payload['decision_document']['decisions'][0]['value'] = 'changed'
        payload['decision_document']['decisions'][0]['review_state'] = 'CONFIRMED'
    groups = None
    if change == 'selection':
        groups = [next(row['decision_key'] for row in data['draft']['decisions'] if row['source_name'] == 'vlan10')]
    response = approve(client, payload, data, groups)
    assert response.status_code == 409, response.get_json()


def test_signed_draft_cannot_be_deployed_and_unsigned_operations_cannot_render():
    client, payload = setup()
    data, payload = allocate(client, payload)
    response = client.post('/api/migration/command-preview', json={'artifact': data['draft']})
    assert response.status_code == 400
    row = payload['decision_document']['decisions'][0]
    row.update(value='vsys1', review_state='CONFIRMED', approved_operation='CREATE')
    assert client.post('/api/migrate', json=payload).status_code == 400


def test_template_and_source_only_cannot_establish_destination_reuse():
    for target, role in [(TARGET, 'TEMPLATE'), (None, None)]:
        client, payload = setup(target, role)
        data, payload = allocate(client, payload)
        assert not data['draft']['destination_verified']
        assert all(row['operation'] != 'REUSE' for row in data['draft']['decisions'])
        assert any(row['code'] == 'DESTINATION_UNVERIFIED' for row in data['draft']['findings'])


def test_changed_approved_parent_and_reference_invalidate_approval():
    client, payload = setup()
    data, payload = allocate(client, payload)
    response = approve(client, payload, data)
    assert response.status_code == 200, response.get_json()
    payload['decision_document'] = response.get_json()['decision_document']
    changed = deepcopy(payload)
    changed['reference_role'] = 'TEMPLATE'
    assert client.post('/api/migrate', json=changed).status_code == 400
    data, _ = prepare(client, changed)
    assert 'design_approval' not in data['decision_document']
    assert not any(row['approved_operation'] for row in data['decisions']['decisions'])
    row = next(row for row in payload['decision_document']['decisions'] if row['source_name'] == 'port1')
    row['value'] = 'ethernet1/2'
    assert client.post('/api/migrate', json=payload).status_code == 400


def test_partial_group_approval_and_decision_export_import_keep_the_boundary():
    client, payload = setup()
    data, payload = allocate(client, payload)
    scope = next(row['decision_key'] for row in data['draft']['decisions'] if row['target_field'] == 'vsys')
    address = next(row['group_key'] for row in data['draft']['configuration'] if row['family'] == 'address')
    response = approve(client, payload, data, [scope, address])
    assert response.status_code == 200, response.get_json()
    document = response.get_json()['decision_document']
    partial = client.post('/api/migrate', json={**payload, 'decision_document': document}).get_json()
    assert partial['plan_status'] != 'READY'
    assert partial['commands'] == ['set vsys vsys1 address net ip-netmask 192.0.2.0/24']
    exported = client.post('/api/migration/decisions/export', json={**payload, 'decision_document': document}).get_json()['document']
    assert exported['design_approval'] == document['design_approval']
    imported = client.post('/api/migration/decisions/import', json={**payload, 'document': exported}).get_json()['decision_document']
    assert imported['design_approval'] == document['design_approval']
    data, payload = prepare(client, {**payload, 'decision_document': imported})
    remaining = [row['decision_key'] for row in data['draft']['decisions'] if row['status'] == 'READY' and not row['approved']]
    remaining += [row['group_key'] for row in data['draft']['configuration'] if row['status'] == 'READY' and row['group_key'] != address]
    response = approve(client, payload, data, remaining)
    assert response.status_code == 200, response.get_json()
    final = client.post('/api/migrate', json={**payload, 'decision_document': response.get_json()['decision_document']})
    assert final.get_json()['plan_status'] == 'READY', final.get_json()


@pytest.mark.parametrize('settings', ['<ip><entry name="203.0.113.1/24"/></ip>', '<future-setting>unknown</future-setting>'])
def test_conflicting_or_unknown_target_settings_block_additive_configuration(settings):
    client, payload = setup(TARGET.replace('<layer3/>', f'<layer3>{settings}</layer3>'))
    data, payload = allocate(client, payload)
    row = next(row for row in data['draft']['decisions'] if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')
    assert row['status'] == 'CONFLICT'
    response = approve(client, payload, data, [row['decision_key']])
    assert response.status_code == 409


def test_template_address_match_does_not_allocate_a_physical_port():
    client, payload = setup(TARGET.replace('<layer3/>', '<layer3><ip><entry name="192.0.2.1/24"/></ip></layer3>'), 'TEMPLATE')
    data, _ = prepare(client, payload)
    physical = next(row for row in data['draft']['decisions'] if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')
    assert physical['proposed_value'] is None


def test_manual_interface_edit_revokes_operations_without_losing_allocations():
    client, payload = setup()
    data, payload = allocate(client, payload)
    response = approve(client, payload, data)
    payload['decision_document'] = response.get_json()['decision_document']
    data, payload = prepare(client, payload)
    interface = next(row for row in data['decisions']['decisions']
                     if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')
    response = client.post('/api/migration/interfaces/confirm', json={**payload,
        'selections': [{'decision_key': interface['key'], 'value': interface['value']}],
        'reviewed_target_evidence': data['target_evidence']})
    assert response.status_code == 200, response.get_json()
    document = response.get_json()['decision_document']
    assert document['draft_required']
    assert 'design_approval' not in document
    assert not any(row['approved_operation'] or row['approval_context'] for row in document['decisions'])
    assert client.post('/api/migrate', json={**payload, 'decision_document': document}).status_code == 400
    refreshed, payload = prepare(client, {**payload, 'decision_document': document})
    assert next(row['value'] for row in refreshed['decisions']['decisions'] if row['key'] == interface['key']) == interface['value']
    approved = approve(client, payload, refreshed)
    assert approved.status_code == 200, approved.get_json()
    assert client.post('/api/migrate', json={**payload,
        'decision_document': approved.get_json()['decision_document']}).get_json()['plan_status'] == 'READY'


def test_template_manual_allocation_survives_refresh_without_destination_provenance():
    client, payload = setup(role='TEMPLATE')
    data, payload = allocate(client, payload)
    interface = next(row for row in data['decisions']['decisions']
                     if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')
    selection = {'decision_key': interface['key'], 'value': 'ethernet1/1'}
    response = client.post('/api/migration/interfaces/confirm', json={**payload,
        'selections': [selection], 'reviewed_target_evidence': data['target_evidence']})
    assert response.status_code == 200, response.get_json()
    document = response.get_json()['decision_document']
    row = next(row for row in document['decisions'] if row['key'] == interface['key'])
    assert row['evidence_type'] == 'MANUAL'
    assert row['evidence_target_digest'] is None and row['evidence_target_device'] is None
    refreshed, _ = prepare(client, {**payload, 'decision_document': document})
    assert next(row['value'] for row in refreshed['decisions']['decisions'] if row['key'] == interface['key']) == 'ethernet1/1'
    assert not refreshed['draft']['destination_verified']
    stale = {**data['target_evidence'], 'config_digest': 'changed'}
    assert client.post('/api/migration/interfaces/confirm', json={**payload,
        'selections': [selection], 'reviewed_target_evidence': stale}).status_code == 400


def test_proposal_edit_after_approval_requires_reapproval_and_keeps_new_value():
    client, payload = setup()
    data, payload = allocate(client, payload)
    payload['decision_document'] = approve(client, payload, data).get_json()['decision_document']
    zone = next(row['decision_key'] for row in data['draft']['decisions'] if row['target_field'] == 'target_zone')
    data, payload = prepare(client, {**payload, 'draft_overrides': {**payload['draft_overrides'], zone: 'new-zone'}})
    assert 'design_approval' not in data['decision_document']
    assert next(row['proposed_value'] for row in data['draft']['decisions'] if row['decision_key'] == zone) == 'new-zone'
    assert client.post('/api/migrate', json=payload).status_code == 400
    response = approve(client, payload, data)
    assert response.status_code == 200, response.get_json()
    plan = client.post('/api/migrate', json={**payload, 'decision_document': response.get_json()['decision_document']})
    assert plan.status_code == 200, plan.get_json()
    assert any('zone new-zone' in command for command in plan.get_json()['commands'])


@pytest.mark.parametrize('change', ['signature', 'unsigned', 'role'])
def test_manual_confirmation_cannot_launder_invalid_design_approval(change):
    client, payload = setup()
    data, payload = allocate(client, payload)
    payload['decision_document'] = approve(client, payload, data).get_json()['decision_document']
    interface = next(row for row in payload['decision_document']['decisions']
                     if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')
    if change == 'signature':
        payload['decision_document']['design_approval']['signature'] = 'invalid'
    elif change == 'unsigned':
        payload['decision_document'].pop('design_approval')
    else:
        payload['reference_role'] = 'UNKNOWN'
    response = client.post('/api/migration/interfaces/confirm', json={**payload,
        'selections': [{'decision_key': interface['key'], 'value': interface['value']}],
        'reviewed_target_evidence': data['target_evidence']})
    assert response.status_code == 400, response.get_json()


def test_inspection_remains_manual_with_complete_placement_and_mixed_causes():
    client, payload = setup()
    policy = '''config firewall policy
 edit 1
 set name inspect
 set srcintf port1
 set dstintf vlan10
 set srcaddr all
 set dstaddr all
 set service ALL
 set action accept
 set inspection-mode flow
 next
end
'''
    source = SOURCE + policy
    payload['source'] = client.post('/api/preview', data={'source_vendor': 'fortigate',
        'file': (io.BytesIO(source.encode()), 'inspection.conf')}).get_json()['source_evidence']
    data, payload = allocate(client, payload)
    row = next(row for row in data['draft']['configuration'] if row['family'] == 'security_rule')
    assert row['status'] == 'UNSUPPORTED'
    issue = next(issue for issue in data['draft']['issues'] if issue['code'] == 'INSPECTION_UNSUPPORTED')
    assert issue['category'] == 'MANUAL' and issue['action'] is None
    response = approve(client, payload, data)
    assert response.status_code == 200
    artifact = client.post('/api/migrate', json={**payload, 'decision_document': response.get_json()['decision_document']}).get_json()['artifact']
    assert not any('rulebase security' in command for command in artifact['commands'])
    assert artifact['report']['deployment_eligibility']['eligible'] is False
    data, _ = prepare(client, {**payload, 'draft_overrides': {}})
    assert any(issue['code'] == 'INSPECTION_UNSUPPORTED' for issue in data['draft']['issues'])
    assert any(issue['action'] for issue in data['draft']['issues'])


def test_pre_artifact_readiness_never_authorizes_a_template():
    client, payload = setup(role='TEMPLATE')
    data, _ = prepare(client, payload)
    readiness = data['draft']['readiness']['deployment']
    assert readiness['assessment'] == 'PRE_ARTIFACT'
    assert readiness['eligible'] is False
    assert 'destination_evidence' in readiness['missing_prerequisites']


def test_missing_parent_is_one_task_with_deduplicated_dependent_scope():
    client, payload = setup()
    data, _ = prepare(client, payload)
    port_key = next(row['decision_key'] for row in data['draft']['decisions']
        if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')
    tasks = [
        issue for issue in data['draft']['issues'] if issue['action'] and issue['action']['decision_key'] == port_key]
    assert len(tasks) == 1
    assert len(tasks[0]['affected_keys']) == len(set(tasks[0]['affected_keys']))
    assert any(row['source_name'] == 'vlan10' for row in tasks[0]['affected_sources'])
    assert any(row['source_name'] == '1' for row in tasks[0]['affected_sources'])
    assert tasks[0]['explanation'] == 'Assign a target interface for port1.'
    assert any('Unresolved prerequisite:' in reason for reason in tasks[0]['explanations'])


def test_many_dependent_vlans_keep_one_short_instruction_and_all_evidence():
    source = 'config system interface\nedit port1\nset type physical\nnext\n' + ''.join(
        f'edit vlan{number}\nset interface port1\nset vlanid {number}\nnext\n'
        for number in range(10, 110)) + 'end\n'
    client, payload = setup(None, source=source)
    data, payload = prepare(client, {**payload, 'workflow_mode': 'DESTINATION_AWARE'})
    payload['draft_overrides'] = {row['decision_key']: 'vsys1' for row in data['draft']['decisions'] if row['target_field'] == 'vsys'}
    data, _ = prepare(client, payload)
    tasks = data['draft']['issues']
    assert len(tasks) == 1
    task = tasks[0]
    assert task['explanation'] == 'Assign a target interface for port1.'
    assert len(task['explanations']) > 100
    assert len(task['affected_sources']) == 101
    assert len(task['affected_keys']) == len(set(task['affected_keys']))
    assert data['draft'] == prepare(client, payload)[0]['draft']


def test_offline_supported_objects_export_without_destination_eligibility():
    client, payload = setup(target=None, role='TEMPLATE')
    data, payload = prepare(client, {**payload, 'reference_role': 'TEMPLATE'})
    vsys = next(row['decision_key'] for row in data['draft']['decisions'] if row['target_field'] == 'vsys')
    data, payload = prepare(client, {**payload, 'draft_overrides': {vsys: 'vsys1'}})
    response = approve(client, payload, data)
    assert response.status_code == 200
    result = client.post('/api/migrate', json={**payload,
        'decision_document': response.get_json()['decision_document']})
    assert result.status_code == 200, result.get_json()
    artifact = result.get_json()['artifact']
    assert any('address net' in command for command in artifact['commands'])
    assert artifact['report']['deployment_eligibility']['eligible'] is False
    assert artifact['report']['readiness']['export']['status'] == 'PARTIAL'
