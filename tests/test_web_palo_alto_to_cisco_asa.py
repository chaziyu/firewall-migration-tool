from io import BytesIO
from pathlib import Path
import zipfile

from fwmigrate.web import create_app
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity


def payload():
    text = (Path(__file__).parent / 'fixtures/palo_alto/asa_policy_explicit.xml').read_text(encoding='utf-8')
    scope = next(row for row in build_panos_config(text).scopes if row.kind == 'vsys')
    return {'source': {'vendor':'palo_alto','source_text':text}, 'options': {
        'source_scope':pan_scope_identity(scope), 'new_target_confirmed':True, 'routing_complete':True,
        'interfaces': {'ethernet1/1': {'target_interface':'GigabitEthernet0/0','nameif':'inside','security_level':100},
                       'ethernet1/2': {'target_interface':'GigabitEthernet0/1','nameif':'outside','security_level':0}}}}


def test_native_policy_signed_approval_preview_download_bundle_and_tampering():
    client = create_app({'TESTING':True,'WEB_MODE':'local'}).test_client()
    base = '/api/migration/palo_alto_to_cisco_asa'
    data = payload()
    prepared = client.post(base+'/design/prepare',json=data)
    assert prepared.status_code == 200, prepared.get_json()
    draft = prepared.get_json()['draft']
    selected = [row['key'] for row in draft['items'] if not row['blockers']]
    policy = next(row['key'] for row in draft['items'] if row['family']=='policy')
    rejected = client.post(base+'/design/approve',json={**data,'draft':draft,'selected_items':[policy]})
    assert rejected.status_code == 400
    response = client.post(base+'/design/approve',json={**data,'draft':draft,'selected_items':selected})
    assert response.status_code == 200, response.get_json()
    approval = response.get_json()['approval']
    built = client.post(base+'/build',json={**data,'approval':approval})
    assert built.status_code == 200, built.get_json()
    artifact = built.get_json()['artifact']
    preview = client.post(base+'/command-preview',json={'artifact':artifact})
    downloaded = client.post(base+'/commands',json={'artifact':artifact})
    bundle = client.post(base+'/bundle',json={**data,'artifact':artifact})
    assert preview.status_code == downloaded.status_code == bundle.status_code == 200
    assert preview.get_json()['text'].encode() == downloaded.data
    assert b'access-group PAN_inside in interface inside' in downloaded.data
    with zipfile.ZipFile(BytesIO(bundle.data)) as archive:
        assert archive.read('asa_config.cfg') == downloaded.data
    assert client.post(base+'/commands',json={'artifact':{**artifact,'command_text':'hostname tampered\n'}}).status_code == 400
    changed = {**data,'options':{**data['options'],'routing_complete':False}}
    assert client.post(base+'/build',json={**changed,'approval':approval}).status_code == 400
    assert client.post(base+'/deploy',json={}).status_code == 404


def test_optional_target_exact_object_reuse_and_stale_evidence_are_bound():
    client = create_app({'TESTING':True,'WEB_MODE':'local'}).test_client()
    base = '/api/migration/palo_alto_to_cisco_asa'
    data = {**payload(), 'target_source': {'vendor':'cisco_asa','source_text':'object network inside-net\n subnet 10.10.0.0 255.255.255.0\nexit\n'},
            'target_metadata':{'context':'single','version':'9.20','mode':'routed','complete_families':['addresses']}}
    prepared = client.post(base+'/design/prepare',json=data)
    assert prepared.status_code == 200, prepared.get_json()
    body = prepared.get_json()
    row = next(row for row in body['draft']['items'] if row['family']=='address' and row['source_name']=='inside-net')
    assert row['target_disposition']=='REUSE'
    assert all(row['blockers'] for row in body['draft']['items'] if row['family'] in {'interface','policy','acl_binding'})
    approved = client.post(base+'/design/approve',json={**data,'draft':body['draft'],'selected_items':[row['key']]})
    assert approved.status_code == 200
    approval = approved.get_json()['approval']
    built = client.post(base+'/build',json={**data,'approval':approval})
    assert built.status_code == 200
    assert built.get_json()['artifact']['command_text']==''
    changed = {**data,'target_source':{**data['target_source'],'source_text':data['target_source']['source_text']+'hostname changed\n'}}
    assert client.post(base+'/build',json={**changed,'approval':approval}).status_code==400
    missing = {**data,'target_metadata':{**data['target_metadata'],'complete_families':[]}}
    response = client.post(base+'/design/prepare',json=missing)
    assert all(row['blockers'] for row in response.get_json()['draft']['items'] if row['family']=='address')
