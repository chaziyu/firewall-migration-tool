"""Build API fixtures through the same signed review flow as the frontend."""
import io


TARGET = b'''<config><devices><entry name="fw" serial="012345678901">
<network><interface><ethernet><entry name="ethernet1/1"><layer3/></entry>
<entry name="ethernet1/2"><layer3/></entry></ethernet></interface></network>
<vsys><entry name="vsys1"/></vsys></entry></devices></config>'''


def approved_payload(client, payload, *, configuration=True):
    payload = dict(payload)
    mapping = payload.pop("mapping", {})
    if "target_source" not in payload:
        target = client.post('/api/preview', data={'source_vendor': 'palo_alto',
            'file': (io.BytesIO(TARGET), 'destination.xml')})
        assert target.status_code == 200, target.get_json()
        payload['target_source'] = target.get_json()['source_evidence']
    prepared = client.post('/api/migration/design/prepare', json=payload)
    assert prepared.status_code == 200, prepared.get_json()
    data = prepared.get_json()
    overrides = {}
    for row in data['draft']['decisions']:
        vdom, kind, name, field = (row[key] for key in ('source_vdom', 'source_kind', 'source_name', 'target_field'))
        values = (mapping.get('vdoms', {}).get(vdom, {}) if kind == 'vdom' else
                  mapping.get('zones' if kind == 'zone' and 'zones' in mapping else 'interfaces', {}).get(vdom, {}).get(name, {}))
        if values.get(field):
            overrides[row['decision_key']] = values[field]
    payload['decision_document'] = data['decision_document']
    if overrides:
        payload['draft_overrides'] = overrides
        prepared = client.post('/api/migration/design/prepare', json=payload)
        assert prepared.status_code == 200, prepared.get_json()
        data = prepared.get_json()
        payload['decision_document'] = data['decision_document']
    draft = data['draft']
    rows = {row['decision_key']: row for row in draft['decisions']}
    if configuration:
        rows.update({row['group_key']: row for row in draft['configuration']})
    selected = {key for key, row in rows.items() if row['status'] == 'READY'
                and (configuration or row.get('target_field') == 'vsys')}
    while True:
        eligible = {key for key in selected if all(parent in selected or rows.get(parent, {}).get('approved')
                    for parent in rows[key]['dependencies'])}
        if eligible == selected:
            break
        selected = eligible
    assert selected, draft
    response = client.post('/api/migration/design/approve', json={**payload,
        'draft': draft, 'draft_digest': draft['digest'], 'selected_groups': sorted(selected)})
    assert response.status_code == 200, response.get_json()
    return {**payload, 'decision_document': response.get_json()['decision_document']}


def approved_migrate(client, *, json):
    return client.post('/api/migrate', json=approved_payload(client, json))
