import io

from fwmigrate.conversion.fortigate_to_palo_alto.coverage import build_migration_coverage
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


SOURCE = '''config system session-helper
edit 1
set name sip
set port 5060
set protocol 17
next
edit 2
set name sip
set port 5061
set protocol 6
next
end
config firewall region
edit 12
set name repeated
next
edit 13
set name repeated
next
end
config firewall vendor-mac
edit 21
set name repeated
next
end
config vpn ssl web realm
edit staff
set virtual-host vpn.example.test
next
end
config vpn ssl web user-bookmark
edit staff-owner
set custom-lang en
next
end
config vpn ssl web user-group-bookmark
edit group-owner
set custom-lang en
next
end
'''


def identities(text):
    config = FortiGateSourceReporter().analyze_source(text).extracted.config
    rows = build_migration_coverage(config)['unplanned']
    return {(row['source_vdom'], row['source_kind'], row['source_name']) for row in rows}, rows


def test_coverage_uses_native_edit_keys_instead_of_labels_or_list_offsets():
    found, rows = identities(SOURCE)
    assert found == {('root', 'session_helper', '1'), ('root', 'session_helper', '2'),
                     (None, 'firewall_region', '12'), (None, 'firewall_region', '13'),
                     (None, 'vendor_mac', '21'), ('root', 'ssl_vpn_realm', 'staff'),
                     ('root', 'ssl_vpn_user_bookmark', 'staff-owner'),
                     ('root', 'ssl_vpn_user_group_bookmark', 'group-owner')}
    assert len(found) == len(rows)


def test_native_identities_keep_global_and_vdom_scopes_distinct():
    helpers = SOURCE.partition('config firewall region')[0]
    text = ('config global\nconfig system session-helper\nedit 1\nset name sip\nnext\nend\nend\n'
            + 'config vdom\nedit root\n' + helpers + 'next\nedit blue\n' + helpers + 'next\nend\n')
    found, rows = identities(text)
    assert (None, 'session_helper', '1') in found
    assert ('root', 'session_helper', '1') in found
    assert ('blue', 'session_helper', '1') in found
    assert len(found) == len(rows)


def test_unparsed_native_ids_and_singleton_paths_are_not_replaced_by_offsets():
    found, _ = identities('''config system session-helper
edit not-a-number
set name sip
next
end
config ips settings
set ips-packet-quota 10
end
config router setting
set hostname lab
end
''')
    assert ('root', 'session_helper', 'not-a-number') in found
    assert ('root', 'ips_settings', 'ips_settings') in found
    assert ('root', 'router_settings', 'router_settings') in found


def test_web_manual_tasks_preserve_each_native_helper_id():
    from fwmigrate.web import create_app

    client = create_app({'TESTING': True}).test_client()
    preview = client.post('/api/preview', data={'file': (io.BytesIO(SOURCE.encode()), 'source.conf')})
    assert preview.status_code == 200
    prepared = client.post('/api/migration/design/prepare', json={
        'source': preview.get_json()['source_evidence'], 'workflow_mode': 'OFFLINE_EXPORT'})
    assert prepared.status_code == 200
    body = prepared.get_json()['draft']
    rows = [row for row in body['configuration'] if row['source_kind'] == 'session_helper']
    assert {row['source_name'] for row in rows} == {'1', '2'}
    assert all(row['status'] == 'UNSUPPORTED' and row['operation'] is None for row in rows)
    tasks = [row for row in body['issues'] if row['source_kind'] == 'session_helper']
    assert {row['source_name'] for row in tasks} == {'1', '2'}
