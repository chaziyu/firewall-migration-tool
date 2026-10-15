"""Synthetic browser smoke for staged conversion settings and unresolved source data."""
import argparse
import json
from playwright.sync_api import sync_playwright, expect


def run(url, chromium):
    source = 'config system interface\n' + ''.join(
        f'edit port{number}\nset type physical\nset snmp-index {number}\n'
        + ('set allowaccess ping ssh\n' if number == 2 else '')
        + ('set ip malformed-primary\n' if number == 1 else '') + 'next\n' for number in range(1, 14))
    source += '''edit site
set type tunnel
set interface port1
next
end
config vpn ipsec phase1-interface
edit site
set interface port1
set remote-gw 192.0.2.2
set proposal aes256-sha512
set dhgrp 14
next
end
config vpn ipsec phase2-interface
edit selectors
set phase1name site
set proposal aes256-sha512
set dhgrp 14
next
end
config firewall address
edit bad/name
set subnet 198.51.100.1 255.255.255.255
next
end
'''
    source += '''config system interface
edit remote
set type tunnel
set interface port2
next
edit ssl.root
set type tunnel
next
end
config system zone
edit shared
set interface port2 port3
next
end
config vpn ipsec phase1-interface
edit remote
set type dynamic
set interface port2
set mode-cfg enable
set xauthtype auto
next
edit orphan
set interface port2
set remote-gw 192.0.2.3
next
end
config router static
edit 1
set dst 203.0.113.0 255.255.255.0
set device orphan
next
end
'''
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=chromium, headless=True)
        page = browser.new_page(viewport={'width': 1280, 'height': 900})
        errors, approvals = [], []
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.on('request', lambda request: approvals.append(request.url) if request.url.endswith('/api/migration/design/approve') else None)
        page.goto(url)
        page.get_by_role('button', name='Plan migration', exact=True).click()
        page.get_by_label('Drop your configuration here').set_input_files({'name': 'automation.conf', 'mimeType': 'text/plain', 'buffer': source.encode()})
        setup = page.locator('.target-setup')
        expect(setup.get_by_label('Target interface for root / site', exact=True)).to_have_value('tunnel.1')
        expect(setup.get_by_label('Target interface for root / port13', exact=True)).to_have_value('ethernet1/13')
        expect(page.get_by_label('Needs attention', exact=True)).to_contain_text('Correct the malformed primary IPv4 address')
        for name in ('remote', 'ssl.root', 'orphan'):
            row = setup.get_by_role('row').filter(has=page.get_by_text(f'root / {name}', exact=True))
            expect(row.locator('input')).to_have_count(0)
            expect(row).to_contain_text('Source interface missing' if name == 'orphan' else 'separate target VPN design')
        expect(page.get_by_text('Advanced mapping editors', exact=True)).to_have_count(0)
        expect(page.get_by_text('Advanced tools and mapping files', exact=True)).to_have_count(0)
        shared = setup.get_by_label('Source zone for root / shared', exact=True)
        expect(shared).to_have_value('shared')
        shared.fill('inside-net')
        with page.expect_response(lambda response: response.url.endswith('/api/migration/design/prepare')) as response:
            page.get_by_role('button', name='Apply mappings', exact=True).click()
        assert response.value.ok
        zones = [row for row in response.value.json()['draft']['decisions'] if row['source_name'] in {'port2', 'port3'} and row['target_field'] == 'target_zone']
        assert len(zones) == 2 and all(row['proposed_value'] == 'inside-net' for row in zones)
        expect(setup.get_by_label('Zone for root / port2', exact=True)).to_have_count(0)
        settings = page.get_by_text('Target version, hardware and conversion scope', exact=True)
        settings.click()
        page.get_by_label('Target hardware', exact=True).select_option('PA-820')
        page.get_by_label('PAN-OS command version', exact=True).select_option('11.1')
        expect(page.get_by_role('button', name='Review supported changes', exact=True)).to_be_disabled()
        with page.expect_response(lambda response: response.url.endswith('/api/migration/design/prepare')) as response:
            page.get_by_role('button', name='Apply conversion settings', exact=True).click()
        assert response.value.ok
        expect(setup.get_by_label('Target interface for root / port13', exact=True)).to_have_value('')
        settings.click()
        page.get_by_text('Missing VPN parameters · grouped decisions', exact=True).click()
        phase1 = page.locator('fieldset').filter(has=page.get_by_text('root · ipsec_phase1 · 1 source objects', exact=True))
        phase2 = page.locator('fieldset').filter(has=page.get_by_text('root · ipsec_phase2 · 1 source objects', exact=True))
        phase1.get_by_label('lifetime seconds', exact=True).fill('28800')
        phase1.get_by_label('ike version', exact=True).select_option('2')
        phase2.get_by_label('lifetime seconds', exact=True).fill('86400')
        phase2.get_by_label('pfs', exact=True).select_option('disable')
        page.get_by_text('Generate management profiles', exact=True).click()
        page.get_by_label('Permitted networks for all proposed management profiles', exact=True).fill('192.0.2.0/24')
        page.get_by_role('button', name='Propose profiles for all protocol groups', exact=True).click()
        page.set_viewport_size({'width': 390, 'height': 844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Settings must fit the mobile viewport'
        page.set_viewport_size({'width': 1280, 'height': 900})
        with page.expect_response(lambda response: response.url.endswith('/api/migration/design/prepare')) as response:
            page.get_by_role('button', name='Apply conversion settings', exact=True).click()
        assert response.value.ok
        draft = response.value.json()['draft']
        crypto = [row for row in draft['configuration'] if row['family'] in {'ike_crypto_profile', 'ipsec_crypto_profile'}
                  and row['source_name'] in {'site', 'selectors'}]
        assert len(crypto) == 2 and all(row['status'] == 'READY' for row in crypto)
        management = [row for row in draft['configuration'] if row['family'] == 'management_profile']
        assert len(management) == 1 and management[0]['status'] == 'READY'
        assert management[0]['configuration']['permitted_ips'] == ['192.0.2.0/24']
        assert next(row for row in draft['configuration'] if row['family'] == 'ike_gateway')['status'] == 'UNSUPPORTED'
        assert '/' not in next(row for row in draft['configuration'] if row['source_name'] == 'bad/name')['target_name']
        page.get_by_role('button', name='3. Review conversion', exact=True).click()
        expect(page.locator('.migration-exceptions')).to_be_visible()
        page.locator('.migration-exceptions > summary').click()
        expect(page.get_by_label('Migration exceptions', exact=True)).to_be_visible()
        expect(page.get_by_label('Migration exceptions', exact=True)).to_contain_text('Excluded from generated commands')
        assert not approvals and not errors, (approvals, errors)
        print(json.dumps({'flow': 'PASS', 'bounded_physical_ports': 12, 'reviewed_crypto_profiles': 2,
                          'proposed_management_profiles': len(management),
                          'approval_requests': len(approvals), 'javascript_errors': errors}))
        browser.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--chromium', required=True)
    arguments = parser.parse_args()
    run(arguments.url, arguments.chromium)
