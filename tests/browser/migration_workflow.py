"""Optional real-browser walkthrough against built frontend + Flask (no device work).

Run: python tests/browser/migration_workflow.py --url http://127.0.0.1:5000
Requires Playwright and a Chromium binary; neither is a runtime dependency.
"""
import argparse
import hashlib
import io
import json
import re
from time import perf_counter
from pathlib import Path
import tempfile
import zipfile

from playwright.sync_api import sync_playwright, expect


def run(url, chromium, destination=False):
    fixtures = Path(__file__).parent.parent / 'fixtures' / 'migration_workflow'
    with sync_playwright() as playwright, tempfile.TemporaryDirectory() as temporary:
        browser = playwright.chromium.launch(executable_path=chromium, args=['--no-sandbox'])
        page = browser.new_page()
        errors = []
        approvals = []
        preparations = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.on('request', lambda req: approvals.append(req) if req.url.endswith('/api/migration/design/approve') else None)
        page.on('request', lambda req: preparations.append(req.post_data_json) if req.url.endswith('/api/migration/design/prepare') else None)
        page.goto(url)
        page.get_by_role('button', name='Plan migration', exact=True).click()
        page.get_by_label('Drop your configuration here').set_input_files(str(fixtures / 'migration-source.conf'))
        page.get_by_role('heading', name='Setup', exact=True).wait_for()
        expect(page.get_by_text('Optional PAN-OS reference', exact=True)).not_to_be_visible()
        expect(page.get_by_label('Reference role')).not_to_be_visible()
        expect(page.get_by_text('Advanced tools and mapping files', exact=True)).not_to_be_visible()
        if destination:
            page.get_by_label('Migration intent').select_option('destination')
            expect(page.get_by_text('Preparing and validating', exact=False)).not_to_be_visible()
            page.get_by_label('Reference role').select_option('DESTINATION')
            expect(page.get_by_text('Preparing and validating', exact=False)).not_to_be_visible()
            page.get_by_label('Drop your target XML here').set_input_files(str(fixtures / 'migration-target.xml'))
            page.get_by_text('Target evidence loaded.', exact=False).wait_for()
            expect(page.get_by_label('Reference role')).to_have_count(0)
            expect(page.get_by_text('Reference role: Destination configuration', exact=True)).to_be_visible()
        else:
            expect(page.get_by_label('Migration intent')).to_have_value('offline')
            expect(page.get_by_label('Drop your target XML here')).not_to_be_visible()
        page.get_by_role('button', name='2. Resolve mappings', exact=True).click()
        expect(page.get_by_text('Advanced tools and mapping files', exact=True)).to_be_visible()
        expect(page.get_by_role('navigation', name='Migration workspace').get_by_role('button')).to_have_count(4)
        resolve = page.get_by_role('button', name='Resolve placement', exact=True).first
        resolve.focus()
        resolve.press('Enter')
        expect(page.get_by_label('target_interface for root / port1', exact=True)).to_be_focused()
        page.get_by_role('button', name='2. Resolve mappings', exact=True).click()
        if destination:
            page.get_by_role('button', name='Recommended next mapping: root · root', exact=True).click()
            page.get_by_role('button', name='Review staged changes', exact=True).click()
            page.get_by_role('button', name='Validate staged changes', exact=True).click()
        page.get_by_role('button', name='Recommended next mapping: root · port1', exact=True).click()
        batch_override_count = len(preparations[-1].get('draft_overrides') or {})
        if destination:
            assert batch_override_count >= 2
        page.get_by_label('target_interface for root / port1', exact=True).wait_for()
        # Force a failed draft request after staging a real port edit.
        port = page.get_by_label('target_interface for root / port1', exact=True)
        if destination:
            port.select_option('ethernet1/1')
        else:
            page.get_by_label('Custom target_interface for root / port1', exact=True).fill('ethernet1/1')
        requests_before_save = len(preparations)
        page.get_by_role('button', name='Save draft', exact=True).click()
        expect(page.get_by_text('Draft saved locally.', exact=False)).to_be_visible()
        assert len(preparations) == requests_before_save
        page.route('**/api/migration/design/prepare', lambda route: route.fulfill(status=502,
            content_type='application/json', body=json.dumps({'success': False, 'error': 'Synthetic draft failure'})), times=1)
        page.get_by_role('button', name='Review staged changes', exact=True).click()
        page.get_by_role('button', name='Validate staged changes', exact=True).click()
        page.get_by_text('Synthetic draft failure', exact=False).wait_for()
        expect(page.get_by_text('Previous successful review', exact=False)).to_be_visible()
        expect(page.get_by_label(('target_interface' if destination else 'Custom target_interface') + ' for root / port1', exact=True)).to_have_value('ethernet1/1')
        page.get_by_role('button', name='Retry intended draft update', exact=True).click()
        expect(page.get_by_text('Previous successful review', exact=False)).not_to_be_visible()
        page.get_by_role('button', name='2. Resolve mappings', exact=True).click()
        page.get_by_role('button', name='Review supported changes', exact=True).click()
        page.get_by_role('button', name='Review ready items', exact=False).click()
        preview = page.get_by_role('region', name='Approval preview')
        expect(preview).to_contain_text('ethernet1/1.10')
        # Approval succeeds; first generation fails. Retry must not submit another approval.
        page.route('**/api/migrate', lambda route: route.fulfill(status=502,
            content_type='application/json', body=json.dumps({'success': False, 'error': 'Synthetic build failure'})), times=1)
        page.get_by_role('button', name='Approve selected changes', exact=True).click()
        page.get_by_text('Synthetic build failure', exact=False).wait_for()
        assert len(approvals) == 1
        page.get_by_role('button', name='Retry generation with current approval', exact=True).click()
        expect(page.get_by_text('Ready for export', exact=True)).to_be_visible()
        if not destination:
            expect(page.get_by_text('Destination unverified. Check', exact=False)).to_be_visible()
            expect(page.get_by_role('button', name='Open live migration', exact=True)).to_have_count(0)
            assert all(payload['workflow_mode'] == 'OFFLINE_EXPORT' for payload in preparations)
            assert all(not payload.get('target_source') for payload in preparations)
        assert len(approvals) == 1
        page.get_by_text('Command preview (', exact=False).click()
        commands = page.get_by_label('Command preview', exact=True).input_value()
        digest = hashlib.sha256(commands.encode()).hexdigest()
        with page.expect_download() as downloaded:
            page.get_by_role('button', name='Download .set', exact=True).click()
        set_path = Path(temporary) / 'commands.set'
        downloaded.value.save_as(set_path)
        assert set_path.read_text() == commands
        with page.expect_download() as downloaded:
            page.get_by_role('button', name='Download migration bundle', exact=True).click()
        bundle_path = Path(temporary) / 'bundle.zip'
        downloaded.value.save_as(bundle_path)
        with zipfile.ZipFile(io.BytesIO(bundle_path.read_bytes())) as bundle:
            assert any(hashlib.sha256(bundle.read(name)).hexdigest() == digest for name in bundle.namelist() if name.endswith('.set'))
        with page.expect_download() as downloaded:
            page.get_by_role('button', name='Download project', exact=True).click()
        project_path = Path(temporary) / 'project.json'
        downloaded.value.save_as(project_path)
        project = json.loads(project_path.read_text())
        assert project['proposals'] and 'design_approval' not in project and 'artifact' not in project
        page.reload()
        page.get_by_role('button', name='Plan migration', exact=True).click()
        page.get_by_label('Resume project').set_input_files(str(project_path))
        page.get_by_text('Proposals restored.', exact=False).wait_for()
        page.get_by_role('button', name='3. Review & approve', exact=True).click()
        expect(page.get_by_role('button', name='Review ready items', exact=False)).to_be_enabled()
        page.get_by_role('button', name='4. Export', exact=True).click()
        expect(page.get_by_role('button', name=re.compile(r'^Build approved'))).to_be_disabled()
        # A rejected import leaves the current evidence and proposals intact.
        bad = Path(temporary) / 'bad.json'
        bad.write_text(json.dumps({**project, 'design_approval': {'signature': 'forged'}}))
        page.get_by_label('Resume project').set_input_files(str(bad))
        page.get_by_text('current workspace is unchanged.', exact=False).wait_for()
        expect(page.get_by_text('Destination: 012345678901' if destination else 'Destination: Not selected', exact=True)).to_be_visible()
        page.get_by_role('button', name='New workspace', exact=True).click()
        page.get_by_role('button', name='Plan migration', exact=True).click()
        large_source = 'config firewall address\n' + ''.join(
            f'edit host-{number}\nset subnet 192.0.{number // 256 % 256}.{number % 256} 255.255.255.255\nnext\n'
            for number in range(2000)) + 'end\n'
        started = perf_counter()
        page.get_by_label('Drop your configuration here').set_input_files({
            'name': 'large.conf', 'mimeType': 'text/plain', 'buffer': large_source.encode()})
        page.get_by_role('heading', name='Setup', exact=True).wait_for()
        expect(page.get_by_text('Preparing and validating', exact=False)).not_to_be_visible()
        large_load_ms = round((perf_counter() - started) * 1000, 1)
        page.get_by_role('button', name='3. Review & approve', exact=True).click()
        page.get_by_label('Show proposals').select_option('all')
        expect(page.locator('.migration-proposal-row:visible')).to_have_count(30)
        started = perf_counter()
        search = page.get_by_placeholder('Source or target name')
        search.fill('host-1999')
        expect(page.locator('.migration-proposal-row:visible')).to_have_count(1)
        search_ms = round((perf_counter() - started) * 1000, 1)
        expect(search).to_be_focused()
        assert not errors, errors
        print(json.dumps({'flow': 'PASS', 'approval_requests': len(approvals), 'command_sha256': digest,
                          'batch_override_count': batch_override_count,
                          'restored_proposals': len(project['proposals']), 'javascript_errors': errors,
                          'large_fixture_objects': 2000, 'large_fixture_bytes': len(large_source.encode()),
                          'large_browser_load_ms': large_load_ms, 'large_browser_search_ms': search_ms}))
        browser.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://127.0.0.1:5000')
    parser.add_argument('--chromium', default='/usr/bin/chromium')
    parser.add_argument('--destination', action='store_true', help='Exercise the advanced destination-aware workflow')
    args = parser.parse_args()
    run(args.url, args.chromium, args.destination)
