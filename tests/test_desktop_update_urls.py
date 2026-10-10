import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    'fix_desktop_update_urls', Path(__file__).resolve().parents[1] / 'scripts/fix_desktop_update_urls.py'
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_update_urls_preserve_signatures_and_support_repeat_runs():
    api = 'https://api.github.com/repos/chaziyu/firewall-migration-tool/releases/assets/123'
    direct = 'https://github.com/chaziyu/firewall-migration-tool/releases/download/desktop-v0.2.1/tool-setup.exe'
    manifest = {'version': '0.2.1', 'notes': 'notes', 'platforms': {
        key: {'url': api, 'signature': 'signed'}
        for key in ('windows-x86_64', 'windows-x86_64-nsis')
    }}
    release = {'tag_name': 'desktop-v0.2.1', 'assets': [{'url': api, 'browser_download_url': direct}]}
    for _ in range(2):
        module.fix_urls(manifest, release, 'chaziyu/firewall-migration-tool')
        assert all(entry == {'url': direct, 'signature': 'signed'} for entry in manifest['platforms'].values())
        assert manifest['notes'] == 'notes'


@pytest.mark.parametrize('fault', ['tag', 'source', 'missing', 'signature'])
def test_update_urls_reject_invalid_release_metadata(fault):
    manifest = {'version': '0.2.1', 'platforms': {'windows-x86_64': {'url': 'api', 'signature': 'signed'}}}
    release = {'tag_name': 'desktop-v0.2.1', 'assets': [{'url': 'api', 'browser_download_url':
        'https://github.com/chaziyu/firewall-migration-tool/releases/download/desktop-v0.2.1/tool-setup.exe'}]}
    if fault == 'tag':
        release['tag_name'] = 'desktop-v0.2.0'
    elif fault == 'source':
        release['assets'][0]['browser_download_url'] = 'https://example.com/tool-setup.exe'
    elif fault == 'missing':
        release['assets'] = []
    else:
        manifest['platforms']['windows-x86_64']['signature'] = ''
    with pytest.raises((ValueError, KeyError)):
        module.fix_urls(manifest, release, 'chaziyu/firewall-migration-tool')
    assert manifest['platforms']['windows-x86_64']['url'] == 'api'
