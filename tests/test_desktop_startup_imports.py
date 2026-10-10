import importlib
import subprocess
import sys

import pytest


def test_desktop_startup_and_vendor_listing_do_not_load_reporters_or_excel():
    subprocess.run([sys.executable, '-c', '''
import sys
from fwmigrate.desktop_server import create_desktop_app
app = create_desktop_app('startup-test', {'TESTING': True})
response = app.test_client().get('/api/vendors', headers={'X-FWMigrate-Desktop-Token': 'startup-test'})
assert response.status_code == 200
assert len(response.get_json()['sources']) == 6
assert 'openpyxl' not in sys.modules
assert not any(name.endswith('.source_report') for name in sys.modules)
'''], check=True, timeout=30)


def test_lazy_reporter_metadata_matches_vendor_implementations():
    from fwmigrate.source_reporting.builtin import _BUILTIN_REPORTERS
    from fwmigrate.source_reporting.builtin import register_builtin_source_reporters
    from fwmigrate.source_reporting import source_reporters
    register_builtin_source_reporters()
    for reporter in _BUILTIN_REPORTERS:
        implementation = getattr(importlib.import_module(
            f'fwmigrate.vendors.{reporter.vendor_id}.source_report'), reporter._class_name)
        assert reporter.display_name == implementation.display_name
        assert reporter.supported_extensions == implementation.supported_extensions
        assert isinstance(source_reporters.get(reporter.vendor_id), implementation)
        assert any(isinstance(candidate, implementation)
                   for candidate in source_reporters.for_extension(reporter.supported_extensions[0]))


def test_lazy_reporter_retries_failed_load_and_preserves_opaque_arguments(monkeypatch):
    from types import SimpleNamespace
    from fwmigrate.source_reporting import builtin

    result = object()
    calls = []

    class Reporter:
        def analyze_source(self, source, **options):
            calls.append((source, options))
            return result

        def build_preview(self, analysis, **options):
            assert analysis is result
            return options

        def export_excel(self, analysis, output, **options):
            assert analysis is result
            return output, options

    attempts = 0

    def load(name):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ImportError('not available')
        return SimpleNamespace(Reporter=Reporter)

    monkeypatch.setattr(builtin, 'import_module', load)
    reporter = builtin._LazySourceReporter('vendor', 'Vendor', ('.txt',), 'Reporter')
    with pytest.raises(ImportError):
        reporter.analyze_source('source')
    assert reporter.analyze_source('source', option=True) is result
    assert calls == [('source', {'option': True})]
    assert reporter.build_preview(result, preview=True) == {'preview': True}
    assert reporter.export_excel(result, 'output', profile='fast') == ('output', {'profile': 'fast'})
    assert attempts == 2


@pytest.mark.parametrize('vendor', ['fortigate', 'checkpoint', 'cisco_asa', 'cisco_ftd', 'juniper_srx', 'palo_alto'])
def test_lazy_package_exports_preserve_public_identity(vendor):
    package = importlib.import_module(f'fwmigrate.vendors.{vendor}')
    for name in package.__all__:
        module, attribute = package._EXPORTS[name]
        assert getattr(package, name) is getattr(importlib.import_module(module, package.__name__), attribute)
    with pytest.raises(AttributeError):
        getattr(package, 'missing_export')
