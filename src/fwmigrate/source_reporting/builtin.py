"""Registration of the built-in vendor-native source reporters."""

from importlib import import_module
from threading import Lock

from .registry import source_reporters


class _LazySourceReporter:
    """Keep discovery lightweight while preserving opaque vendor dispatch."""

    def __init__(self, vendor_id, display_name, extensions, class_name):
        self.vendor_id = vendor_id
        self.display_name = display_name
        self.supported_extensions = extensions
        self._class_name = class_name
        self._reporter = None
        self._lock = Lock()

    def _load(self):
        with self._lock:
            if self._reporter is None:
                module = import_module(f'fwmigrate.vendors.{self.vendor_id}.source_report')
                self._reporter = getattr(module, self._class_name)()
            return self._reporter

    def analyze_source(self, source, **options):
        return self._load().analyze_source(source, **options)

    def build_preview(self, analysis, **options):
        return self._load().build_preview(analysis, **options)

    def export_excel(self, analysis, output, **options):
        return self._load().export_excel(analysis, output, **options)


_BUILTIN_REPORTERS = (
    _LazySourceReporter('fortigate', 'Fortinet FortiGate', ('.conf', '.cfg', '.txt'), 'FortiGateSourceReporter'),
    _LazySourceReporter('checkpoint', 'Check Point R81', ('.json', '.txt', '.cfg'), 'CheckPointSourceReporter'),
    _LazySourceReporter('cisco_asa', 'Cisco ASA', ('.cfg', '.txt', '.conf'), 'CiscoASASourceReporter'),
    _LazySourceReporter('cisco_ftd', 'Cisco Firepower Threat Defense', ('.cfg', '.txt', '.conf', '.json'), 'CiscoFTDSourceReporter'),
    _LazySourceReporter('juniper_srx', 'Juniper SRX', ('.set', '.txt', '.conf'), 'JuniperSRXSourceReporter'),
    _LazySourceReporter('palo_alto', 'Palo Alto Networks (PAN-OS / Panorama)', ('.xml',), 'PaloAltoSourceReporter'),
)


def register_builtin_source_reporters() -> None:
    for reporter in _BUILTIN_REPORTERS:
        source_reporters.register(reporter, loader=reporter._load)


__all__ = ["register_builtin_source_reporters"]
