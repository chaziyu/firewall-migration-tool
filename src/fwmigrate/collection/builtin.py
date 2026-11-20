"""Built-in live collectors."""

from importlib import import_module
from threading import Lock
from typing import Any

from .contracts import SSH_FIELDS
from .registry import collected_source_sanitizers, source_collectors


class _LazySourceCollector:
    """Keep collector discovery lightweight while loading vendor transports on demand."""

    def __init__(
        self,
        vendor_id: str,
        method: str,
        fields: tuple[dict[str, Any], ...],
        module_name: str,
        class_name: str,
    ) -> None:
        self.vendor_id = vendor_id
        self.method = method
        self.fields = fields
        self._module_name = module_name
        self._class_name = class_name
        self._collector = None
        self._lock = Lock()

    def _load(self):
        with self._lock:
            if self._collector is None:
                module = import_module(self._module_name)
                self._collector = getattr(module, self._class_name)()
            return self._collector

    def validate_options(self, connection: dict[str, Any]) -> dict[str, Any]:
        return self._load().validate_options(connection)

    def test_connection(self, options: dict[str, Any]) -> None:
        self._load().test_connection(options)

    def collect(self, options: dict[str, Any]):
        return self._load().collect(options)


class _LazySourceSanitizer:
    """Load vendor-native snapshot sanitizers on first use."""

    def __init__(self, vendor_id: str, module_name: str, class_name: str) -> None:
        self.vendor_id = vendor_id
        self._module_name = module_name
        self._class_name = class_name
        self._sanitizer = None
        self._lock = Lock()

    def _load(self):
        with self._lock:
            if self._sanitizer is None:
                module = import_module(self._module_name)
                self._sanitizer = getattr(module, self._class_name)()
            return self._sanitizer

    def sanitize(self, source_text: str) -> str:
        return self._load().sanitize(source_text)


_CISCO_FTD_FIELDS = (
    {"name": "host", "label": "FMC HTTPS host", "type": "text", "required": True},
    {"name": "port", "label": "HTTPS port", "type": "number", "required": True, "default": 443},
    {"name": "username", "label": "Username", "type": "text", "required": True},
    {"name": "password", "label": "Password", "type": "password", "required": True},
    {"name": "domain", "label": "Domain name or UUID", "type": "text", "required": False},
)

_CHECKPOINT_FIELDS = (
    {"name": "host", "label": "Management HTTPS host", "type": "text", "required": True},
    {"name": "port", "label": "HTTPS port", "type": "number", "required": True, "default": 443},
    {"name": "username", "label": "Username", "type": "text", "required": True},
    {"name": "password", "label": "Password", "type": "password", "required": True},
    {"name": "domain", "label": "Domain", "type": "text", "required": False},
    {"name": "package", "label": "Policy package", "type": "text", "required": False},
    {"name": "layer", "label": "Access layer", "type": "text", "required": False},
    {"name": "gateway", "label": "Gateway", "type": "text", "required": False},
    {"name": "gaia_host", "label": "Gaia SSH host (optional)", "type": "text", "required": False},
    {"name": "gaia_port", "label": "Gaia SSH port", "type": "number", "required": False, "default": 22},
    {"name": "gaia_username", "label": "Gaia username", "type": "text", "required": False},
    {"name": "gaia_password", "label": "Gaia password", "type": "password", "required": False},
)

_BUILTIN_COLLECTORS = (
    _LazySourceCollector("cisco_asa", "ssh", SSH_FIELDS, "fwmigrate.collection.cisco_asa", "CiscoASACollector"),
    _LazySourceCollector("juniper_srx", "ssh", SSH_FIELDS, "fwmigrate.collection.juniper_srx", "JuniperSRXCollector"),
    _LazySourceCollector("cisco_ftd", "https", _CISCO_FTD_FIELDS, "fwmigrate.collection.cisco_ftd", "CiscoFTDCollector"),
    _LazySourceCollector("checkpoint", "management-api", _CHECKPOINT_FIELDS, "fwmigrate.collection.checkpoint", "CheckPointCollector"),
)

_BUILTIN_SANITIZERS = (
    _LazySourceSanitizer("cisco_asa", "fwmigrate.vendors.cisco_asa.collection_source", "CiscoASACollectedSourceSanitizer"),
    _LazySourceSanitizer("juniper_srx", "fwmigrate.vendors.juniper_srx.collection_source", "JuniperCollectedSourceSanitizer"),
    _LazySourceSanitizer("cisco_ftd", "fwmigrate.vendors.cisco_ftd.collection_source", "CiscoFTDCollectedSourceSanitizer"),
    _LazySourceSanitizer("checkpoint", "fwmigrate.vendors.checkpoint.collection_source", "CheckPointCollectedSourceSanitizer"),
    _LazySourceSanitizer("fortigate", "fwmigrate.vendors.fortigate.collection_source", "FortiGateCollectedSourceSanitizer"),
    _LazySourceSanitizer("palo_alto", "fwmigrate.vendors.palo_alto.collection_source", "PANOSCollectedSourceSanitizer"),
)


def register_builtin_source_sanitizers() -> None:
    for sanitizer in _BUILTIN_SANITIZERS:
        collected_source_sanitizers.register(sanitizer, loader=sanitizer._load)


def register_builtin_collectors() -> None:
    register_builtin_source_sanitizers()
    for collector in _BUILTIN_COLLECTORS:
        source_collectors.register(collector, loader=collector._load)
