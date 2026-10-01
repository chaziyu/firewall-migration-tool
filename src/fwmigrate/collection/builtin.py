"""Built-in live collectors."""

from .cisco_asa import CiscoASACollector
from .cisco_ftd import CiscoFTDCollector
from .checkpoint import CheckPointCollector
from .juniper_srx import JuniperSRXCollector
from .registry import source_collectors
from .registry import collected_source_sanitizers
from fwmigrate.vendors.cisco_asa.collection_source import CiscoASACollectedSourceSanitizer
from fwmigrate.vendors.cisco_ftd.collection_source import CiscoFTDCollectedSourceSanitizer
from fwmigrate.vendors.checkpoint.collection_source import CheckPointCollectedSourceSanitizer
from fwmigrate.vendors.juniper_srx.collection_source import JuniperCollectedSourceSanitizer
from fwmigrate.vendors.fortigate.collection_source import FortiGateCollectedSourceSanitizer
from fwmigrate.vendors.palo_alto.collection_source import PANOSCollectedSourceSanitizer


_BUILTIN_COLLECTORS = (CiscoASACollector(), JuniperSRXCollector(), CiscoFTDCollector(), CheckPointCollector())
_BUILTIN_SANITIZERS = (CiscoASACollectedSourceSanitizer(), JuniperCollectedSourceSanitizer(),
                       CiscoFTDCollectedSourceSanitizer(), CheckPointCollectedSourceSanitizer(),
                       FortiGateCollectedSourceSanitizer(), PANOSCollectedSourceSanitizer())


def register_builtin_source_sanitizers() -> None:
    for sanitizer in _BUILTIN_SANITIZERS:
        collected_source_sanitizers.register(sanitizer)


def register_builtin_collectors() -> None:
    register_builtin_source_sanitizers()
    for collector in _BUILTIN_COLLECTORS:
        source_collectors.register(collector)
