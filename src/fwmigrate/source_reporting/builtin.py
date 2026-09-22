"""Registration of the built-in vendor-native source reporters."""

from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter
from fwmigrate.vendors.checkpoint.source_report import CheckPointSourceReporter
from fwmigrate.vendors.cisco_asa.source_report import CiscoASASourceReporter
from fwmigrate.vendors.cisco_ftd.source_report import CiscoFTDSourceReporter
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.vendors.juniper_srx.source_report import JuniperSRXSourceReporter

from .registry import source_reporters


_BUILTIN_REPORTERS = (
    FortiGateSourceReporter(),
    CheckPointSourceReporter(),
    CiscoASASourceReporter(),
    CiscoFTDSourceReporter(),
    JuniperSRXSourceReporter(),
    PaloAltoSourceReporter(),
)


def register_builtin_source_reporters() -> None:
    for reporter in _BUILTIN_REPORTERS:
        source_reporters.register(reporter)


__all__ = ["register_builtin_source_reporters"]
