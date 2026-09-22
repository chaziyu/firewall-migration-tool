from fwmigrate.vendors.cisco_asa.source_report import CiscoASASourceReporter
from fwmigrate.vendors.cisco_ftd.source_report import CiscoFTDSourceReporter
from fwmigrate.vendors.juniper_srx.source_report import JuniperSRXSourceReporter
from fwmigrate.vendors.checkpoint.source_report import CheckPointSourceReporter
from fwmigrate.parsers.palo_alto.source_report import PaloAltoSourceReporter
from fwmigrate.source_reporting import source_reporters
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


_SOURCE_REPORTERS = (
    FortiGateSourceReporter(),
    CheckPointSourceReporter(),
    CiscoASASourceReporter(),
    CiscoFTDSourceReporter(),
    JuniperSRXSourceReporter(),
    PaloAltoSourceReporter(),
)


def register_builtin_plugins() -> None:
    for reporter in _SOURCE_REPORTERS:
        source_reporters.register(reporter)
