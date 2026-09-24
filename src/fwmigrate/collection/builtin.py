"""Built-in live collectors."""

from .cisco_asa import CiscoASACollector
from .cisco_ftd import CiscoFTDCollector
from .checkpoint import CheckPointCollector
from .juniper_srx import JuniperSRXCollector
from .registry import source_collectors


_BUILTIN_COLLECTORS = (CiscoASACollector(), JuniperSRXCollector(), CiscoFTDCollector(), CheckPointCollector())


def register_builtin_collectors() -> None:
    for collector in _BUILTIN_COLLECTORS:
        source_collectors.register(collector)
