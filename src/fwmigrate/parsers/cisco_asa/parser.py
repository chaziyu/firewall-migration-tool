from fwmigrate.vendors.cisco_asa.parser import *
from fwmigrate.vendors.cisco_asa.parser import (
    CiscoASAParser as _CiscoASAParser,
    _nat_port_range,
    _pbr_acl_match_evidence,
    _safe_name,
)


class CiscoASAParser(_CiscoASAParser):
    """Compatibility class for legacy parser imports."""

    def parse_raw(self):
        return super().parse_raw()

    def transform_to_ir(self):
        return super().transform_to_ir()
