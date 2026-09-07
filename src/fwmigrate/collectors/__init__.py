"""Live source configuration collectors.

Collectors acquire raw vendor configuration. They do not parse or normalize it.
"""

from fwmigrate.collectors.models import ConnectionResult, SourceSnapshot
from fwmigrate.collectors.fortigate import FortiGateSSHCollector

__all__ = ["ConnectionResult", "SourceSnapshot", "FortiGateSSHCollector"]
