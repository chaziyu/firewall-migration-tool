# Import all built-in source parsers to register them with PluginRegistry
import fwmigrate.parsers.fortigate
import fwmigrate.parsers.palo_alto
import fwmigrate.parsers.cisco_asa
import fwmigrate.parsers.checkpoint
import fwmigrate.parsers.juniper_srx

__all__ = ["fortigate", "palo_alto", "cisco_asa", "checkpoint", "juniper_srx"]
