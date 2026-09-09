# Import all built-in source parsers to register them with PluginRegistry
import fwmigrate.parsers.fortigate
import fwmigrate.parsers.palo_alto
import fwmigrate.parsers.cisco_asa
import fwmigrate.parsers.cisco_ftd
import fwmigrate.parsers.checkpoint
import fwmigrate.parsers.juniper_srx

__all__ = ["fortigate", "palo_alto", "cisco_asa", "cisco_ftd", "checkpoint", "juniper_srx"]
