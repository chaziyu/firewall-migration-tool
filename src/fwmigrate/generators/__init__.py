# Import all built-in target generators to register them with PluginRegistry
import fwmigrate.generators.palo_alto
import fwmigrate.generators.fortigate
import fwmigrate.generators.cisco_asa
import fwmigrate.generators.checkpoint
import fwmigrate.generators.juniper_srx

__all__ = ["palo_alto", "fortigate", "cisco_asa", "checkpoint", "juniper_srx"]
