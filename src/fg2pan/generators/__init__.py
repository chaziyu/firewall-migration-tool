# Import all built-in target generators to register them with PluginRegistry
import fg2pan.generators.palo_alto
import fg2pan.generators.fortigate
import fg2pan.generators.cisco_asa
import fg2pan.generators.checkpoint
import fg2pan.generators.juniper_srx

__all__ = ["palo_alto", "fortigate", "cisco_asa", "checkpoint", "juniper_srx"]
