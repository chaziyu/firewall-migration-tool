# Import all built-in source parsers to register them with PluginRegistry
import fg2pan.parsers.fortigate
import fg2pan.parsers.cisco_asa
import fg2pan.parsers.checkpoint
import fg2pan.parsers.juniper_srx

__all__ = ["fortigate", "cisco_asa", "checkpoint", "juniper_srx"]
