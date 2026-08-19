# Import all built-in target generators to register them with PluginRegistry
import fg2pan.generators.palo_alto
import fg2pan.generators.fortigate

__all__ = ["palo_alto", "fortigate"]
