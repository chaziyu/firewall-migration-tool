"""Firewall Migration Tool package."""

from fwmigrate.builtin_plugins import register_builtin_plugins

# Register only vendor-native source reporters at package startup.
register_builtin_plugins()

__all__ = ["register_builtin_plugins"]
