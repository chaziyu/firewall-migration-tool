"""Firewall Migration Tool package."""

from fwmigrate.builtin_plugins import register_builtin_plugins

# Keep imports from any fwmigrate submodule backward-compatible while making
# the built-in catalog the only registration path.
register_builtin_plugins()

import fwmigrate.generators as generators
import fwmigrate.parsers as parsers

__all__ = ["generators", "parsers", "register_builtin_plugins"]
