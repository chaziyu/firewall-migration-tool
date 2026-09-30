"""Compatibility import for rendering.cli_paths."""

from .rendering import cli_paths as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
