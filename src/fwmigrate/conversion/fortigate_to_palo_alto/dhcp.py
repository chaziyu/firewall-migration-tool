"""Compatibility import for planning.dhcp."""

from .planning import dhcp as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
