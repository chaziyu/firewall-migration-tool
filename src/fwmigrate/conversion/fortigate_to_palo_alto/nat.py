"""Compatibility import for planning.nat."""

from .planning import nat as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
