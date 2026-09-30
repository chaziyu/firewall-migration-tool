"""Compatibility import for planning.topology."""

from .planning import topology as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
