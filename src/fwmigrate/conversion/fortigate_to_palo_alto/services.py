"""Compatibility import for planning.services."""

from .planning import services as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
