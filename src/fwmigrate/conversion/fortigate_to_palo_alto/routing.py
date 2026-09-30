"""Compatibility import for planning.routing."""

from .planning import routing as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
