"""Compatibility import for planning.interfaces."""

from .planning import interfaces as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
