"""Compatibility import for planning.addresses."""

from .planning import addresses as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
