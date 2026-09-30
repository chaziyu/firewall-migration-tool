"""Compatibility import for planning.schedules."""

from .planning import schedules as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
