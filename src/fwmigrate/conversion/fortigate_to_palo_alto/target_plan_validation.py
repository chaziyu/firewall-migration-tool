"""Compatibility import for target.target_plan_validation."""

from .target import target_plan_validation as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
