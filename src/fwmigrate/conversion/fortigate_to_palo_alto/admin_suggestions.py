"""Compatibility import for recommendations.admin_suggestions."""

from .recommendations import admin_suggestions as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
