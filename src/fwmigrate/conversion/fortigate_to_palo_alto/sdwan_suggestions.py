"""Compatibility import for recommendations.sdwan_suggestions."""

from .recommendations import sdwan_suggestions as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
