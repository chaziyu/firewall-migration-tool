"""Compatibility import for recommendations.external_resource_suggestions."""

from .recommendations import external_resource_suggestions as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
