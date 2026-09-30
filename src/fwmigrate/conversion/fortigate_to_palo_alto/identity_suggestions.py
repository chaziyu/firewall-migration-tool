"""Compatibility import for recommendations.identity_suggestions."""

from .recommendations import identity_suggestions as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
