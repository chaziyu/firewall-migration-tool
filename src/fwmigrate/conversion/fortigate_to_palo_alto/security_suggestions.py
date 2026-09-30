"""Compatibility import for recommendations.security_suggestions."""

from .recommendations import security_suggestions as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
