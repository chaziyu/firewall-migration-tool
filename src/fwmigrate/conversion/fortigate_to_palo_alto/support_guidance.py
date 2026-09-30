"""Compatibility import for recommendations.support_guidance."""

from .recommendations import support_guidance as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
