"""Compatibility import for recommendations.recommendation_engine."""

from .recommendations import recommendation_engine as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
