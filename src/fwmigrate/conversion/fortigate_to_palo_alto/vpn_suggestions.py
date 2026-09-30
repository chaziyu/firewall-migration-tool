"""Compatibility import for recommendations.vpn_suggestions."""

from .recommendations import vpn_suggestions as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
