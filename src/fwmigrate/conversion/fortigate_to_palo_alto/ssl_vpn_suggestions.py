"""Compatibility import for recommendations.ssl_vpn_suggestions."""

from .recommendations import ssl_vpn_suggestions as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
