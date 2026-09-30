"""Compatibility import for rendering.renderer."""

from .rendering import renderer as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
