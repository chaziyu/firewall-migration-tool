"""Compatibility import for review.review_context."""

from .review import review_context as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
