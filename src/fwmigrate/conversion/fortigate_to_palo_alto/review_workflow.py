"""Compatibility import for review.review_workflow."""

from .review import review_workflow as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
