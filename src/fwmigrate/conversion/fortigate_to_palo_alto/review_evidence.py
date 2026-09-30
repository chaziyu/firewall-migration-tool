"""Compatibility import for review.review_evidence."""

from .review import review_evidence as _m
globals().update({key: getattr(_m, key) for key in dir(_m) if not key.startswith("__")})
