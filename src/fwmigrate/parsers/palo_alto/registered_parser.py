"""Backward-compatible PAN-OS parser import."""

from .pipeline import PANOSExtractionPipeline

PANOSSourceParser = PANOSExtractionPipeline

__all__ = ["PANOSSourceParser"]
