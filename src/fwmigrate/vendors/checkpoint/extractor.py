"""Vendor-native Check Point source extraction and legacy adapter entry point."""

from __future__ import annotations

from typing import Dict, Optional

from .ir_adapter import CheckPointIRAdapter
from .loader import load_checkpoint_input
from .source_model import build_checkpoint_config


def extract_checkpoint_config(
    content: str,
    zone_mapping: Optional[Dict[str, str]] = None,
):
    """Build the source aggregate, then project it through the legacy IR adapter."""
    bundle, scope = load_checkpoint_input(content)
    config = build_checkpoint_config(bundle)
    return CheckPointIRAdapter(config, bundle, scope, zone_mapping).to_extraction_result()


__all__ = ["extract_checkpoint_config"]
