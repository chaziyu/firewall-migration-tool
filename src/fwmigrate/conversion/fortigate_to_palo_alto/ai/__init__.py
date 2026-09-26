"""Pair-specific AI assistance for FortiGate to PAN-OS engineer review."""

from .assistant import explain_review_group, generate_architecture_questions
from .cache import proposal_cache

__all__ = ["explain_review_group", "generate_architecture_questions", "proposal_cache"]
