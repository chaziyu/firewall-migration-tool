"""Optional provider boundary for user-triggered AI assistance."""

from .config import AISettings, get_ai_settings
from .errors import (
    AIConfigurationError,
    AIDisabledError,
    AIError,
    AIInvalidResponseError,
    AIProviderError,
    AIRateLimitError,
    AIStaleProposalError,
    AITimeoutError,
)
from .provider import AIProvider, AIStructuredResult

__all__ = [
    "AIConfigurationError", "AIDisabledError", "AIError", "AIInvalidResponseError",
    "AIProvider", "AIProviderError", "AIRateLimitError", "AISettings",
    "AIStaleProposalError", "AIStructuredResult", "AITimeoutError", "get_ai_settings",
]
