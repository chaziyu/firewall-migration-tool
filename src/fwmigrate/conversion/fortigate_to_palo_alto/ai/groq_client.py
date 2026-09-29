"""Thin Groq transport for the FortiGate to PAN-OS AI advisor.

This module owns Groq credential lookup, SDK loading, request execution, and
response-content extraction. Migration-specific prompting, candidate selection,
validation, and error policy remain in ai_advisor.py.
"""

from __future__ import annotations

import os


class GroqClientUnavailable(RuntimeError):
    """Groq cannot be called because local client configuration is unavailable."""


class GroqClientResponseError(ValueError):
    """Groq returned a completion without usable message content."""


def configured() -> bool:
    return bool(os.environ.get("GROQ_API_KEY", "").strip())


def request_content(request_kwargs: dict, *, timeout: float) -> str:
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        raise GroqClientUnavailable("GROQ_API_KEY is not configured")
    try:
        from groq import Groq
    except ImportError as exc:
        raise GroqClientUnavailable(
            "Install the optional AI dependencies to use Groq"
        ) from exc

    completion = Groq(api_key=api_key, timeout=timeout).chat.completions.create(
        **request_kwargs
    )
    try:
        content = completion.choices[0].message.content
    except (AttributeError, IndexError, TypeError) as exc:
        raise GroqClientResponseError(
            "AI advisor returned no proposal content"
        ) from exc
    if not isinstance(content, str) or not content:
        raise GroqClientResponseError("AI advisor returned no proposal content")
    return content
