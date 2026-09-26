"""Environment-backed configuration for optional AI assistance."""

from dataclasses import dataclass
import math
import os


@dataclass(frozen=True, slots=True)
class AISettings:
    enabled: bool = False
    provider: str = "groq"
    model: str = "openai/gpt-oss-120b"
    reasoning_effort: str = "medium"
    timeout_seconds: float = 30
    max_context_bytes: int = 16000
    max_review_groups: int = 20
    max_questions: int = 8


def _positive_number(name, default, cast):
    try:
        value = cast(os.environ.get(name, default))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a positive number") from exc
    if value <= 0 or (isinstance(value, float) and not math.isfinite(value)):
        raise ValueError(f"{name} must be a positive number")
    return value


def get_ai_settings():
    enabled = os.environ.get("AI_ASSIST_ENABLED", "false").strip().casefold() in {"1", "true", "yes", "on"}
    provider = os.environ.get("AI_PROVIDER", "groq").strip().casefold()
    if provider != "groq":
        raise ValueError("AI_PROVIDER must be groq")
    model = os.environ.get("AI_MODEL", "openai/gpt-oss-120b").strip()
    reasoning_effort = os.environ.get("AI_REASONING_EFFORT", "medium").strip().casefold()
    if not model or reasoning_effort not in {"low", "medium", "high"}:
        raise ValueError("AI_MODEL and AI_REASONING_EFFORT must be valid")
    return AISettings(
        enabled=enabled,
        provider=provider,
        model=model,
        reasoning_effort=reasoning_effort,
        timeout_seconds=_positive_number("AI_TIMEOUT_SECONDS", "30", float),
        max_context_bytes=min(_positive_number("AI_MAX_CONTEXT_BYTES", "16000", int), 16000),
        max_review_groups=min(_positive_number("AI_MAX_REVIEW_GROUPS", "20", int), 20),
        max_questions=min(_positive_number("AI_MAX_QUESTIONS", "8", int), 8),
    )
