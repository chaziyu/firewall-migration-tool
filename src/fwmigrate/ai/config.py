"""Environment-backed configuration for optional AI assistance."""

from dataclasses import dataclass
import math
import os


@dataclass(frozen=True, slots=True)
class AISettings:
    enabled: bool = True
    provider: str = "local"
    model: str = "openai/gpt-oss-120b"
    reasoning_effort: str = "medium"
    timeout_seconds: float = 30
    local_model: str = "qwen3-1.7b-q4_k_m"
    local_context_size: int = 4096
    local_idle_seconds: int = 300
    local_threads: int | None = None
    local_timeout_seconds: float = 120
    local_startup_timeout_seconds: float = 90
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
    enabled = os.environ.get("AI_ASSIST_ENABLED", "true").strip().casefold() in {"1", "true", "yes", "on"}
    provider = os.environ.get("AI_PROVIDER", "local").strip().casefold()
    if provider not in {"local", "groq"}:
        raise ValueError("AI_PROVIDER must be local or groq")
    from .manifests import LOCAL_MODEL
    local_model = os.environ.get("AI_LOCAL_MODEL", LOCAL_MODEL.model_id).strip()
    if local_model != LOCAL_MODEL.model_id:
        raise ValueError("AI_LOCAL_MODEL is not in the pinned model manifest")
    model = (os.environ.get("AI_MODEL", "openai/gpt-oss-120b").strip()
             if provider == "groq" else local_model)
    reasoning_effort = os.environ.get("AI_REASONING_EFFORT", "medium").strip().casefold()
    if not model or reasoning_effort not in {"low", "medium", "high"}:
        raise ValueError("AI_MODEL and AI_REASONING_EFFORT must be valid")
    return AISettings(
        enabled=enabled,
        provider=provider,
        model=model,
        reasoning_effort=reasoning_effort,
        timeout_seconds=_positive_number("AI_TIMEOUT_SECONDS", "30", float),
        local_model=local_model,
        local_context_size=_positive_number("AI_LOCAL_CONTEXT_SIZE", "4096", int),
        local_idle_seconds=_positive_number("AI_LOCAL_IDLE_SECONDS", "300", int),
        local_threads=(None if os.environ.get("AI_LOCAL_THREADS", "auto").strip().casefold() == "auto"
                       else _positive_number("AI_LOCAL_THREADS", "auto", int)),
        local_timeout_seconds=_positive_number("AI_LOCAL_TIMEOUT_SECONDS", "120", float),
        local_startup_timeout_seconds=_positive_number("AI_LOCAL_STARTUP_TIMEOUT_SECONDS", "90", float),
        max_context_bytes=min(_positive_number("AI_MAX_CONTEXT_BYTES", "16000", int), 16000),
        max_review_groups=min(_positive_number("AI_MAX_REVIEW_GROUPS", "20", int), 20),
        max_questions=min(_positive_number("AI_MAX_QUESTIONS", "8", int), 8),
    )
