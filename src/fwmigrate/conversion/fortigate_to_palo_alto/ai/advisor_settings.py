"""Environment-backed configuration for the pair-specific AI advisor."""

from __future__ import annotations

import os

DEFAULT_SIMPLE_MODEL = "openai/gpt-oss-20b"
DEFAULT_COMPLEX_MODEL = "openai/gpt-oss-120b"
DEFAULT_REPAIR_MODEL = "openai/gpt-oss-120b"
MAX_DECISIONS = 2
DEFAULT_MAX_REQUEST_BYTES = 24 * 1024
DEFAULT_MAX_CANDIDATES_PER_DECISION = 12
DEFAULT_MAX_COMPLETION_TOKENS = 1536
DEFAULT_MAX_RETRY_DELAY_SECONDS = 10.0
DEFAULT_COMPLEX_CANDIDATE_THRESHOLD = 3


def advisor_enabled() -> bool:
    return os.environ.get("FWMIGRATE_AI_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}


def advisor_provider() -> str:
    return "qwen_local" if os.environ.get("FWMIGRATE_AI_LOCAL_URL", "").strip() else "groq"


def groq_model(tier="complex") -> str:
    setting, default = {
        "simple": ("FWMIGRATE_AI_SIMPLE_MODEL", DEFAULT_SIMPLE_MODEL),
        "complex": ("FWMIGRATE_AI_COMPLEX_MODEL", DEFAULT_COMPLEX_MODEL),
        "repair": ("FWMIGRATE_AI_REPAIR_MODEL", DEFAULT_REPAIR_MODEL),
    }.get(tier, ("FWMIGRATE_AI_COMPLEX_MODEL", DEFAULT_COMPLEX_MODEL))
    return (
        os.environ.get(setting)
        or os.environ.get("FWMIGRATE_AI_GROQ_MODEL")
        or os.environ.get("FWMIGRATE_GROQ_MODEL")
        or os.environ.get("FWMIGRATE_AI_MODEL")
        or default
    ).strip() or default


def _max_completion_tokens() -> int:
    try:
        return min(65536, max(256, int(os.environ.get(
            "FWMIGRATE_AI_MAX_COMPLETION_TOKENS", DEFAULT_MAX_COMPLETION_TOKENS
        ))))
    except (TypeError, ValueError):
        return DEFAULT_MAX_COMPLETION_TOKENS


def _reasoning_effort() -> str:
    value = os.environ.get("FWMIGRATE_AI_REASONING_EFFORT", "medium").strip().lower()
    return value if value in {"low", "medium", "high"} else "medium"


def _reasoning_format() -> str:
    value = os.environ.get("FWMIGRATE_AI_REASONING_FORMAT", "hidden").strip().lower()
    return value if value in {"hidden", "raw", "parsed"} else "hidden"


def _max_decisions() -> int:
    try:
        return min(32, max(1, int(os.environ.get("FWMIGRATE_AI_MAX_BATCH", MAX_DECISIONS))))
    except (TypeError, ValueError):
        return MAX_DECISIONS


def _max_request_bytes() -> int:
    try:
        return min(1_000_000, max(1024, int(os.environ.get(
            "FWMIGRATE_AI_MAX_REQUEST_BYTES", DEFAULT_MAX_REQUEST_BYTES
        ))))
    except (TypeError, ValueError):
        return DEFAULT_MAX_REQUEST_BYTES


def _max_candidates_per_decision() -> int:
    try:
        return min(256, max(1, int(os.environ.get(
            "FWMIGRATE_AI_MAX_CANDIDATES_PER_DECISION", DEFAULT_MAX_CANDIDATES_PER_DECISION
        ))))
    except (TypeError, ValueError):
        return DEFAULT_MAX_CANDIDATES_PER_DECISION


def _timeout() -> float:
    try:
        return min(
            120.0,
            max(1.0, float(os.environ.get(
                "FWMIGRATE_AI_TIMEOUT",
                os.environ.get("FWMIGRATE_AI_TIMEOUT_SECONDS", "30"),
            ))),
        )
    except ValueError:
        return 30.0


def _max_retry_delay() -> float:
    try:
        return min(60.0, max(0.1, float(os.environ.get(
            "FWMIGRATE_AI_MAX_RETRY_DELAY_SECONDS", DEFAULT_MAX_RETRY_DELAY_SECONDS
        ))))
    except (TypeError, ValueError):
        return DEFAULT_MAX_RETRY_DELAY_SECONDS


def _complex_candidate_threshold() -> int:
    try:
        return min(64, max(1, int(os.environ.get(
            "FWMIGRATE_AI_COMPLEX_CANDIDATE_THRESHOLD", DEFAULT_COMPLEX_CANDIDATE_THRESHOLD
        ))))
    except (TypeError, ValueError):
        return DEFAULT_COMPLEX_CANDIDATE_THRESHOLD
