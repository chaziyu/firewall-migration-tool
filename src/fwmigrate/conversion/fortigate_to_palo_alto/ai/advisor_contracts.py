"""Advisor result/error contracts and safe provider diagnostics."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AdvisorFailure:
    category: str
    provider: str
    model: str
    status: int | None = None
    request_id: str | None = None
    provider_code: str | None = None
    provider_type: str | None = None
    safe_reason: str | None = None
    decision_keys: tuple[str, ...] = ()
    batch_size: int = 0
    candidate_count: int = 0
    request_bytes: int = 0
    retry_after_seconds: float | None = None

    def to_dict(self) -> dict:
        return {
            "failure_category": self.category,
            "provider": self.provider,
            "model": self.model,
            "status": self.status,
            "request_id": self.request_id,
            "provider_code": self.provider_code,
            "provider_type": self.provider_type,
            "safe_reason": self.safe_reason,
            "decision_keys": list(self.decision_keys),
            "batch_size": self.batch_size,
            "candidate_count": self.candidate_count,
            "request_bytes": self.request_bytes,
            "retry_after_seconds": self.retry_after_seconds,
        }


@dataclass(frozen=True, slots=True)
class RepairResult:
    proposals: tuple[dict, ...]
    failures: tuple[dict, ...] = ()
    exhausted: bool = False

    def __iter__(self):
        return iter(self.proposals)


class AdvisorError(ValueError):
    code = "AI_INTERNAL_ERROR"
    message = "The AI advisor could not complete the request."

    def __init__(self, detail="", *, status=None, request_id=None, reason=None, failure=None):
        super().__init__(detail or self.message)
        self.status = status
        self.request_id = request_id
        self.reason = reason
        self.failure = failure


class AdvisorUnavailable(AdvisorError):
    code = "AI_UNAVAILABLE"
    message = "The configured AI provider is unavailable."


class AdvisorAuthenticationError(AdvisorError):
    code = "AI_AUTH_FAILED"
    message = "The AI provider rejected its credentials."


class AdvisorRateLimitError(AdvisorError):
    code = "AI_RATE_LIMITED"
    message = "The AI provider is rate limited."


class AdvisorTimeoutError(AdvisorError):
    code = "AI_TIMEOUT"
    message = "The AI provider timed out."


class AdvisorRequestError(AdvisorError):
    code = "AI_REQUEST_REJECTED"
    message = "The configured AI model rejected the advisor request."


class AdvisorResponseError(AdvisorError):
    code = "AI_RESPONSE_INVALID"
    message = "The AI provider returned an invalid response."


class AdvisorProposalValidationError(AdvisorError):
    code = "AI_PROPOSAL_INVALID"
    message = "The AI proposal failed deterministic validation."

    def __init__(self, detail="", *, reason="PROPOSAL_INVALID"):
        super().__init__(detail, reason=reason)


def _safe_diagnostic_text(value):
    if not isinstance(value, str) or "\n" in value or "\r" in value:
        return None
    lowered = value.casefold()
    if value.lstrip().startswith(("{", "[")) or any(marker in lowered for marker in (
        "migration_pair", "candidate_id", "decision_id", "evidence_refs", "source_vdom",
        "target_device", "fortigate to pan-os", "config system", "config firewall",
    )):
        return None
    value = " ".join(value.split())
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if api_key:
        value = value.replace(api_key, "[redacted]")
    value = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [redacted]", value)
    value = re.sub(r"(?i)\b(?:gsk_|sk-)[A-Za-z0-9_-]{8,}", "[redacted]", value)
    value = re.sub(
        r"(?i)\b(password|passwd|token|secret|api[_-]?key|private[_ -]?key|psk)\b\s*[:=]\s*[^,;\s]+",
        r"\1=[redacted]",
        value,
    )
    if any(marker in value.casefold() for marker in ("config system", "config firewall", "set password", "private key")):
        return None
    return value[:240] or None


def _provider_error_payload(exc):
    body = getattr(exc, "body", None)
    if body is None:
        response = getattr(exc, "response", None)
        try:
            body = response.json() if response is not None else None
        except (AttributeError, TypeError, ValueError):
            body = None
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except (TypeError, ValueError):
            return None
    return body if isinstance(body, dict) else None


def _retry_after_seconds(headers):
    if headers is None:
        return None
    raw = headers.get("retry-after") or headers.get("Retry-After")
    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None
