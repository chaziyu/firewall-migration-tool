"""Provider-agnostic structured generation contract."""

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class AIStructuredResult:
    data: dict[str, Any]
    provider: str
    model: str
    request_id: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None


class AIProvider(Protocol):
    def generate_structured(self, *, system_prompt: str, payload: dict, schema_name: str,
                           schema: dict) -> AIStructuredResult: ...
