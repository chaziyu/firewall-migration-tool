from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PANAIProposalAction(str, Enum):
    USE_EXISTING = "USE_EXISTING"
    NO_SAFE_PROPOSAL = "NO_SAFE_PROPOSAL"


@dataclass(frozen=True, slots=True)
class PANAIProposal:
    decision_key: str
    action: PANAIProposalAction
    candidate_id: str | None
    proposed_value: str | None
    target_scope: str | None
    rationale: str
    evidence_refs: tuple[str, ...]
    evidence: tuple[dict, ...]
    provider: str
    model: str
    prompt_version: int
    source_digest: str
    target_digest: str
    target_device: str
    state_digest: str
    context_digest: str
    base_context_digest: str | None = None
    validation_status: str = "VALID"
    validation_findings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.decision_key or not self.provider or not self.model:
            raise ValueError("AI proposal identity and provider fields must be non-empty")
        if not all((self.source_digest, self.target_digest, self.target_device, self.state_digest, self.context_digest)):
            raise ValueError("AI proposal digests and target identity must be non-empty")
        if self.base_context_digest is None:
            object.__setattr__(self, "base_context_digest", self.context_digest)
        if not self.base_context_digest:
            raise ValueError("AI proposal base context digest must be non-empty")
        if self.action is PANAIProposalAction.USE_EXISTING:
            if not self.candidate_id or not self.proposed_value or not self.evidence_refs:
                raise ValueError("existing-target proposals require a candidate, value, and evidence")
        elif self.candidate_id is not None or self.proposed_value is not None:
            raise ValueError("abstentions cannot include a target candidate or value")

    def to_dict(self) -> dict:
        return {
            "decision_key": self.decision_key,
            "action": self.action.value,
            "candidate_id": self.candidate_id,
            "proposed_value": self.proposed_value,
            "target_scope": self.target_scope,
            "rationale": self.rationale,
            "evidence_refs": list(self.evidence_refs),
            "evidence": list(self.evidence),
            "provider": self.provider,
            "model": self.model,
            "prompt_version": self.prompt_version,
            "source_digest": self.source_digest,
            "target_digest": self.target_digest,
            "target_device": self.target_device,
            "state_digest": self.state_digest,
            "context_digest": self.context_digest,
            "base_context_digest": self.base_context_digest,
            "validation_status": self.validation_status,
            "validation_findings": list(self.validation_findings),
        }


@dataclass(frozen=True, slots=True)
class PANAIProposalSet:
    proposals: tuple[PANAIProposal, ...]

    def __post_init__(self) -> None:
        keys = [item.decision_key for item in self.proposals]
        if len(set(keys)) != len(keys):
            raise ValueError("AI proposal decision keys must be unique")

    def to_list(self) -> list[dict]:
        return [item.to_dict() for item in self.proposals]
