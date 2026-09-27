"""Validated advisory proposals; these types never represent migration state."""

from dataclasses import asdict, dataclass, field
from enum import Enum


class PANAIAssistKind(str, Enum):
    MAPPING_RECOMMENDATION = "MAPPING_RECOMMENDATION"
    SELECTION_SUGGESTION = "SELECTION_SUGGESTION"
    ARCHITECTURE_QUESTION = "ARCHITECTURE_QUESTION"
    CANDIDATE_COMPARISON = "CANDIDATE_COMPARISON"


@dataclass(frozen=True, slots=True)
class PANAIAssignment:
    decision_key: str
    value: str


@dataclass(frozen=True, slots=True)
class PANAIChoice:
    label: str
    assignments: tuple[PANAIAssignment, ...] = ()


@dataclass(frozen=True, slots=True)
class PANAIAssistProposal:
    proposal_id: str
    context_digest: str
    state_digest: str
    kind: PANAIAssistKind
    title: str
    summary: str
    decision_keys: tuple[str, ...]
    affected_count: int
    provider: str
    model: str
    prompt_version: str
    question: str | None = None
    choices: tuple[PANAIChoice, ...] = ()
    suggested_value: str | None = None
    evidence: tuple[str, ...] = ()
    rationale: tuple[str, ...] = ()
    missing_information: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    comparisons: tuple[dict, ...] = field(default_factory=tuple)

    def to_dict(self):
        return asdict(self) | {"kind": self.kind.value}


@dataclass(frozen=True, slots=True)
class PANAIReviewDraft:
    proposal_id: str
    state_digest: str
    revision: int
    cursor: int
    total_groups: int
    proposals: tuple[PANAIAssistProposal, ...] = ()
    blockers: tuple[dict, ...] = ()
    dependencies: tuple[dict, ...] = ()

    def to_dict(self):
        return {"draft_id": self.proposal_id, "revision": self.revision, "cursor": self.cursor,
                "total_groups": self.total_groups, "complete": self.cursor == self.total_groups,
                "proposals": [item.to_dict() for item in self.proposals],
                "blockers": list(self.blockers), "dependencies": list(self.dependencies),
                "prepared_decisions": len({assignment.decision_key for proposal in self.proposals
                    for choice in proposal.choices for assignment in choice.assignments}),
                "blocked_decisions": len(self.blockers)}


def proposal_from_output(*, output, kind, proposal_id, context_digest, provider, model, prompt_version,
                         affected_count, state_digest="", comparisons=()):
    choices = tuple(PANAIChoice(item["label"], tuple(PANAIAssignment(**assignment)
                                                     for assignment in item.get("assignments", ())))
                    for item in output.get("choices", ()))
    return PANAIAssistProposal(
        proposal_id=proposal_id, context_digest=context_digest, state_digest=state_digest, kind=kind,
        title=output["title"], summary=output["summary"], question=output.get("question"),
        decision_keys=tuple(output.get("decision_keys", ())), choices=choices,
        affected_count=affected_count, provider=provider, model=model, prompt_version=prompt_version,
        rationale=tuple(output.get("rationale", ())),
        evidence=tuple(output.get("evidence", ())),
        suggested_value=output.get("suggested_value"),
        missing_information=tuple(output.get("missing_information", ())),
        limitations=tuple(output.get("limitations", ())), comparisons=tuple(comparisons),
    )
