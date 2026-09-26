"""Validated advisory proposals; these types never represent migration state."""

from dataclasses import asdict, dataclass, field
from enum import Enum


class PANAIAssistKind(str, Enum):
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
    rationale: tuple[str, ...] = ()
    missing_information: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    comparisons: tuple[dict, ...] = field(default_factory=tuple)

    def to_dict(self):
        return asdict(self) | {"kind": self.kind.value}


def proposal_from_output(*, output, kind, proposal_id, context_digest, provider, model, prompt_version,
                         affected_count, comparisons=()):
    choices = tuple(PANAIChoice(item["label"], tuple(PANAIAssignment(**assignment)
                                                     for assignment in item.get("assignments", ())))
                    for item in output.get("choices", ()))
    return PANAIAssistProposal(
        proposal_id=proposal_id, context_digest=context_digest, kind=kind,
        title=output["title"], summary=output["summary"], question=output.get("question"),
        decision_keys=tuple(output.get("decision_keys", ())), choices=choices,
        affected_count=affected_count, provider=provider, model=model, prompt_version=prompt_version,
        rationale=tuple(output.get("rationale", ())),
        missing_information=tuple(output.get("missing_information", ())),
        limitations=tuple(output.get("limitations", ())), comparisons=tuple(comparisons),
    )
