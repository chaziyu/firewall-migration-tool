"""Advisory design state kept separate from authoritative migration decisions."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from ..ai.models import PANAIProposal, PANAIProposalAction
from ..decisions import PANDecisionMode, PANDecisionReviewState, PANMigrationDecisionSet


@dataclass(frozen=True, slots=True)
class PANProposedDesign:
    source_digest: str
    target_digest: str
    target_device: str
    authoritative_decisions: PANMigrationDecisionSet
    proposals: tuple[PANAIProposal, ...] = ()

    def __post_init__(self) -> None:
        if not all((self.source_digest, self.target_digest, self.target_device)):
            raise ValueError("proposed design requires source and target identity")
        keys = [item.decision_key for item in self.proposals]
        if len(set(keys)) != len(keys):
            raise ValueError("proposed design decisions must be unique")

    @property
    def proposals_by_decision_key(self) -> dict[str, PANAIProposal]:
        return {item.decision_key: item for item in self.proposals}

    def authoritative_value(self, key: str) -> str | None:
        for decision in self.authoritative_decisions.decisions:
            if decision.key == key and decision.mode is not PANDecisionMode.UNSUPPORTED and decision.value:
                if decision.mode is PANDecisionMode.AUTO or decision.review_state is PANDecisionReviewState.CONFIRMED:
                    return decision.value
        return None

    def provisional_value(self, key: str) -> str | None:
        value = self.authoritative_value(key)
        if value is not None:
            return value
        proposal = self.proposals_by_decision_key.get(key)
        if (proposal and proposal.validation_status == "VALID"
                and proposal.action is PANAIProposalAction.USE_EXISTING):
            return proposal.proposed_value
        return None

    @property
    def digest(self) -> str:
        value = {
            "source_digest": self.source_digest,
            "target_digest": self.target_digest,
            "target_device": self.target_device,
            "decisions": [item.to_dict() for item in sorted(
                self.authoritative_decisions.decisions, key=lambda item: item.key
            )],
            "proposals": [item.to_dict() for item in sorted(
                self.proposals, key=lambda item: item.decision_key
            )],
        }
        content = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def with_state(self, decisions=None, proposals=None) -> "PANProposedDesign":
        return PANProposedDesign(
            source_digest=self.source_digest,
            target_digest=self.target_digest,
            target_device=self.target_device,
            authoritative_decisions=decisions or self.authoritative_decisions,
            proposals=self.proposals if proposals is None else tuple(proposals),
        )


@dataclass(frozen=True, slots=True)
class PANProposedDesignSession:
    session_id: str
    created_at: float
    design: PANProposedDesign
    stable: bool = True
    iterations: int = 0
    audit: tuple[dict, ...] = ()
    failure_category: str | None = None
    failures: tuple[dict, ...] = ()
    ai_eligible_decision_keys: tuple[str, ...] = ()
    dependency_graph: object | None = None

    def __post_init__(self) -> None:
        if not self.session_id or not isinstance(self.created_at, (int, float)) or self.created_at <= 0:
            raise ValueError("proposed design session requires an id and creation time")
        if not isinstance(self.iterations, int) or self.iterations < 0:
            raise ValueError("iterations must be a non-negative integer")

    def summary(self, dependency_graph) -> dict:
        dependency_graph = dependency_graph or self.dependency_graph
        decisions = {item.key: item for item in self.design.authoritative_decisions.decisions}
        proposals = self.design.proposals_by_decision_key
        counts = {
            "deterministic_confirmed": 0,
            "engineer_confirmed": 0,
            "ai_proposed": 0,
            "abstained": 0,
            "conflicted": 0,
            "rejected": 0,
            "unsupported": 0,
            "blocked": 0,
            "ready_unresolved": 0,
            "blocked_by_dependency": 0,
            "not_ai_eligible": 0,
        }
        ready = (set(dependency_graph.ready_proposed_decision_keys(self.design))
                 if dependency_graph is not None else set(self.ai_eligible_decision_keys))
        ai_eligible = set(self.ai_eligible_decision_keys)
        groups = {}
        for key, decision in decisions.items():
            proposal = proposals.get(key)
            if decision.mode is PANDecisionMode.UNSUPPORTED:
                status = "unsupported"
            elif proposal and proposal.validation_status == "CONFLICT":
                status = "conflicted"
            elif proposal and proposal.validation_status == "REJECTED":
                status = "rejected"
            elif proposal and proposal.action is PANAIProposalAction.NO_SAFE_PROPOSAL:
                status = "abstained"
            elif proposal and proposal.validation_status == "VALID":
                status = "ai_proposed"
            elif decision.mode is PANDecisionMode.AUTO or decision.review_state is PANDecisionReviewState.CONFIRMED:
                status = "engineer_confirmed" if decision.evidence_source == "ENGINEER" else "deterministic_confirmed"
            else:
                status = ("blocked_by_dependency" if key not in ready else
                          "ready_unresolved" if key in ai_eligible else "not_ai_eligible")
                counts["blocked"] += 1
            counts[status] += 1
            family = decision.target_field
            for group_key, group_name in (("family", family), ("source_vdom", decision.source_vdom)):
                group = groups.setdefault(group_key, {}).setdefault(group_name, {name: 0 for name in counts})
                group[status] += 1
                if status in {"ready_unresolved", "blocked_by_dependency", "not_ai_eligible"}:
                    group["blocked"] += 1
        counts["stable"] = self.stable
        counts["iterations"] = self.iterations
        counts["failure_count"] = len(self.failures)
        counts["proposed_design_digest"] = self.design.digest
        counts["groups"] = groups
        return counts

    def to_dict(self, dependency_graph) -> dict:
        return {
            "design_session_id": self.session_id,
            "created_at": self.created_at,
            "source_digest": self.design.source_digest,
            "target_digest": self.design.target_digest,
            "target_device": self.design.target_device,
            "proposed_design_digest": self.design.digest,
            "proposals": [item.to_dict() for item in self.design.proposals],
            "summary": self.summary(dependency_graph),
            "stable": self.stable,
            "iterations": self.iterations,
            "failure_category": self.failure_category,
            "failures": list(self.failures),
            "audit": list(self.audit),
        }
