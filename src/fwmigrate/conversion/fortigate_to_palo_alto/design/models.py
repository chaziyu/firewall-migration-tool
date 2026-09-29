from __future__ import annotations

from dataclasses import dataclass
import heapq

from ..decisions import PANDecisionMode, PANDecisionReviewState, PANMigrationDecisionSet


@dataclass(frozen=True, slots=True)
class PANDecisionDependency:
    decision_key: str
    depends_on: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.decision_key, str) or not self.decision_key:
            raise ValueError("decision_key must be a non-empty string")
        if any(not isinstance(key, str) or not key for key in self.depends_on):
            raise ValueError("dependency keys must be non-empty strings")
        if self.decision_key in self.depends_on or len(set(self.depends_on)) != len(self.depends_on):
            raise ValueError("decision dependencies must be unique and cannot include themselves")


@dataclass(frozen=True, slots=True)
class PANDecisionGraph:
    dependencies: tuple[PANDecisionDependency, ...]

    def __post_init__(self) -> None:
        keys = {item.decision_key for item in self.dependencies}
        if len(keys) != len(self.dependencies):
            raise ValueError("decision graph keys must be unique")
        if any(set(item.depends_on) - keys for item in self.dependencies):
            raise ValueError("decision graph dependencies must reference existing decisions")
        self.topological_order()

    def topological_order(self) -> tuple[str, ...]:
        """Return stable dependency-first order and reject cyclic source topology."""
        dependents = {item.decision_key: [] for item in self.dependencies}
        remaining = {}
        for item in self.dependencies:
            remaining[item.decision_key] = len(item.depends_on)
            for dependency in item.depends_on:
                dependents[dependency].append(item.decision_key)
        ready = [key for key, count in remaining.items() if count == 0]
        heapq.heapify(ready)
        ordered = []
        while ready:
            key = heapq.heappop(ready)
            ordered.append(key)
            for dependent in dependents[key]:
                remaining[dependent] -= 1
                if remaining[dependent] == 0:
                    heapq.heappush(ready, dependent)
        if len(ordered) != len(remaining):
            raise ValueError("migration decision dependencies contain a cycle")
        return tuple(ordered)

    def ready_decision_keys(
        self,
        decisions: PANMigrationDecisionSet,
        *,
        conflicted: tuple[str, ...] = (),
    ) -> tuple[str, ...]:
        by_key = {item.key: item for item in decisions.decisions}
        blocked = set(conflicted)
        resolved = {
            item.key
            for item in decisions.decisions
            if item.mode is PANDecisionMode.AUTO
            or item.review_state is PANDecisionReviewState.CONFIRMED
        }
        output = []
        for key in self.topological_order():
            decision = by_key[key]
            if decision.mode is PANDecisionMode.UNSUPPORTED or key in blocked or key in resolved:
                continue
            dependencies = next(item.depends_on for item in self.dependencies if item.decision_key == key)
            if not (set(dependencies) & blocked) and set(dependencies) <= resolved:
                output.append(key)
            else:
                blocked.add(key)
        return tuple(output)

    def ready_proposed_decision_keys(self, proposed_design, *, conflicted: tuple[str, ...] = ()) -> tuple[str, ...]:
        """Return pending decisions unlocked by authoritative or valid proposed values."""
        decisions = proposed_design.authoritative_decisions
        by_key = {item.key: item for item in decisions.decisions}
        proposals = proposed_design.proposals_by_decision_key
        settled = set(proposals)
        blocked = set(conflicted)
        resolved = {
            item.key for item in decisions.decisions
            if item.mode is PANDecisionMode.AUTO
            or item.review_state is PANDecisionReviewState.CONFIRMED
        }
        resolved.update(
            key for key, item in proposals.items()
            if item.validation_status == "VALID" and item.action.value == "USE_EXISTING"
        )
        output = []
        for key in self.topological_order():
            decision = by_key[key]
            if (decision.mode is PANDecisionMode.UNSUPPORTED or key in blocked
                    or key in resolved or key in settled):
                continue
            dependencies = next(item.depends_on for item in self.dependencies if item.decision_key == key)
            if not (set(dependencies) & blocked) and set(dependencies) <= resolved:
                output.append(key)
            else:
                blocked.add(key)
        return tuple(output)

    def to_dict(self) -> dict:
        return {
            "dependencies": [
                {"decision_key": item.decision_key, "depends_on": list(item.depends_on)}
                for item in self.dependencies
            ],
            "topological_order": list(self.topological_order()),
        }


@dataclass(frozen=True, slots=True)
class PANMigrationDesignSession:
    source_digest: str | None
    target_digest: str | None
    target_device: str | None
    decisions: PANMigrationDecisionSet
    dependency_graph: PANDecisionGraph
    deterministic_audit: tuple[dict, ...] = ()
    resolved: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()
    conflicted: tuple[str, ...] = ()
    unsupported: tuple[str, ...] = ()
    iterations: int = 0
    stable: bool = True

    def __post_init__(self) -> None:
        for name in ("source_digest", "target_digest", "target_device"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError(f"{name} must be a non-empty string or null")
        categories = (self.resolved, self.unresolved, self.conflicted, self.unsupported)
        if any(not isinstance(key, str) or not key for group in categories for key in group):
            raise ValueError("design decision categories must contain non-empty keys")
        if any(len(set(group)) != len(group) for group in categories):
            raise ValueError("design decision categories cannot contain duplicate keys")
        category_keys = [set(group) for group in categories]
        covered = set().union(*category_keys)
        if covered != {item.key for item in self.decisions.decisions}:
            raise ValueError("design decision categories must cover every decision exactly once")
        if sum(map(len, category_keys)) != len(covered):
            raise ValueError("design decision categories must be disjoint")
        if not isinstance(self.iterations, int) or self.iterations < 0:
            raise ValueError("iterations must be a non-negative integer")

    def to_dict(self) -> dict:
        return {
            "source_digest": self.source_digest,
            "target_digest": self.target_digest,
            "target_device": self.target_device,
            "decisions": self.decisions.to_dict(),
            "dependency_graph": self.dependency_graph.to_dict(),
            "ready_decision_keys": list(self.dependency_graph.ready_decision_keys(
                self.decisions, conflicted=self.conflicted
            )),
            "deterministic_audit": list(self.deterministic_audit),
            "resolved": list(self.resolved),
            "unresolved": list(self.unresolved),
            "conflicted": list(self.conflicted),
            "unsupported": list(self.unsupported),
            "iterations": self.iterations,
            "stable": self.stable,
        }
