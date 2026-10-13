"""Non-executable deterministic FortiGate -> PAN-OS review contracts."""
from dataclasses import asdict, dataclass
import hashlib
import json


def design_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class PANDraftDecision:
    decision_key: str
    source_vdom: str
    source_kind: str
    source_name: str
    target_field: str
    proposed_value: str | None
    operation: str | None
    status: str
    target_scope: str | None
    dependencies: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    blocking_reasons: tuple[str, ...] = ()
    approved: bool = False

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PANMigrationDraft:
    context: dict
    decisions: tuple[PANDraftDecision, ...]
    configuration: tuple[dict, ...]
    findings: tuple[dict, ...] = ()
    decision_state_digest: str | None = None

    def to_dict(self):
        body = {"envelope_type": "pan_migration_draft", "schema_version": 1,
                "decision_state_digest": self.decision_state_digest,
                "context": self.context, "decisions": [item.to_dict() for item in self.decisions],
                "configuration": list(self.configuration), "findings": list(self.findings),
                "destination_verified": self.context["reference_role"] == "DESTINATION"
                    and bool(self.context["reference_digest"] and self.context["target_device"])}
        body["digest"] = design_digest(body)
        return body
