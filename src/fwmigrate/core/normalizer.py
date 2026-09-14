from fwmigrate.ir.core import IRAuditEntry, IRConfig
from fwmigrate.ir.enums import MigrationConfidence, PolicyAction


class RuleNormalizer:
    """Apply mandatory, target-independent semantic corrections."""

    def __init__(self, ir: IRConfig):
        self.ir = ir

    def normalize_outbound_threat_source_anomalies(self) -> None:
        for pol in self.ir.policies:
            if (
                pol.requires_manual_review
                or pol.migration_status != "NORMALIZED"
                or not pol.safe_for_target_generation
            ):
                continue
            if pol.action == PolicyAction.DENY and len(pol.source) == 1 and len(pol.destination) >= 5:
                src_val = pol.source[0]
                if src_val not in ["all", "any"] and any(
                    "botnet" in a.lower()
                    or "emotet" in a.lower()
                    or "bad" in a.lower()
                    or "malicious" in a.lower()
                    for a in pol.destination
                ):
                    pol.source = ["any"]
                    if src_val not in pol.destination:
                        pol.destination.append(src_val)
                    self.ir.audit_entries.append(IRAuditEntry(
                        id=pol.name,
                        category="Policy Optimization",
                        message=(
                            f"Automatically fixed source field anomaly in outbound block rule "
                            f"'{pol.name}': Changed source from '{src_val}' to 'any' and ensured "
                            f"'{src_val}' is in the destination list."
                        ),
                        confidence=MigrationConfidence.FULL,
                    ))
