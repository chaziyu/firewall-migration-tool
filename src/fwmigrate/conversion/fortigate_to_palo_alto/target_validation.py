"""Report-only validation of confirmed FortiGate mappings against PAN-OS evidence."""

from dataclasses import dataclass

from .decisions import PANDecisionReviewState, PANMigrationDecisionSet
from .target_suggestions import _addresses, _compatible, _device
from ...vendors.palo_alto.source_model import pan_scope_identity


@dataclass(frozen=True, slots=True)
class PANTargetFinding:
    decision_key: str
    code: str
    severity: str
    message: str
    target_object: str | None = None
    evidence: object = None

    def to_dict(self) -> dict:
        return {
            "decision_key": self.decision_key,
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "target_object": self.target_object,
            "evidence": self.evidence,
        }


def _records(target, device, name=None):
    values = (*getattr(target.config, "interfaces", ()), *getattr(target.config, "interface_units", ()))
    return [item for item in values if item.name and _device(item) == device and (name is None or item.name == name)]


def _topology(target, item):
    identity = pan_scope_identity(item.scope) if item.scope else None
    return [entry for entry in getattr(target.derived, "interface_topology", ())
            if entry.interface == item.name and entry.scope == identity]


def _finding(decision, code, severity, message, target_object=None, evidence=None):
    return PANTargetFinding(decision.key, code, severity, message, target_object, evidence)


def validate_against_target(source, decisions: PANMigrationDecisionSet, target, device: str | None):
    """Return target conflicts without changing decisions or planner options."""
    if target is None or not device:
        return ()
    findings = []
    source_interfaces = {(item.vdom or "root", item.name): item for item in getattr(source, "interfaces", ()) if item.name}
    mapped = {}
    confirmed_names = {(item.source_vdom, item.source_name): item.value for item in decisions.decisions
                       if item.source_kind == "interface" and item.target_field == "target_interface"
                       and item.review_state is PANDecisionReviewState.CONFIRMED and item.value}
    for decision in decisions.decisions:
        if decision.review_state is not PANDecisionReviewState.CONFIRMED or not decision.value:
            continue
        if decision.source_kind == "interface" and decision.target_field == "target_interface":
            source_item = source_interfaces.get((decision.source_vdom, decision.source_name))
            records = _records(target, device, decision.value)
            scopes = {pan_scope_identity(item.scope) for item in records if item.scope}
            if not records:
                findings.append(_finding(decision, "TARGET_INTERFACE_NOT_FOUND", "error",
                                         f"Confirmed target interface {decision.value!r} was not found on device {device!r}.", decision.value))
                continue
            if len(records) != 1 or len(scopes) != 1:
                findings.append(_finding(decision, "TARGET_INTERFACE_AMBIGUOUS", "error",
                                         f"Confirmed target interface {decision.value!r} is ambiguous in the selected target scope.", decision.value,
                                         sorted(scopes)))
                continue
            target_item = records[0]
            mapped[(decision.source_vdom, decision.source_name)] = target_item
            if source_item is not None and not _compatible(source_item, target_item):
                findings.append(_finding(decision, "TARGET_INTERFACE_FAMILY_MISMATCH", "error",
                                         f"Target interface {decision.value!r} is not compatible with FortiGate interface {decision.source_name!r}.",
                                         decision.value, getattr(target_item, "interface_family", None)))
            source_addresses = _addresses(getattr(source_item, "ip", None)) if source_item else set()
            target_addresses = _addresses(getattr(target_item, "ipv4_addresses", None))
            if source_addresses and target_addresses and source_addresses != target_addresses:
                findings.append(_finding(decision, "TARGET_ADDRESS_DIFFERS", "warning",
                                         f"Target interface {decision.value!r} has different explicit addresses; renumbering may be intentional.",
                                         decision.value, sorted(target_addresses)))
            source_vlan = getattr(source_item, "vlanid", None) if source_item else None
            target_vlan = getattr(target_item, "tag", None)
            if source_vlan is not None and target_vlan is not None and str(source_vlan) != str(target_vlan):
                findings.append(_finding(decision, "TARGET_VLAN_TAG_MISMATCH", "error",
                                         f"Target VLAN tag {target_vlan!r} differs from source VLAN tag {source_vlan!r}.",
                                         decision.value, target_vlan))
            source_parent = getattr(source_item, "interface", None) if source_item else None
            target_parent = getattr(target_item, "parent", None)
            expected_parent = confirmed_names.get((decision.source_vdom, source_parent)) if source_parent else None
            if expected_parent and target_parent != expected_parent:
                findings.append(_finding(decision, "TARGET_PARENT_MISMATCH", "error",
                                         f"Target parent {target_parent!r} differs from confirmed parent mapping {expected_parent!r}.",
                                         decision.value, target_parent))
    for decision in decisions.decisions:
        if decision.review_state is not PANDecisionReviewState.CONFIRMED or not decision.value:
            continue
        if decision.source_kind == "interface" and decision.target_field == "target_zone":
            target_item = mapped.get((decision.source_vdom, decision.source_name))
            if target_item is None:
                continue
            topologies = _topology(target, target_item)
            zones = {zone for topology in topologies for zone in topology.zones}
            if len(zones) > 1:
                findings.append(_finding(decision, "TARGET_SCOPE_AMBIGUOUS", "error",
                                         f"Target interface {target_item.name!r} has multiple explicit zone assignments.", target_item.name, sorted(zones)))
            elif zones and decision.value not in zones:
                findings.append(_finding(decision, "TARGET_ZONE_CONFLICT", "error",
                                         f"Confirmed target zone {decision.value!r} conflicts with explicit target assignment {next(iter(zones))!r}.",
                                         target_item.name, sorted(zones)))
        elif decision.source_kind == "vdom" and decision.target_field in {"vsys", "virtual_router"}:
            field = "imported_vsys" if decision.target_field == "vsys" else "virtual_routers"
            values = {value for item in mapped.values() for topology in _topology(target, item) for value in getattr(topology, field)}
            if not values and decision.target_field == "vsys":
                scopes = [scope for scope in getattr(target.config, "scopes", ())
                          if scope.name == decision.value and (scope.device_serial or scope.device_name) == device]
                if not scopes:
                    findings.append(_finding(decision, "TARGET_VSYS_CONFLICT", "error",
                                             f"Confirmed target VSYS {decision.value!r} was not found on device {device!r}.", decision.value))
                elif len({pan_scope_identity(scope) for scope in scopes}) > 1:
                    findings.append(_finding(decision, "TARGET_SCOPE_AMBIGUOUS", "error",
                                             f"Confirmed target VSYS {decision.value!r} has ambiguous scope.", decision.value))
                continue
            if not values and decision.target_field == "virtual_router":
                routers = [router for router in getattr(target.config, "virtual_routers", ())
                           if router.name == decision.value and _device(router) == device]
                if not routers:
                    findings.append(_finding(decision, "TARGET_VIRTUAL_ROUTER_CONFLICT", "error",
                                             f"Confirmed target virtual router {decision.value!r} was not found on device {device!r}.", decision.value))
                elif len({pan_scope_identity(router.scope) for router in routers if router.scope}) > 1:
                    findings.append(_finding(decision, "TARGET_SCOPE_AMBIGUOUS", "error",
                                             f"Confirmed target virtual router {decision.value!r} has ambiguous scope.", decision.value))
                continue
            if len(values) > 1:
                findings.append(_finding(decision, "TARGET_SCOPE_AMBIGUOUS", "error",
                                         f"Confirmed target {decision.target_field} has multiple explicit assignments.", decision.value, sorted(values)))
            elif values and decision.value not in values:
                code = "TARGET_VSYS_CONFLICT" if decision.target_field == "vsys" else "TARGET_VIRTUAL_ROUTER_CONFLICT"
                findings.append(_finding(decision, code, "error",
                                         f"Confirmed target {decision.target_field} {decision.value!r} conflicts with explicit target assignment {next(iter(values))!r}.",
                                         decision.value, sorted(values)))
    return tuple(findings)


__all__ = ["PANTargetFinding", "validate_against_target"]
