import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Set, Tuple

from fwmigrate.capabilities.schema import CapabilityStatus
from fwmigrate.generators.service_capabilities import (
    ServiceCapabilityResult,
    service_capabilities,
)
from fwmigrate.ir.service import IRService, IRServiceGroup


ServiceKey = Tuple[str, str]


@dataclass(frozen=True)
class TargetServicePreparation:
    """Target-safe service decisions and lowered service-group members."""

    service_results: dict[ServiceKey, ServiceCapabilityResult]
    group_results: dict[ServiceKey, ServiceCapabilityResult]
    group_members: dict[ServiceKey, tuple[str, ...]]

    @staticmethod
    def key(item: IRService | IRServiceGroup) -> ServiceKey:
        return (str(item.source_context or "root"), item.name)

    def service_result(self, service: IRService) -> ServiceCapabilityResult:
        return self.service_results[self.key(service)]

    def group_result(self, group: IRServiceGroup) -> ServiceCapabilityResult:
        return self.group_results[self.key(group)]

    def members_for(self, group: IRServiceGroup) -> tuple[str, ...]:
        return self.group_members[self.key(group)]


def prepare_target_services(
    services: Iterable[IRService],
    groups: Iterable[IRServiceGroup],
    target_vendor: str,
) -> TargetServicePreparation:
    """Evaluate service support and flatten nested groups only when safe."""
    services = list(services)
    groups = list(groups)
    capabilities = service_capabilities(target_vendor)
    service_by_key = {TargetServicePreparation.key(item): item for item in services}
    group_by_key = {TargetServicePreparation.key(item): item for item in groups}
    service_results = {
        key: capabilities.evaluate_service(item)
        for key, item in service_by_key.items()
    }
    groups_by_context: dict[str, list[IRServiceGroup]] = {}
    for group in groups:
        groups_by_context.setdefault(str(group.source_context or "root"), []).append(group)
    base_group_results = {
        key: capabilities.evaluate_group(
            item,
            groups_by_context.get(key[0], []),
        )
        for key, item in group_by_key.items()
    }
    group_results: dict[ServiceKey, ServiceCapabilityResult] = {}

    def review_group(
        key: ServiceKey,
        trail: tuple[ServiceKey, ...] = (),
    ) -> ServiceCapabilityResult:
        if key in trail:
            return ServiceCapabilityResult(
                CapabilityStatus.MANUAL_REVIEW,
                ("cyclic service-group reference",),
            )
        if key in group_results:
            return group_results[key]

        group = group_by_key[key]
        base = base_group_results[key]
        reasons = [] if base.requires_lowering else list(base.reasons)
        next_trail = (*trail, key)
        for member in group.members:
            member_key = (key[0], member)
            if member_key in service_results:
                result = service_results[member_key]
                if not result.supported:
                    reasons.extend(result.reasons)
            elif member_key in group_by_key:
                result = review_group(member_key, next_trail)
                if not result.supported:
                    reasons.extend(result.reasons)
            else:
                reasons.append(
                    f"unresolved service-group member '{member}'"
                )

        if reasons:
            result = ServiceCapabilityResult(
                CapabilityStatus.MANUAL_REVIEW,
                tuple(dict.fromkeys(reasons)),
            )
        else:
            result = base
        group_results[key] = result
        return result

    group_members: dict[ServiceKey, tuple[str, ...]] = {}
    for key, group in group_by_key.items():
        result = review_group(key)
        if not result.supported and not result.requires_lowering:
            continue
        if result.requires_lowering:
            flattened: list[str] = []

            def flatten(member_key: ServiceKey, trail: tuple[ServiceKey, ...]) -> None:
                if member_key in trail:
                    raise ValueError("cyclic service-group reference")
                child = group_by_key.get(member_key)
                if child is None:
                    service = service_by_key.get(member_key)
                    if service is None:
                        raise ValueError(
                            f"service-group member '{member_key[1]}' cannot be lowered safely"
                        )
                    if not service_results[member_key].supported:
                        raise ValueError(
                            f"service member '{member_key[1]}' requires target review"
                        )
                    flattened.append(member_key[1])
                    return
                for nested_member in child.members:
                    nested_key = (member_key[0], nested_member)
                    flatten(nested_key, (*trail, member_key))

            try:
                for member in group.members:
                    flatten((key[0], member), (key,))
            except ValueError as exc:
                result = ServiceCapabilityResult(
                    CapabilityStatus.MANUAL_REVIEW,
                    tuple(dict.fromkeys((*result.reasons, str(exc)))),
                )
                group_results[key] = result
                continue
            group_members[key] = tuple(dict.fromkeys(flattened))
            group_results[key] = ServiceCapabilityResult(CapabilityStatus.SUPPORTED)
        else:
            group_members[key] = tuple(group.members)

    return TargetServicePreparation(service_results, group_results, group_members)


def allocate_target_helper_name(
    preferred_name: str,
    existing_objects: dict[str, str],
    expected_value: str,
) -> Tuple[str, bool]:
    """
    Allocates a collision-safe name for a target generator helper object.

    Args:
        preferred_name: The ideal name for the object (e.g., "__fwmigrate_any_ipv4")
        existing_objects: A dictionary mapping existing object names to their values.
                          For example, if mapping addresses, the value would be the IP/subnet.
        expected_value: The value the helper object must have.

    Returns:
        A tuple of (name_to_use, was_reused_from_existing).
        - If preferred_name not in existing: return (preferred_name, False)
        - If preferred_name exists with matching value: return (preferred_name, True)
        - If collision, returns a deterministic fallback name and False.
    """
    if preferred_name not in existing_objects:
        return preferred_name, False
        
    if existing_objects[preferred_name] == expected_value:
        return preferred_name, True
        
    # Collision occurred (same name, different value)
    # Generate fallbacks: name_2, name_3, etc.
    counter = 2
    while True:
        fallback_name = f"{preferred_name}_{counter}"
        if fallback_name not in existing_objects:
            return fallback_name, False
        if existing_objects[fallback_name] == expected_value:
            return fallback_name, True
        counter += 1


def is_generation_safe_object(obj: Any) -> bool:
    """Verify an IR object is normalized, free of manual review flags, and parse errors."""
    if obj is None:
        return False
    if getattr(obj, "migration_status", "NORMALIZED") != "NORMALIZED":
        return False
    if getattr(obj, "requires_manual_review", False):
        return False
    if getattr(obj, "review_reasons", []):
        return False
    if getattr(obj, "parse_error", None) is not None:
        return False
    if getattr(obj, "parse_errors", []):
        return False
    model_safe = getattr(obj, "safe_for_target_generation", None)
    if model_safe is not None:
        if callable(model_safe):
            model_safe = model_safe()
        if not model_safe:
            return False
    return True


def ir_generation_blocked(ir: Any) -> bool:
    """Check if IR-level generation is blocked."""
    if ir is None:
        return True
    return not getattr(ir, "generation_safe", True)


def hcl_string(value: str) -> str:
    """Format a string safely as an HCL double-quoted literal."""
    return json.dumps(str(value))


def hcl_list(values: Iterable[str]) -> str:
    """Format an iterable of strings as a valid HCL list expression."""
    return json.dumps([str(v) for v in values])


def terraform_resource_label(name: str, used_labels: Optional[Set[str]] = None) -> str:
    """
    Produce a valid, deterministic Terraform resource label from an arbitrary object name.

    Replaces non-alphanumeric characters with underscores, ensures valid leading character,
    and resolves collisions if used_labels set is provided.
    """
    sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    if not sanitized or not (sanitized[0].isalpha() or sanitized[0] == "_"):
        sanitized = f"r_{sanitized}"

    if used_labels is None:
        return sanitized

    if sanitized not in used_labels:
        used_labels.add(sanitized)
        return sanitized

    counter = 2
    while True:
        candidate = f"{sanitized}_{counter}"
        if candidate not in used_labels:
            used_labels.add(candidate)
            return candidate
        counter += 1
