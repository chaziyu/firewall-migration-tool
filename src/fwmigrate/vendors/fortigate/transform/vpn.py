from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_network

from ..model.address import FGAddress, FGAddressGroup
from ..model.source import FGConfig
from ..model.vpn import FGIPsecPhase2, FGIPsecPolicyPhase2

from ..relationships.references import (
    ReferenceIndex,
    ReferenceKind,
    build_reference_index,
)


@dataclass(frozen=True, slots=True)
class NormalizedVPNPhase2:
    name: str
    vdom: str

    phase1name: str | None

    proposal: tuple[str, ...]
    pfs: str | None
    dhgrp: tuple[int, ...]

    keylifeseconds: int | None
    keylifekbs: int | None

    source_range: str | None
    destination_range: str | None
    source_range6: str | None
    destination_range6: str | None
    vpn_type: str = "route-based"


@dataclass(frozen=True, slots=True)
class VPNSelectorIssue:
    vdom: str
    phase2: str
    selector: str
    message: str
    vpn_type: str = "route-based"


@dataclass(slots=True)
class VPNTransformResult:
    phase2: list[
        NormalizedVPNPhase2
    ] = field(default_factory=list)

    issues: list[
        VPNSelectorIssue
    ] = field(default_factory=list)


def normalize_vpn_phase2(
    config: FGConfig,
    *,
    references: ReferenceIndex | None = None,
) -> VPNTransformResult:
    references = (
        references
        or build_reference_index(config)
    )

    result = VPNTransformResult()

    for phase2 in [*config.ipsec_phase2, *config.ipsec_policy_phase2]:
        local_issues: list[VPNSelectorIssue] = []
        vpn_type = "policy-based" if isinstance(phase2, FGIPsecPolicyPhase2) else "route-based"
        source_range = _selector_range(
            phase2,
            selector="source",
            references=references,
            issues=local_issues,
        )

        destination_range = (
            _selector_range(
                phase2,
                selector="destination",
                references=references,
                issues=local_issues,
            )
        )

        source_range6 = _selector_range(
            phase2, selector="source", references=references,
            issues=local_issues, ipv6=True,
        )
        destination_range6 = _selector_range(
            phase2, selector="destination", references=references,
            issues=local_issues, ipv6=True,
        )

        result.phase2.append(
            NormalizedVPNPhase2(
                name=phase2.name,
                vdom=phase2.vdom,
                phase1name=(
                    phase2.phase1name
                ),
                proposal=tuple(
                    phase2.proposal
                ),
                pfs=phase2.pfs,
                dhgrp=tuple(
                    phase2.dhgrp
                ),
                keylifeseconds=(
                    phase2.keylifeseconds
                ),
                keylifekbs=(
                    phase2.keylifekbs
                ),
                source_range=source_range,
                destination_range=(
                    destination_range
                ),
                source_range6=source_range6,
                destination_range6=destination_range6,
                vpn_type=vpn_type,
            )
        )
        result.issues.extend(
            VPNSelectorIssue(item.vdom, item.phase2, item.selector, item.message, vpn_type)
            for item in local_issues
        )

    return result


def _selector_range(
    phase2: FGIPsecPhase2,
    *,
    selector: str,
    references: ReferenceIndex,
    issues: list[VPNSelectorIssue],
    ipv6: bool = False,
) -> str | None:
    if selector == "source":
        addr_type = phase2.src_addr_type
        start = phase2.src_start_ip6 if ipv6 else phase2.src_start_ip
        end = phase2.src_end_ip6 if ipv6 else phase2.src_end_ip
        subnet = phase2.src_subnet6 if ipv6 else phase2.src_subnet
        name = phase2.src_name6 if ipv6 else phase2.src_name

    elif selector == "destination":
        addr_type = phase2.dst_addr_type
        start = phase2.dst_start_ip6 if ipv6 else phase2.dst_start_ip
        end = phase2.dst_end_ip6 if ipv6 else phase2.dst_end_ip
        subnet = phase2.dst_subnet6 if ipv6 else phase2.dst_subnet
        name = phase2.dst_name6 if ipv6 else phase2.dst_name

    else:
        raise ValueError(
            f"Unknown selector: {selector}"
        )

    addr_type = (addr_type or "").strip().lower()
    selector_types = {
        "subnet", "range", "ip", "name",
        "subnet6", "range6", "ip6", "name6",
    }
    family_types = {"subnet6", "range6", "ip6", "name6"} if ipv6 else {
        "subnet", "range", "ip", "name",
    }
    if addr_type in selector_types and addr_type not in family_types:
        return None

    if addr_type in family_types:
        prefix = "src" if selector == "source" else "dst"
        suffix = "6" if ipv6 else ""
        fields = {
            f"{prefix}_subnet{suffix}": {"subnet", "subnet6"},
            f"{prefix}_start_ip{suffix}": {"range", "range6", "ip", "ip6"},
            f"{prefix}_end_ip{suffix}": {"range", "range6"},
            f"{prefix}_name{suffix}": {"name", "name6"},
        }
        selected = {
            field_name for field_name, types in fields.items()
            if addr_type in types
        }
        inactive = [
            field_name for field_name in fields
            if field_name not in selected and getattr(phase2, field_name) is not None
        ]
        if inactive:
            issues.append(VPNSelectorIssue(
                vdom=phase2.vdom,
                phase2=phase2.name,
                selector=selector,
                message=(
                    f"Inactive selector field(s) {', '.join(inactive)} were "
                    f"ignored because {addr_type!r} is selected."
                ),
            ))

    # An explicit ip selector is one host, not an incomplete range.
    if addr_type == ("ip6" if ipv6 else "ip"):
        return f"{start}-{start}" if start else None

    # --------------------------------------------------------------
    # Explicit range
    # --------------------------------------------------------------

    if addr_type == ("range6" if ipv6 else "range"):
        if not start and not end:
            return None
        if not start or not end:
            issues.append(
                VPNSelectorIssue(
                    vdom=phase2.vdom,
                    phase2=phase2.name,
                    selector=selector,
                    message=(
                        "Selector has only one "
                        "range endpoint."
                    ),
                )
            )
            return None

        return (
            f"{start}-{end}"
        )

    if addr_type not in {"subnet", "name", "range", "ip", "subnet6", "name6", "range6", "ip6"} and (start or end):
        if not start or not end:
            issues.append(
                VPNSelectorIssue(
                    vdom=phase2.vdom,
                    phase2=phase2.name,
                    selector=selector,
                    message=(
                        "Selector has only one "
                        "range endpoint."
                    ),
                )
            )
            return None

        return f"{start}-{end}"

    # --------------------------------------------------------------
    # Subnet → first-last address
    # --------------------------------------------------------------

    subnet_type = "subnet6" if ipv6 else "subnet"
    if addr_type == subnet_type or (addr_type not in selector_types and subnet):
        if not subnet and addr_type == subnet_type:
            return None

        value = _subnet_to_range(
            subnet
        )

        if value is None:
            issues.append(
                VPNSelectorIssue(
                    vdom=phase2.vdom,
                    phase2=phase2.name,
                    selector=selector,
                    message=(
                        "Unable to convert subnet "
                        f"{subnet!r} to an IP range."
                    ),
                )
            )

        return value

    # --------------------------------------------------------------
    # Named address object
    # --------------------------------------------------------------

    if addr_type == ("name6" if ipv6 else "name"):
        if not name:
            return None

    if name:
        resolution = references.resolve_any(
            vdom=phase2.vdom,
            name=name,
            kinds=(
                (ReferenceKind.ADDRESS6, ReferenceKind.ADDRESS_GROUP6)
                if ipv6
                else (ReferenceKind.ADDRESS, ReferenceKind.ADDRESS_GROUP)
            ),
        )

        if resolution is not None and isinstance(resolution.target, FGAddressGroup):
            issues.append(VPNSelectorIssue(
                vdom=phase2.vdom,
                phase2=phase2.name,
                selector=selector,
                message=(
                    f"Address group {name!r} is a valid selector reference, "
                    "but the current single-range derived view cannot represent it deterministically."
                ),
            ))
            return None

        if (
            resolution is None
            or not isinstance(
                resolution.target,
                FGAddress,
            )
        ):
            issues.append(
                VPNSelectorIssue(
                    vdom=phase2.vdom,
                    phase2=phase2.name,
                    selector=selector,
                    message=(
                        "Selector address object "
                        f"{name!r} cannot be resolved "
                        "to one numeric address."
                    ),
                )
            )
            return None

        value = _address_to_range(
            resolution.target
        )

        if value is None:
            issues.append(
                VPNSelectorIssue(
                    vdom=phase2.vdom,
                    phase2=phase2.name,
                    selector=selector,
                    message=(
                        "Address object "
                        f"{name!r} is not convertible "
                        "to one numeric IP range."
                    ),
                )
            )

        return value

    # No explicit selector data.
    #
    # Do not inject a FortiOS default here.
    return None


def _address_to_range(
    address: FGAddress,
) -> str | None:
    if (
        address.start_ip
        and address.end_ip
    ):
        return (
            f"{address.start_ip}-"
            f"{address.end_ip}"
        )

    if address.subnet:
        return _subnet_to_range(
            address.subnet
        )

    if address.ip6:
        return _subnet_to_range(address.ip6)

    return None


def _subnet_to_range(
    value: str,
) -> str | None:
    raw = value.strip()

    if not raw:
        return None

    parts = raw.split()

    try:
        if len(parts) == 2:
            network = ip_network(
                f"{parts[0]}/{parts[1]}",
                strict=False,
            )

        elif len(parts) == 1:
            network = ip_network(
                parts[0],
                strict=False,
            )

        else:
            return None

    except ValueError:
        return None

    return (
        f"{network.network_address}-"
        f"{network.broadcast_address}"
    )
