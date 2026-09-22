from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_network

from ..model.address import FGAddress
from ..model.source import FGConfig
from ..model.vpn import FGIPsecPhase2

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


@dataclass(frozen=True, slots=True)
class VPNSelectorIssue:
    vdom: str
    phase2: str
    selector: str
    message: str


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

    for phase2 in config.ipsec_phase2:
        source_range = _selector_range(
            phase2,
            selector="source",
            references=references,
            issues=result.issues,
        )

        destination_range = (
            _selector_range(
                phase2,
                selector="destination",
                references=references,
                issues=result.issues,
            )
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
            )
        )

    return result


def _selector_range(
    phase2: FGIPsecPhase2,
    *,
    selector: str,
    references: ReferenceIndex,
    issues: list[VPNSelectorIssue],
) -> str | None:
    if selector == "source":
        addr_type = phase2.src_addr_type
        start = phase2.src_start_ip
        end = phase2.src_end_ip
        subnet = phase2.src_subnet
        name = phase2.src_name

    elif selector == "destination":
        addr_type = phase2.dst_addr_type
        start = phase2.dst_start_ip
        end = phase2.dst_end_ip
        subnet = phase2.dst_subnet
        name = phase2.dst_name

    else:
        raise ValueError(
            f"Unknown selector: {selector}"
        )

    # An explicit ip selector is one host, not an incomplete range.
    if addr_type == "ip":
        return f"{start}-{start}" if start else None

    # --------------------------------------------------------------
    # Explicit range
    # --------------------------------------------------------------

    if addr_type == "range" and (start or end):
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

    if addr_type not in {"subnet", "name", "range"} and (start or end):
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

    if subnet:
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

    if name:
        resolution = references.resolve_any(
            vdom=phase2.vdom,
            name=name,
            kinds=(
                ReferenceKind.ADDRESS,
            ),
        )

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
