from __future__ import annotations

from dataclasses import dataclass

from ..model.interface import FGInterface
from ..model.source import FGConfig

from .references import (
    ReferenceIndex,
    ReferenceKind,
    build_reference_index,
)


@dataclass(frozen=True, slots=True)
class InterfaceTopologyEntry:
    vdom: str
    name: str

    kind: str

    parent: str | None

    # Object → parent → parent's parent.
    path: tuple[str, ...]

    # First aggregate encountered in the ancestry.
    aggregate: str | None

    # Final physical/terminal interfaces.
    physical_interfaces: tuple[str, ...]

    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VPNTopologyEntry:
    vdom: str
    name: str

    attached_interface: str | None

    # VPN → attached interface → parent...
    path: tuple[str, ...]

    aggregate: str | None

    physical_interfaces: tuple[str, ...]

    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class InterfaceTopology:
    interfaces: tuple[
        InterfaceTopologyEntry,
        ...
    ]

    vpns: tuple[
        VPNTopologyEntry,
        ...
    ]


def build_interface_topology(
    config: FGConfig,
    *,
    references: ReferenceIndex | None = None,
) -> InterfaceTopology:
    references = (
        references
        or build_reference_index(config)
    )

    aggregate_owners: dict[tuple[str, str], list[str]] = {}
    for aggregate in config.interfaces:
        if not _is_aggregate(aggregate):
            continue
        for member_name in _deduplicate(aggregate.members):
            owners = aggregate_owners.setdefault(
                (aggregate.vdom, member_name),
                [],
            )
            if aggregate.name not in owners:
                owners.append(aggregate.name)

    interfaces = tuple(
        _resolve_interface(
            interface,
            references,
            aggregate_owners=aggregate_owners.get(
                (interface.vdom, interface.name),
                (),
            ),
        )
        for interface in config.interfaces
    )

    by_key = {
        (
            item.vdom,
            item.name,
        ): item
        for item in interfaces
    }

    vpns: list[VPNTopologyEntry] = []

    for vpn in config.ipsec_phase1:
        issues: list[str] = []

        if not vpn.interface:
            vpns.append(
                VPNTopologyEntry(
                    vdom=vpn.vdom,
                    name=vpn.name,
                    attached_interface=None,
                    path=(vpn.name,),
                    aggregate=None,
                    physical_interfaces=(),
                    issues=(
                        "VPN has no explicit interface.",
                    ),
                )
            )
            continue

        topology = by_key.get(
            (
                vpn.vdom,
                vpn.interface,
            )
        )

        if topology is None:
            issues.append(
                "Attached interface "
                f"{vpn.interface!r} was not found."
            )

            vpns.append(
                VPNTopologyEntry(
                    vdom=vpn.vdom,
                    name=vpn.name,
                    attached_interface=vpn.interface,
                    path=(
                        vpn.name,
                        vpn.interface,
                    ),
                    aggregate=None,
                    physical_interfaces=(),
                    issues=tuple(issues),
                )
            )
            continue

        vpns.append(
            VPNTopologyEntry(
                vdom=vpn.vdom,
                name=vpn.name,
                attached_interface=vpn.interface,
                path=(
                    vpn.name,
                    *topology.path,
                ),
                aggregate=topology.aggregate,
                physical_interfaces=(
                    topology.physical_interfaces
                ),
                issues=topology.issues,
            )
        )

    return InterfaceTopology(
        interfaces=interfaces,
        vpns=tuple(vpns),
    )


def _resolve_interface(
    interface: FGInterface,
    references: ReferenceIndex,
    *,
    aggregate_owners: tuple[str, ...] | list[str] = (),
) -> InterfaceTopologyEntry:
    path: list[str] = [
        interface.name
    ]

    issues: list[str] = []
    aggregate_owners = tuple(aggregate_owners)

    aggregate: str | None = (
        interface.name
        if _is_aggregate(interface)
        else None
    )

    current = interface

    seen = {
        interface.name
    }

    while current.interface:
        parent_name = current.interface

        if parent_name in seen:
            issues.append(
                "Interface parent cycle detected at "
                f"{parent_name!r}."
            )
            break

        seen.add(parent_name)
        path.append(parent_name)

        parent = references.get(
            ReferenceKind.INTERFACE,
            vdom=interface.vdom,
            name=parent_name,
        )

        if parent is None:
            issues.append(
                "Parent interface "
                f"{parent_name!r} was not found."
            )
            break

        if (
            aggregate is None
            and _is_aggregate(parent)
        ):
            aggregate = parent.name

        current = parent

    if len(aggregate_owners) > 1:
        issues.append(
            "Interface belongs to multiple aggregates: "
            f"{', '.join(repr(name) for name in aggregate_owners)}."
        )

    if aggregate is None and len(aggregate_owners) == 1:
        aggregate = aggregate_owners[0]
    elif (
        aggregate is not None
        and aggregate_owners
        and aggregate not in aggregate_owners
    ):
        issues.append(
            "Reverse aggregate membership conflicts with parent-derived "
            f"aggregate {aggregate!r}: "
            f"{', '.join(repr(name) for name in aggregate_owners)}."
        )

    physical_interfaces, physical_issues = (
        _resolve_physical_interfaces(
            interface,
            references,
            seen=set(),
        )
    )

    issues.extend(
        physical_issues
    )

    return InterfaceTopologyEntry(
        vdom=interface.vdom,
        name=interface.name,
        kind=_interface_kind(interface),
        parent=interface.interface,
        path=tuple(path),
        aggregate=aggregate,
        physical_interfaces=tuple(
            _deduplicate(
                physical_interfaces
            )
        ),
        issues=tuple(
            _deduplicate(issues)
        ),
    )


def _resolve_physical_interfaces(
    interface: FGInterface,
    references: ReferenceIndex,
    *,
    seen: set[str],
) -> tuple[list[str], list[str]]:
    if interface.name in seen:
        return (
            [],
            [
                "Interface topology cycle detected "
                f"at {interface.name!r}."
            ],
        )

    seen = {
        *seen,
        interface.name,
    }

    # Aggregate/redundant interface.
    if _is_aggregate(interface):
        physical: list[str] = []
        issues: list[str] = []

        if not interface.members:
            issues.append(
                "Aggregate/redundant interface has no configured members."
            )

        for member_name in interface.members:
            member = references.get(
                ReferenceKind.INTERFACE,
                vdom=interface.vdom,
                name=member_name,
            )

            if member is None:
                issues.append(
                    "Aggregate member "
                    f"{member_name!r} was not found."
                )
                continue

            member_physical, member_issues = (
                _resolve_physical_interfaces(
                    member,
                    references,
                    seen=seen,
                )
            )

            physical.extend(
                member_physical
            )

            issues.extend(
                member_issues
            )

        return (
            physical,
            issues,
        )

    # VLAN / logical child.
    if interface.interface:
        parent = references.get(
            ReferenceKind.INTERFACE,
            vdom=interface.vdom,
            name=interface.interface,
        )

        if parent is None:
            return (
                [],
                [
                    "Parent interface "
                    f"{interface.interface!r} "
                    "was not found."
                ],
            )

        return _resolve_physical_interfaces(
            parent,
            references,
            seen=seen,
        )

    # Terminal interface.
    if _requires_resolvable_parent(
        interface
    ):
        return (
            [],
            [
                "Logical interface has no resolvable "
                "physical parent."
            ],
        )

    if _is_logical_without_parent(interface):
        return (
            [],
            [],
        )

    return (
        [
            interface.name
        ],
        [],
    )


def _is_aggregate(
    interface: FGInterface,
) -> bool:
    interface_type = (
        interface.type or ""
    ).lower()

    return (
        bool(interface.members)
        or interface_type
        in {
            "aggregate",
            "redundant",
        }
    )


def _interface_kind(
    interface: FGInterface,
) -> str:
    interface_type = (
        interface.type or ""
    ).lower()

    if _is_aggregate(interface):
        return "aggregate"

    if (
        interface.vlanid is not None
        or interface_type == "vlan"
    ):
        return "vlan"

    if (
        "tunnel" in interface_type
        or interface_type
        in {
            "ipsec",
            "gre",
        }
    ):
        return "tunnel"

    if interface.interface:
        return "logical"

    return "physical"


def _requires_resolvable_parent(
    interface: FGInterface,
) -> bool:
    interface_type = (
        interface.type or ""
    ).lower()

    return interface_type == "vlan"


def _is_logical_without_parent(
    interface: FGInterface,
) -> bool:
    interface_type = (
        interface.type or ""
    ).lower()

    return interface_type in {
        "loopback",
        "tunnel",
        "ipsec",
        "gre",
        "vdom-link",
    }


def _deduplicate(
    values: list[str],
) -> list[str]:
    return list(
        dict.fromkeys(values)
    )
