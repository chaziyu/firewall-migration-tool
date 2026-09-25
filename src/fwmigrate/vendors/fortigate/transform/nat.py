from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_interface

from ..model.interface import FGInterface
from ..model.ippool import FGIPPool
from ..model.source import FGConfig
from ..model.zone import FGZone

from ..relationships.references import (
    ReferenceIndex,
    ReferenceKind,
    build_reference_index,
)


@dataclass(frozen=True, slots=True)
class NormalizedSourceNAT:
    vdom: str

    policy_id: int | None
    policy_name: str | None

    translation_type: str

    # Preserve FortiGate pool reference names.
    pool_names: tuple[str, ...]

    # Interface or pool addresses/ranges.
    translated_addresses: tuple[
        str,
        ...
    ]

    egress_interfaces: tuple[
        str,
        ...
    ]

    issues: tuple[
        str,
        ...
    ]


@dataclass(frozen=True, slots=True)
class _InterfaceAddressResult:
    address: str | None
    issue: str | None


def transform_nat(
    config: FGConfig,
    *,
    references: ReferenceIndex | None = None,
) -> list[NormalizedSourceNAT]:
    references = (
        references
        or build_reference_index(config)
    )

    result: list[
        NormalizedSourceNAT
    ] = []

    for policy in config.policies:
        nat64 = _enabled(policy.nat64)
        ordinary_nat = _enabled(policy.nat)
        if not nat64 and not ordinary_nat:
            continue

        if ordinary_nat:
            if _enabled(policy.ippool) or policy.poolname:
                result.append(
                    _pool_nat(policy, references)
                )
            else:
                result.append(_interface_nat(config, policy, references))

        if nat64:
            result.append(
                _pool_nat(
                    policy,
                    references,
                    translation_type="nat64_ip_pool",
                    nat64=True,
                )
            )

    return result


def _pool_nat(
    policy,
    references: ReferenceIndex,
    *,
    translation_type: str = "ip_pool",
    nat64: bool = False,
) -> NormalizedSourceNAT:
    addresses: list[str] = []
    issues: list[str] = []

    if not policy.poolname:
        issues.append(
            "NAT64 is enabled but no poolname is configured."
            if nat64
            else "IP-pool NAT is enabled but no poolname is configured."
        )

    for pool_name in policy.poolname:
        resolution = references.resolve_any(
            vdom=policy.vdom,
            name=pool_name,
            kinds=(
                ReferenceKind.IP_POOL,
            ),
        )

        if (
            resolution is None
            or not isinstance(
                resolution.target,
                FGIPPool,
            )
        ):
            issues.append(
                "IP pool "
                f"{pool_name!r} was not found."
            )
            continue

        pool = resolution.target
        if nat64 and (pool.nat64 or "").lower() == "disable":
            issues.append(
                f"IP pool {pool_name!r} explicitly disables NAT64."
            )

        value = _pool_address(
            pool
        )

        if value is None:
            if pool.startip or pool.endip:
                issues.append(
                    "IP pool "
                    f"{pool_name!r} has only one explicitly configured "
                    "range endpoint; translated address cannot be derived safely."
                )
                continue
            issues.append(
                "IP pool "
                f"{pool_name!r} has no usable "
                "start/end address."
            )
            continue

        addresses.append(
            value
        )

    if nat64 and not addresses:
        issues.append(
            "No deterministic NAT64 source translation could be derived."
        )

    return NormalizedSourceNAT(
        vdom=policy.vdom,
        policy_id=policy.policy_id,
        policy_name=policy.name,
        translation_type=translation_type,
        pool_names=tuple(
            policy.poolname
        ),
        translated_addresses=tuple(
            dict.fromkeys(addresses)
        ),
        egress_interfaces=tuple(
            policy.dstintf
        ),
        issues=tuple(issues),
    )


def _interface_nat(
    config: FGConfig,
    policy,
    references: ReferenceIndex,
) -> NormalizedSourceNAT:
    interface_names: list[str] = []
    addresses: list[str] = []
    issues: list[str] = []

    for name in policy.dstintf:
        resolution = references.resolve_any(
            vdom=policy.vdom,
            name=name,
            kinds=(
                ReferenceKind.INTERFACE,
                ReferenceKind.ZONE,
                ReferenceKind.SDWAN_ZONE,
            ),
        )

        if resolution is None:
            issues.append(
                "Outgoing interface/zone "
                f"{name!r} was not found."
            )
            continue

        if resolution.predefined:
            issues.append(
                f"Outgoing interface {name!r} is non-specific; "
                "interface-address SNAT depends on the runtime "
                "egress path and cannot be derived deterministically."
            )
            continue

        if isinstance(
            resolution.target,
            FGInterface,
        ):
            interface_names.append(
                resolution.target.name
            )
            continue

        if isinstance(
            resolution.target,
            FGZone,
        ):
            interface_names.extend(
                resolution.target.members
            )
            continue

        if (
            resolution.kind
            == ReferenceKind.SDWAN_ZONE
        ):
            interface_names.extend(
                _sdwan_zone_interfaces(
                    config,
                    vdom=policy.vdom,
                    zone=name,
                )
            )

    interface_names = list(
        dict.fromkeys(
            interface_names
        )
    )

    for interface_name in interface_names:
        interface = references.get(
            ReferenceKind.INTERFACE,
            vdom=policy.vdom,
            name=interface_name,
        )

        if not isinstance(
            interface,
            FGInterface,
        ):
            issues.append(
                "Outgoing interface "
                f"{interface_name!r} was not found."
            )
            continue

        resolution = _interface_address(
            interface
        )

        if resolution.issue is not None:
            issues.append(resolution.issue)

        if resolution.address is None:
            continue

        addresses.append(resolution.address)

    if len(interface_names) > 1:
        issues.append(
            "Multiple possible outgoing interfaces "
            "exist; interface-address NAT is "
            "runtime-path dependent."
        )

        addresses = []

    return NormalizedSourceNAT(
        vdom=policy.vdom,
        policy_id=policy.policy_id,
        policy_name=policy.name,
        translation_type=(
            "interface_address"
        ),
        pool_names=(),
        translated_addresses=tuple(
            dict.fromkeys(addresses)
        ),
        egress_interfaces=tuple(
            interface_names
        ),
        issues=tuple(
            dict.fromkeys(issues)
        ),
    )


def _interface_address(
    interface: FGInterface,
) -> _InterfaceAddressResult:
    if (
        interface.mode
        and interface.mode.lower()
        in {
            "dhcp",
            "pppoe",
        }
    ):
        return _InterfaceAddressResult(
            address=None,
            issue=(
                f"Outgoing interface {interface.name!r} uses "
                f"dynamic addressing mode {interface.mode.lower()!r}; "
                "interface-address SNAT is runtime-dependent."
            ),
        )

    if not interface.ip or not interface.ip.strip():
        return _InterfaceAddressResult(
            address=None,
            issue=(
                f"Outgoing interface {interface.name!r} has no "
                "explicitly configured IPv4 address; "
                "interface-address SNAT cannot be derived."
            ),
        )

    raw = interface.ip.strip()

    # FortiGate source forms commonly include:
    #
    # 192.0.2.1 255.255.255.0
    # 192.0.2.1/24
    first = raw.split()[0]

    try:
        if "/" in first:
            return _InterfaceAddressResult(
                address=str(ip_interface(first).ip),
                issue=None,
            )

        return _InterfaceAddressResult(
            address=str(ip_address(first)),
            issue=None,
        )

    except ValueError:
        return _InterfaceAddressResult(
            address=None,
            issue=(
                f"Outgoing interface {interface.name!r} has an explicit "
                "'ip' value that could not be parsed as a static IPv4 "
                "address; interface-address SNAT cannot be derived. "
                f"Source value: {_preview_source_value(raw)!r}."
            ),
        )


def _preview_source_value(
    value: str,
    *,
    max_length: int = 120,
) -> str:
    preview = " ".join(value.split())
    if len(preview) <= max_length:
        return preview
    return f"{preview[:max_length - 3]}..."


def _pool_address(
    pool: FGIPPool,
) -> str | None:
    if (
        pool.startip
        and pool.endip
    ):
        if pool.startip == pool.endip:
            return pool.startip

        return (
            f"{pool.startip}-"
            f"{pool.endip}"
        )

    return None


def _sdwan_zone_interfaces(
    config: FGConfig,
    *,
    vdom: str,
    zone: str,
) -> list[str]:
    result: list[str] = []

    for sdwan in config.sdwans:
        if sdwan.vdom != vdom:
            continue

        for member in sdwan.members:
            if (
                member.zone == zone
                and member.interface
            ):
                result.append(
                    member.interface
                )

    return result


def _enabled(
    value: str | None,
) -> bool:
    return (
        value or ""
    ).lower() == "enable"
