from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from ..fortios.predefined_services import (
    is_predefined_service_reference,
)
from ..model.source import FGConfig


class ReferenceKind(str, Enum):
    INTERFACE = "interface"
    ZONE = "zone"

    ADDRESS = "address"
    ADDRESS6 = "address6"
    ADDRESS_GROUP = "address_group"
    ADDRESS_GROUP6 = "address_group6"
    WILDCARD_FQDN = "wildcard_fqdn"
    EXTERNAL_ADDRESS = "external_address"

    SERVICE = "service"
    SERVICE_GROUP = "service_group"
    SCHEDULE = "schedule"
    SCHEDULE_GROUP = "schedule_group"

    VIP = "vip"
    VIP_GROUP = "vip_group"

    IP_POOL = "ip_pool"

    USER_GROUP = "user_group"

    SSL_VPN_PORTAL = "ssl_vpn_portal"

    PROFILE_GROUP = "profile_group"
    IPS_SENSOR = "ips_sensor"

    IPSEC_PHASE1 = "ipsec_phase1"

    SDWAN_ZONE = "sdwan_zone"


@dataclass(frozen=True, slots=True)
class ResolvedReference:
    kind: ReferenceKind
    vdom: str
    name: str
    target: Any | None

    predefined: bool = False


@dataclass(frozen=True, slots=True)
class BrokenReference:
    source_kind: str
    source_vdom: str
    source_name: str
    source_field: str

    reference: str

    expected_kinds: tuple[ReferenceKind, ...]


@dataclass(frozen=True, slots=True)
class DuplicateObject:
    kind: ReferenceKind
    vdom: str
    name: str


@dataclass(slots=True)
class ReferenceIndex:
    """
    VDOM-scoped FortiGate source-object lookup.

    Relationships are resolved without modifying source models.
    """

    objects: dict[
        ReferenceKind,
        dict[tuple[str, str], Any],
    ] = field(default_factory=dict)

    duplicates: list[DuplicateObject] = field(
        default_factory=list
    )

    def add(
        self,
        kind: ReferenceKind,
        *,
        vdom: str,
        name: str,
        target: Any,
    ) -> None:
        bucket = self.objects.setdefault(
            kind,
            {},
        )

        key = (
            vdom,
            name,
        )

        if key in bucket:
            self.duplicates.append(
                DuplicateObject(
                    kind=kind,
                    vdom=vdom,
                    name=name,
                )
            )
            return

        bucket[key] = target

    def get(
        self,
        kind: ReferenceKind,
        *,
        vdom: str,
        name: str,
    ) -> Any | None:
        return self.objects.get(
            kind,
            {},
        ).get(
            (
                vdom,
                name,
            )
        )

    def resolve_any(
        self,
        *,
        vdom: str,
        name: str,
        kinds: Iterable[ReferenceKind],
    ) -> ResolvedReference | None:
        kinds = tuple(kinds)

        implicit = _implicit_reference(
            name,
            kinds,
        )

        if implicit is not None:
            return ResolvedReference(
                kind=implicit,
                vdom=vdom,
                name=name,
                target=None,
                predefined=True,
            )

        for kind in kinds:
            target = self.get(
                kind,
                vdom=vdom,
                name=name,
            )

            if target is not None:
                return ResolvedReference(
                    kind=kind,
                    vdom=vdom,
                    name=name,
                    target=target,
                )

        return None


def build_reference_index(
    config: FGConfig,
) -> ReferenceIndex:
    index = ReferenceIndex()

    _add_named(
        index,
        ReferenceKind.INTERFACE,
        config.interfaces,
    )

    _add_named(
        index,
        ReferenceKind.ZONE,
        config.zones,
    )

    for address in config.addresses:
        index.add(
            ReferenceKind.ADDRESS6
            if address.address_family == "ipv6"
            else ReferenceKind.ADDRESS,
            vdom=address.vdom,
            name=address.name,
            target=address,
        )

    for group in config.address_groups:
        index.add(
            ReferenceKind.ADDRESS_GROUP6
            if group.address_family == "ipv6"
            else ReferenceKind.ADDRESS_GROUP,
            vdom=group.vdom,
            name=group.name,
            target=group,
        )

    _add_named(
        index,
        ReferenceKind.WILDCARD_FQDN,
        config.wildcard_fqdns,
    )

    for resource in config.external_resources:
        if (resource.type or "").lower() == "address":
            index.add(
                ReferenceKind.EXTERNAL_ADDRESS,
                vdom=resource.vdom,
                name=resource.name,
                target=resource,
            )

    _add_named(
        index,
        ReferenceKind.SERVICE,
        config.services,
    )

    _add_named(
        index,
        ReferenceKind.SERVICE_GROUP,
        config.service_groups,
    )

    _add_named(index, ReferenceKind.SCHEDULE, config.one_time_schedules)
    _add_named(index, ReferenceKind.SCHEDULE, config.recurring_schedules)
    _add_named(index, ReferenceKind.SCHEDULE_GROUP, config.schedule_groups)

    _add_named(
        index,
        ReferenceKind.VIP,
        config.vips,
    )

    _add_named(
        index,
        ReferenceKind.VIP_GROUP,
        config.vip_groups,
    )

    _add_named(
        index,
        ReferenceKind.IP_POOL,
        config.ip_pools,
    )

    _add_named(
        index,
        ReferenceKind.USER_GROUP,
        config.user_groups,
    )

    _add_named(
        index,
        ReferenceKind.SSL_VPN_PORTAL,
        config.ssl_vpn_portals,
    )

    _add_named(
        index,
        ReferenceKind.PROFILE_GROUP,
        config.profile_groups,
    )

    _add_named(
        index,
        ReferenceKind.IPS_SENSOR,
        config.ips_sensors,
    )

    _add_named(
        index,
        ReferenceKind.IPSEC_PHASE1,
        config.ipsec_phase1,
    )

    for sdwan in config.sdwans:
        for zone in sdwan.zones:
            index.add(
                ReferenceKind.SDWAN_ZONE,
                vdom=sdwan.vdom,
                name=zone.name,
                target=zone,
            )

    return index


def collect_broken_references(
    config: FGConfig,
    *,
    index: ReferenceIndex | None = None,
) -> list[BrokenReference]:
    """
    Check migration-relevant direct references.

    This reports problems only; it never modifies source data.
    """

    index = index or build_reference_index(
        config
    )

    issues: list[BrokenReference] = []

    policy_interface_like = (
        ReferenceKind.INTERFACE,
        ReferenceKind.ZONE,
        ReferenceKind.SDWAN_ZONE,
        ReferenceKind.IPSEC_PHASE1,
    )

    ipv4_address_like = (
        ReferenceKind.ADDRESS,
        ReferenceKind.ADDRESS_GROUP,
        ReferenceKind.WILDCARD_FQDN,
        ReferenceKind.EXTERNAL_ADDRESS,
    )

    ipv6_address_like = (
        ReferenceKind.ADDRESS6,
        ReferenceKind.ADDRESS_GROUP6,
    )

    destination_address_like = (
        *ipv4_address_like,
        ReferenceKind.VIP,
        ReferenceKind.VIP_GROUP,
    )

    service_like = (
        ReferenceKind.SERVICE,
        ReferenceKind.SERVICE_GROUP,
    )
    schedule_like = (ReferenceKind.SCHEDULE, ReferenceKind.SCHEDULE_GROUP)

    def check(
        *,
        source_kind: str,
        vdom: str,
        source_name: str,
        source_field: str,
        names: Iterable[str],
        kinds: tuple[ReferenceKind, ...],
    ) -> None:
        for name in names:
            if not name:
                continue

            if (
                index.resolve_any(
                    vdom=vdom,
                    name=name,
                    kinds=kinds,
                )
                is not None
            ):
                continue

            issues.append(
                BrokenReference(
                    source_kind=source_kind,
                    source_vdom=vdom,
                    source_name=source_name,
                    source_field=source_field,
                    reference=name,
                    expected_kinds=kinds,
                )
            )

    # --------------------------------------------------------------
    # Interfaces / zones
    # --------------------------------------------------------------

    for interface in config.interfaces:
        if interface.interface:
            check(
                source_kind="interface",
                vdom=interface.vdom,
                source_name=interface.name,
                source_field="interface",
                names=(interface.interface,),
                kinds=(
                    ReferenceKind.INTERFACE,
                ),
            )

        check(
            source_kind="interface",
            vdom=interface.vdom,
            source_name=interface.name,
            source_field="members",
            names=interface.members,
            kinds=(
                ReferenceKind.INTERFACE,
            ),
        )

    for zone in config.zones:
        check(
            source_kind="zone",
            vdom=zone.vdom,
            source_name=zone.name,
            source_field="members",
            names=zone.members,
            kinds=(
                ReferenceKind.INTERFACE,
            ),
        )

    # --------------------------------------------------------------
    # Object groups
    # --------------------------------------------------------------

    for group in config.address_groups:
        check(
            source_kind="address_group",
            vdom=group.vdom,
            source_name=group.name,
            source_field="members",
            names=group.members,
            kinds=(
                ReferenceKind.ADDRESS6,
                ReferenceKind.ADDRESS_GROUP6,
            ) if group.address_family == "ipv6" else ipv4_address_like,
        )

        check(
            source_kind="address_group",
            vdom=group.vdom,
            source_name=group.name,
            source_field="exclude_members",
            names=group.exclude_members,
            kinds=(
                ReferenceKind.ADDRESS6,
                ReferenceKind.ADDRESS_GROUP6,
            ) if group.address_family == "ipv6" else ipv4_address_like,
        )

    for group in config.service_groups:
        check(
            source_kind="service_group",
            vdom=group.vdom,
            source_name=group.name,
            source_field="members",
            names=group.members,
            kinds=service_like,
        )

    for group in config.schedule_groups:
        check(
            source_kind="schedule_group",
            vdom=group.vdom,
            source_name=group.name,
            source_field="members",
            names=group.members,
            kinds=(ReferenceKind.SCHEDULE,),
        )

    for group in config.vip_groups:
        check(
            source_kind="vip_group",
            vdom=group.vdom,
            source_name=group.name,
            source_field="members",
            names=group.members,
            kinds=(
                ReferenceKind.VIP,
            ),
        )

    # --------------------------------------------------------------
    # Policies
    # --------------------------------------------------------------

    for policy in config.policies:
        source_name = (
            policy.name
            or (
                str(policy.policy_id)
                if policy.policy_id is not None
                else "<unnamed>"
            )
        )

        check(
            source_kind="policy",
            vdom=policy.vdom,
            source_name=source_name,
            source_field="srcintf",
            names=policy.srcintf,
            kinds=policy_interface_like,
        )

        check(
            source_kind="policy",
            vdom=policy.vdom,
            source_name=source_name,
            source_field="dstintf",
            names=policy.dstintf,
            kinds=policy_interface_like,
        )

        check(
            source_kind="policy",
            vdom=policy.vdom,
            source_name=source_name,
            source_field="srcaddr",
            names=policy.srcaddr,
            kinds=ipv4_address_like,
        )

        check(
            source_kind="policy",
            vdom=policy.vdom,
            source_name=source_name,
            source_field="dstaddr",
            names=policy.dstaddr,
            kinds=destination_address_like,
        )

        check(
            source_kind="policy",
            vdom=policy.vdom,
            source_name=source_name,
            source_field="srcaddr6",
            names=policy.srcaddr6,
            kinds=ipv6_address_like,
        )

        check(
            source_kind="policy",
            vdom=policy.vdom,
            source_name=source_name,
            source_field="dstaddr6",
            names=policy.dstaddr6,
            kinds=ipv6_address_like,
        )

        check(
            source_kind="policy",
            vdom=policy.vdom,
            source_name=source_name,
            source_field="service",
            names=policy.service,
            kinds=service_like,
        )

        if policy.schedule:
            check(
                source_kind="policy",
                vdom=policy.vdom,
                source_name=source_name,
                source_field="schedule",
                names=(policy.schedule,),
                kinds=schedule_like,
            )

        check(
            source_kind="policy",
            vdom=policy.vdom,
            source_name=source_name,
            source_field="poolname",
            names=policy.poolname,
            kinds=(
                ReferenceKind.IP_POOL,
            ),
        )

        if policy.vpntunnel:
            check(
                source_kind="policy",
                vdom=policy.vdom,
                source_name=source_name,
                source_field="vpntunnel",
                names=(policy.vpntunnel,),
                kinds=(
                    ReferenceKind.IPSEC_PHASE1,
                ),
            )

        if policy.profile_group:
            check(
                source_kind="policy",
                vdom=policy.vdom,
                source_name=source_name,
                source_field="profile_group",
                names=(policy.profile_group,),
                kinds=(
                    ReferenceKind.PROFILE_GROUP,
                ),
            )

        if policy.ips_sensor:
            check(
                source_kind="policy",
                vdom=policy.vdom,
                source_name=source_name,
                source_field="ips_sensor",
                names=(policy.ips_sensor,),
                kinds=(
                    ReferenceKind.IPS_SENSOR,
                ),
            )

    # --------------------------------------------------------------
    # VPN
    # --------------------------------------------------------------

    for phase1 in config.ipsec_phase1:
        if not phase1.interface:
            continue

        check(
            source_kind="ipsec_phase1",
            vdom=phase1.vdom,
            source_name=phase1.name,
            source_field="interface",
            names=(phase1.interface,),
            kinds=(
                ReferenceKind.INTERFACE,
            ),
        )

    for phase2 in config.ipsec_phase2:
        if not phase2.phase1name:
            continue

        check(
            source_kind="ipsec_phase2",
            vdom=phase2.vdom,
            source_name=phase2.name,
            source_field="phase1name",
            names=(phase2.phase1name,),
            kinds=(
                ReferenceKind.IPSEC_PHASE1,
            ),
        )

    # --------------------------------------------------------------
    # SD-WAN
    # --------------------------------------------------------------

    for sdwan in config.sdwans:
        for member in sdwan.members:
            source_name = (
                str(member.seq_num)
                if member.seq_num is not None
                else "<unknown>"
            )

            if member.interface:
                check(
                    source_kind="sdwan_member",
                    vdom=sdwan.vdom,
                    source_name=source_name,
                    source_field="interface",
                    names=(member.interface,),
                    kinds=(
                        ReferenceKind.INTERFACE,
                    ),
                )

            if member.zone:
                check(
                    source_kind="sdwan_member",
                    vdom=sdwan.vdom,
                    source_name=source_name,
                    source_field="zone",
                    names=(member.zone,),
                    kinds=(
                        ReferenceKind.SDWAN_ZONE,
                    ),
                )

    for administrator in config.administrators:
        if administrator.schedule:
            check(
                source_kind="administrator",
                vdom="root",
                source_name=administrator.name,
                source_field="schedule",
                names=(administrator.schedule,),
                kinds=schedule_like,
            )

    return issues


def _add_named(
    index: ReferenceIndex,
    kind: ReferenceKind,
    objects: Iterable[Any],
) -> None:
    for obj in objects:
        index.add(
            kind,
            vdom=getattr(
                obj,
                "vdom",
                "root",
            ),
            name=obj.name,
            target=obj,
        )


def _implicit_reference(
    name: str,
    kinds: tuple[ReferenceKind, ...],
) -> ReferenceKind | None:
    if (
        ReferenceKind.SERVICE in kinds
        or ReferenceKind.SERVICE_GROUP in kinds
    ):
        if is_predefined_service_reference(
            name
        ):
            return ReferenceKind.SERVICE

    if ReferenceKind.SCHEDULE in kinds or ReferenceKind.SCHEDULE_GROUP in kinds:
        if name.lower() == "always":
            return ReferenceKind.SCHEDULE

    if ReferenceKind.ADDRESS6 in kinds:
        if name.lower() in {"all", "all6"}:
            return ReferenceKind.ADDRESS6

    if (
        ReferenceKind.ADDRESS in kinds
        or ReferenceKind.ADDRESS_GROUP in kinds
    ):
        if name.lower() in {
            "all",
            "all6",
        }:
            return ReferenceKind.ADDRESS

    if (
        ReferenceKind.INTERFACE in kinds
        or ReferenceKind.ZONE in kinds
        or ReferenceKind.SDWAN_ZONE in kinds
    ):
        if name.lower() == "any":
            return ReferenceKind.INTERFACE

    return None
