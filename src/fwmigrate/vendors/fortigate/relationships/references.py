from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field
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
    VIP6 = "vip6"
    VIP_GROUP = "vip_group"
    VIP_GROUP6 = "vip_group6"

    IP_POOL = "ip_pool"
    IP_POOL6 = "ip_pool6"

    LOCAL_USER = "local_user"
    USER_GROUP = "user_group"

    SSL_VPN_PORTAL = "ssl_vpn_portal"

    PROFILE_GROUP = "profile_group"
    PROTOCOL_OPTIONS = "protocol_options"
    PER_IP_SHAPER = "per_ip_shaper"
    IPS_SENSOR = "ips_sensor"
    ADMIN_PROFILE = "admin_profile"

    AV_PROFILE = "av_profile"
    WEBFILTER_PROFILE = "webfilter_profile"
    DNSFILTER_PROFILE = "dnsfilter_profile"
    APPLICATION_LIST = "application_list"
    SSL_SSH_PROFILE = "ssl_ssh_profile"
    FILE_FILTER_PROFILE = "file_filter_profile"
    EMAILFILTER_PROFILE = "emailfilter_profile"
    VOIP_PROFILE = "voip_profile"
    WAF_PROFILE = "waf_profile"
    TRAFFIC_SHAPER = "traffic_shaper"
    LDB_MONITOR = "ldb_monitor"

    LDAP_SERVER = "ldap_server"
    RADIUS_SERVER = "radius_server"
    TACACS_SERVER = "tacacs_server"

    IPSEC_PHASE1 = "ipsec_phase1"
    IPSEC_POLICY_PHASE1 = "ipsec_policy_phase1"

    WTP_PROFILE = "wtp_profile"
    SWITCH_PORT_POLICY = "switch_port_policy"
    SWITCH_LLDP_PROFILE = "switch_lldp_profile"
    SWITCH_QOS_POLICY = "switch_qos_policy"
    SWITCH_VLAN_POLICY = "switch_vlan_policy"

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
    ] = dataclass_field(default_factory=dict)

    duplicates: list[DuplicateObject] = dataclass_field(
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
        (interface for interface in config.interfaces if interface.vdom is not None),
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
    _add_named(index, ReferenceKind.VIP6, config.vips6)

    _add_named(
        index,
        ReferenceKind.VIP_GROUP,
        config.vip_groups,
    )
    _add_named(index, ReferenceKind.VIP_GROUP6, config.vip_groups6)

    _add_named(
        index,
        ReferenceKind.IP_POOL,
        config.ip_pools,
    )
    _add_named(index, ReferenceKind.IP_POOL6, config.ip_pools6)

    _add_named(index, ReferenceKind.LOCAL_USER, config.local_users)
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
    _add_named(index, ReferenceKind.PROTOCOL_OPTIONS, config.protocol_options)
    _add_named(index, ReferenceKind.PER_IP_SHAPER, config.per_ip_shapers)

    _add_named(
        index,
        ReferenceKind.IPS_SENSOR,
        config.ips_sensors,
    )

    _add_named(index, ReferenceKind.AV_PROFILE, config.antivirus_profiles)
    _add_named(index, ReferenceKind.WEBFILTER_PROFILE, config.webfilter_profiles)
    _add_named(index, ReferenceKind.DNSFILTER_PROFILE, config.dnsfilter_profiles)
    _add_named(index, ReferenceKind.APPLICATION_LIST, config.application_lists)
    _add_named(index, ReferenceKind.SSL_SSH_PROFILE, config.ssl_ssh_profiles)
    _add_named(index, ReferenceKind.FILE_FILTER_PROFILE, config.file_filter_profiles)
    _add_named(index, ReferenceKind.EMAILFILTER_PROFILE, config.emailfilter_profiles)
    _add_named(index, ReferenceKind.VOIP_PROFILE, config.voip_profiles)
    _add_named(index, ReferenceKind.WAF_PROFILE, config.waf_profiles)
    _add_named(index, ReferenceKind.TRAFFIC_SHAPER, config.traffic_shapers)
    _add_named(index, ReferenceKind.LDB_MONITOR, config.ldb_monitors)
    _add_named(index, ReferenceKind.LDAP_SERVER, config.ldap_servers)
    _add_named(index, ReferenceKind.RADIUS_SERVER, config.radius_servers)
    _add_named(index, ReferenceKind.TACACS_SERVER, config.tacacs_servers)
    _add_named(index, ReferenceKind.WTP_PROFILE, config.wtp_profiles)
    _add_named(index, ReferenceKind.SWITCH_PORT_POLICY, config.switch_port_policies)
    _add_named(index, ReferenceKind.SWITCH_LLDP_PROFILE, config.switch_lldp_profiles)
    _add_named(index, ReferenceKind.SWITCH_QOS_POLICY, config.switch_qos_policies)
    _add_named(index, ReferenceKind.SWITCH_VLAN_POLICY, config.switch_vlan_policies)

    _add_named(index, ReferenceKind.ADMIN_PROFILE, config.admin_profiles)

    _add_named(
        index,
        ReferenceKind.IPSEC_PHASE1,
        config.ipsec_phase1,
    )
    _add_named(index, ReferenceKind.IPSEC_POLICY_PHASE1, config.ipsec_policy_phase1)

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
    resolution_cache: dict[tuple[str, str, tuple[ReferenceKind, ...]], bool] = {}

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

            cache_key = (vdom, name, kinds)
            if cache_key not in resolution_cache:
                resolution_cache[cache_key] = (
                    index.resolve_any(
                        vdom=vdom,
                        name=name,
                        kinds=kinds,
                    )
                    is not None
                )

            if resolution_cache[cache_key]:
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
            names=group.members or (),
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
            names=group.exclude_members or (),
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
            names=group.members or (),
            kinds=service_like,
        )

    for group in config.schedule_groups:
        check(
            source_kind="schedule_group",
            vdom=group.vdom,
            source_name=group.name,
            source_field="members",
            names=group.members or (),
            kinds=(ReferenceKind.SCHEDULE,),
        )

    for group in config.vip_groups:
        check(
            source_kind="vip_group",
            vdom=group.vdom,
            source_name=group.name,
            source_field="members",
            names=group.members or (),
            kinds=(
                ReferenceKind.VIP,
            ),
        )

    # --------------------------------------------------------------
    # Policies
    # --------------------------------------------------------------

    for rule in config.central_snat:
        for field, kinds in (("orig_addr", ipv4_address_like), ("dst_addr", ipv4_address_like),
                             ("orig_addr6", (ReferenceKind.ADDRESS6, ReferenceKind.ADDRESS_GROUP6)),
                             ("dst_addr6", (ReferenceKind.ADDRESS6, ReferenceKind.ADDRESS_GROUP6)),
                             ("srcintf", policy_interface_like), ("dstintf", policy_interface_like),
                             ("nat_ippool", (ReferenceKind.IP_POOL,)),
                             ("nat_ippool6", (ReferenceKind.IP_POOL6,))):
            check(source_kind="central_snat", vdom=rule.vdom, source_name=str(rule.policy_id),
                  source_field=field, names=getattr(rule, field) or (), kinds=kinds)

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
            names=policy.srcintf or (),
            kinds=policy_interface_like,
        )

        check(
            source_kind="policy",
            vdom=policy.vdom,
            source_name=source_name,
            source_field="dstintf",
            names=policy.dstintf or (),
            kinds=policy_interface_like,
        )

        check(
            source_kind="policy",
            vdom=policy.vdom,
            source_name=source_name,
            source_field="srcaddr",
            names=policy.srcaddr or (),
            kinds=ipv4_address_like,
        )

        check(
            source_kind="policy",
            vdom=policy.vdom,
            source_name=source_name,
            source_field="dstaddr",
            names=policy.dstaddr or (),
            kinds=destination_address_like,
        )

        check(
            source_kind="policy",
            vdom=policy.vdom,
            source_name=source_name,
            source_field="srcaddr6",
            names=policy.srcaddr6 or (),
            kinds=ipv6_address_like,
        )

        check(
            source_kind="policy",
            vdom=policy.vdom,
            source_name=source_name,
            source_field="dstaddr6",
            names=policy.dstaddr6 or (),
            kinds=ipv6_address_like,
        )

        check(
            source_kind="policy",
            vdom=policy.vdom,
            source_name=source_name,
            source_field="service",
            names=policy.service or (),
            kinds=service_like,
        )

        check(source_kind="policy", vdom=policy.vdom, source_name=source_name,
              source_field="users", names=policy.users or (), kinds=(ReferenceKind.LOCAL_USER,))
        check(source_kind="policy", vdom=policy.vdom, source_name=source_name,
              source_field="groups", names=policy.groups or (), kinds=(ReferenceKind.USER_GROUP,))

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
            names=policy.poolname or (),
            kinds=(
                ReferenceKind.IP_POOL,
            ),
        )

        check(
            source_kind="policy",
            vdom=policy.vdom,
            source_name=source_name,
            source_field="poolname6",
            names=policy.poolname6 or (),
            kinds=(ReferenceKind.IP_POOL6,),
        )

        if policy.vpntunnel:
            check(
                source_kind="policy",
                vdom=policy.vdom,
                source_name=source_name,
                source_field="vpntunnel",
                names=(policy.vpntunnel,),
                kinds=(ReferenceKind.IPSEC_POLICY_PHASE1,),
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

        if policy.profile_protocol_options:
            check(
                source_kind="policy", vdom=policy.vdom, source_name=source_name,
                source_field="profile_protocol_options", names=(policy.profile_protocol_options,),
                kinds=(ReferenceKind.PROTOCOL_OPTIONS,),
            )
        if policy.per_ip_shaper:
            check(
                source_kind="policy", vdom=policy.vdom, source_name=source_name,
                source_field="per_ip_shaper", names=(policy.per_ip_shaper,),
                kinds=(ReferenceKind.PER_IP_SHAPER,),
            )
        for field, kind in (
            ("av_profile", ReferenceKind.AV_PROFILE),
            ("webfilter_profile", ReferenceKind.WEBFILTER_PROFILE),
            ("dnsfilter_profile", ReferenceKind.DNSFILTER_PROFILE),
            ("application_list", ReferenceKind.APPLICATION_LIST),
            ("ssl_ssh_profile", ReferenceKind.SSL_SSH_PROFILE),
            ("file_filter_profile", ReferenceKind.FILE_FILTER_PROFILE),
            ("emailfilter_profile", ReferenceKind.EMAILFILTER_PROFILE),
            ("waf_profile", ReferenceKind.WAF_PROFILE),
        ):
            val = getattr(policy, field, None)
            if val and index.objects.get(kind):
                check(source_kind="policy", vdom=policy.vdom, source_name=source_name,
                      source_field=field, names=(val,), kinds=(kind,))

    for group in config.profile_groups:
        if group.ips_sensor:
            check(source_kind="profile_group", vdom=group.vdom, source_name=group.name,
                  source_field="ips_sensor", names=(group.ips_sensor,), kinds=(ReferenceKind.IPS_SENSOR,))
        if group.profile_protocol_options:
            check(source_kind="profile_group", vdom=group.vdom, source_name=group.name,
                  source_field="profile_protocol_options", names=(group.profile_protocol_options,), kinds=(ReferenceKind.PROTOCOL_OPTIONS,))
        for field, kind in (
            ("av_profile", ReferenceKind.AV_PROFILE),
            ("webfilter_profile", ReferenceKind.WEBFILTER_PROFILE),
            ("dnsfilter_profile", ReferenceKind.DNSFILTER_PROFILE),
            ("application_list", ReferenceKind.APPLICATION_LIST),
            ("ssl_ssh_profile", ReferenceKind.SSL_SSH_PROFILE),
            ("file_filter_profile", ReferenceKind.FILE_FILTER_PROFILE),
            ("emailfilter_profile", ReferenceKind.EMAILFILTER_PROFILE),
            ("voip_profile", ReferenceKind.VOIP_PROFILE),
            ("waf_profile", ReferenceKind.WAF_PROFILE),
        ):
            val = getattr(group, field, None)
            if val and index.objects.get(kind):
                check(source_kind="profile_group", vdom=group.vdom, source_name=group.name,
                      source_field=field, names=(val,), kinds=(kind,))

    for proxy in config.proxy_policies:
        pname = proxy.name or (str(proxy.policy_id) if proxy.policy_id is not None else "<unnamed>")
        for field, names, kinds in (
            ("srcintf", proxy.srcintf, policy_interface_like),
            ("dstintf", proxy.dstintf, policy_interface_like),
            ("srcaddr", proxy.srcaddr, ipv4_address_like),
            ("dstaddr", proxy.dstaddr, destination_address_like),
            ("srcaddr6", proxy.srcaddr6, ipv6_address_like),
            ("dstaddr6", proxy.dstaddr6, ipv6_address_like),
            ("service", proxy.service, service_like),
            ("users", proxy.users, (ReferenceKind.LOCAL_USER,)),
            ("groups", proxy.groups, (ReferenceKind.USER_GROUP,)),
            ("poolname", proxy.poolname, (ReferenceKind.IP_POOL,)),
        ):
            check(source_kind="proxy_policy", vdom=proxy.vdom, source_name=pname,
                  source_field=field, names=names or (), kinds=kinds)
        if proxy.schedule:
            check(source_kind="proxy_policy", vdom=proxy.vdom, source_name=pname,
                  source_field="schedule", names=(proxy.schedule,), kinds=schedule_like)
        for field, kind, gated in (
            ("profile_group", ReferenceKind.PROFILE_GROUP, False),
            ("ips_sensor", ReferenceKind.IPS_SENSOR, False),
            ("profile_protocol_options", ReferenceKind.PROTOCOL_OPTIONS, False),
            ("av_profile", ReferenceKind.AV_PROFILE, True),
            ("webfilter_profile", ReferenceKind.WEBFILTER_PROFILE, True),
            ("application_list", ReferenceKind.APPLICATION_LIST, True),
            ("ssl_ssh_profile", ReferenceKind.SSL_SSH_PROFILE, True),
            ("file_filter_profile", ReferenceKind.FILE_FILTER_PROFILE, True),
            ("emailfilter_profile", ReferenceKind.EMAILFILTER_PROFILE, True),
            ("waf_profile", ReferenceKind.WAF_PROFILE, True),
        ):
            val = getattr(proxy, field, None)
            if val and (not gated or index.objects.get(kind)):
                check(source_kind="proxy_policy", vdom=proxy.vdom, source_name=pname,
                      source_field=field, names=(val,), kinds=(kind,))

    for auth in config.auth_policies:
        aname = auth.name or (str(auth.policy_id) if auth.policy_id is not None else "<unnamed>")
        for field, names, kinds in (
            ("srcintf", auth.srcintf, policy_interface_like),
            ("srcaddr", auth.srcaddr, ipv4_address_like),
            ("dstaddr", auth.dstaddr, ipv4_address_like),
            ("srcaddr6", auth.srcaddr6, ipv6_address_like),
            ("dstaddr6", auth.dstaddr6, ipv6_address_like),
            ("service", (auth.service,) if auth.service else (), service_like),
            ("users", auth.users, (ReferenceKind.LOCAL_USER,)),
            ("groups", auth.groups, (ReferenceKind.USER_GROUP,)),
        ):
            check(source_kind="auth_policy", vdom=auth.vdom, source_name=aname,
                  source_field=field, names=names or (), kinds=kinds)

    for proute in config.policy_routes:
        rname = str(proute.seq_num) if proute.seq_num is not None else "<unnamed>"
        rkind = "policy_route6" if proute.address_family == "ipv6" else "policy_route"
        addr_kinds = ipv6_address_like if proute.address_family == "ipv6" else ipv4_address_like
        check(source_kind=rkind, vdom=proute.vdom, source_name=rname,
              source_field="input_device", names=proute.input_device, kinds=(ReferenceKind.INTERFACE,))
        if proute.output_device:
            check(source_kind=rkind, vdom=proute.vdom, source_name=rname,
                  source_field="output_device", names=(proute.output_device,), kinds=(ReferenceKind.INTERFACE, ReferenceKind.IPSEC_PHASE1))
        check(source_kind=rkind, vdom=proute.vdom, source_name=rname,
              source_field="srcaddr", names=proute.srcaddr, kinds=addr_kinds)
        check(source_kind=rkind, vdom=proute.vdom, source_name=rname,
              source_field="dstaddr", names=proute.dstaddr, kinds=addr_kinds)

    for luser in config.local_users:
        for field, kind in (
            ("ldap_server", ReferenceKind.LDAP_SERVER),
            ("radius_server", ReferenceKind.RADIUS_SERVER),
            ("tacacs_server", ReferenceKind.TACACS_SERVER),
        ):
            val = getattr(luser, field, None)
            if val and index.objects.get(kind):
                check(source_kind="local_user", vdom=luser.vdom, source_name=luser.name,
                      source_field=field, names=(val,), kinds=(kind,))

    auth_server_kinds = tuple(
        k for k in (ReferenceKind.LDAP_SERVER, ReferenceKind.RADIUS_SERVER, ReferenceKind.TACACS_SERVER)
        if index.objects.get(k)
    )
    if auth_server_kinds:
        for ugroup in config.user_groups:
            for match in ugroup.matches:
                if match.server_name:
                    check(source_kind="user_group", vdom=ugroup.vdom, source_name=ugroup.name,
                          source_field="matches.server_name", names=(match.server_name,), kinds=auth_server_kinds)

    for keytab in config.kerberos_keytabs:
        if keytab.ldap_server and index.objects.get(ReferenceKind.LDAP_SERVER):
            check(source_kind="kerberos_keytab", vdom=keytab.vdom, source_name=keytab.name,
                  source_field="ldap_server", names=(keytab.ldap_server,), kinds=(ReferenceKind.LDAP_SERVER,))

    for vap in config.wireless_vaps:
        if index.objects.get(ReferenceKind.RADIUS_SERVER):
            for field in ("radius_server", "radius_mac_auth_server"):
                val = getattr(vap, field, None)
                if val:
                    check(source_kind="wireless_vap", vdom=vap.vdom, source_name=vap.name,
                          source_field=field, names=(val,), kinds=(ReferenceKind.RADIUS_SERVER,))
        check(source_kind="wireless_vap", vdom=vap.vdom, source_name=vap.name,
              source_field="usergroup", names=vap.usergroup, kinds=(ReferenceKind.USER_GROUP,))
        check(source_kind="wireless_vap", vdom=vap.vdom, source_name=vap.name,
              source_field="selected_usergroups", names=vap.selected_usergroups, kinds=(ReferenceKind.USER_GROUP,))
        check(source_kind="wireless_vap", vdom=vap.vdom, source_name=vap.name,
              source_field="address_group", names=vap.address_group, kinds=(ReferenceKind.ADDRESS, ReferenceKind.ADDRESS_GROUP))

    for policy in config.nac_policies:
        if policy.firewall_address:
            check(source_kind="nac_policy", vdom=policy.vdom, source_name=policy.name,
                  source_field="firewall_address", names=(policy.firewall_address,),
                  kinds=(ReferenceKind.ADDRESS, ReferenceKind.ADDRESS_GROUP, ReferenceKind.ADDRESS6, ReferenceKind.ADDRESS_GROUP6))
        if policy.user_group:
            check(source_kind="nac_policy", vdom=policy.vdom, source_name=policy.name,
                  source_field="user_group", names=(policy.user_group,),
                  kinds=(ReferenceKind.USER_GROUP,))

    if index.objects.get(ReferenceKind.WTP_PROFILE):
        for wtp in config.wireless_wtps:
            if wtp.wtp_profile:
                check(source_kind="wireless_wtp", vdom=wtp.vdom, source_name=wtp.wtp_id,
                      source_field="wtp_profile", names=(wtp.wtp_profile,),
                      kinds=(ReferenceKind.WTP_PROFILE,))

    for port_policy in config.switch_port_policies:
        if port_policy.qos_policy and index.objects.get(ReferenceKind.SWITCH_QOS_POLICY):
            check(source_kind="switch_port_policy", vdom=port_policy.vdom, source_name=port_policy.name,
                  source_field="qos_policy", names=(port_policy.qos_policy,),
                  kinds=(ReferenceKind.SWITCH_QOS_POLICY,))
        if port_policy.vlan_policy and index.objects.get(ReferenceKind.SWITCH_VLAN_POLICY):
            check(source_kind="switch_port_policy", vdom=port_policy.vdom, source_name=port_policy.name,
                  source_field="vlan_policy", names=(port_policy.vlan_policy,),
                  kinds=(ReferenceKind.SWITCH_VLAN_POLICY,))
        if port_policy.user_group and index.objects.get(ReferenceKind.USER_GROUP):
            check(source_kind="switch_port_policy", vdom=port_policy.vdom, source_name=port_policy.name,
                  source_field="user_group", names=port_policy.user_group,
                  kinds=(ReferenceKind.USER_GROUP,))

    for sw in config.managed_switches:
        for port in sw.ports:
            if port.lldp_profile and index.objects.get(ReferenceKind.SWITCH_LLDP_PROFILE):
                check(source_kind="managed_switch_port", vdom=sw.vdom, source_name=f"{sw.switch_id}:{port.port_name}",
                      source_field="lldp_profile", names=(port.lldp_profile,),
                      kinds=(ReferenceKind.SWITCH_LLDP_PROFILE,))
            if port.qos_policy and index.objects.get(ReferenceKind.SWITCH_QOS_POLICY):
                check(source_kind="managed_switch_port", vdom=sw.vdom, source_name=f"{sw.switch_id}:{port.port_name}",
                      source_field="qos_policy", names=(port.qos_policy,),
                      kinds=(ReferenceKind.SWITCH_QOS_POLICY,))
            if port.port_security_policy and index.objects.get(ReferenceKind.SWITCH_PORT_POLICY):
                check(source_kind="managed_switch_port", vdom=sw.vdom, source_name=f"{sw.switch_id}:{port.port_name}",
                      source_field="port_security_policy", names=(port.port_security_policy,),
                      kinds=(ReferenceKind.SWITCH_PORT_POLICY,))

    for sniffer in config.on_demand_sniffers:
        if sniffer.interface:
            check(source_kind="on_demand_sniffer", vdom=sniffer.vdom, source_name=sniffer.name,
                  source_field="interface", names=(sniffer.interface,), kinds=(ReferenceKind.INTERFACE,))

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
        if administrator.accprofile:
            check(
                source_kind="administrator",
                vdom="root",
                source_name=administrator.name,
                source_field="accprofile",
                names=(administrator.accprofile,),
                kinds=(ReferenceKind.ADMIN_PROFILE,),
            )
        if administrator.schedule:
            check(
                source_kind="administrator",
                vdom="root",
                source_name=administrator.name,
                source_field="schedule",
                names=(administrator.schedule,),
                kinds=schedule_like,
            )

    for route in config.static_routes:
        source_name = str(route.seq_num) if route.seq_num is not None else "<unknown>"
        if route.dstaddr:
            check(
                source_kind="static_route6" if route.address_family == "ipv6" else "static_route",
                vdom=route.vdom,
                source_name=source_name,
                source_field="dstaddr",
                names=(route.dstaddr,),
                kinds=(
                    (ReferenceKind.ADDRESS6, ReferenceKind.ADDRESS_GROUP6)
                    if route.address_family == "ipv6"
                    else (ReferenceKind.ADDRESS, ReferenceKind.ADDRESS_GROUP)
                ),
            )
        if route.device:
            check(
                source_kind="static_route6" if route.address_family == "ipv6" else "static_route",
                vdom=route.vdom,
                source_name=source_name,
                source_field="device",
                names=(route.device,),
                kinds=(ReferenceKind.INTERFACE, ReferenceKind.IPSEC_PHASE1),
            )
        check(
            source_kind="static_route6" if route.address_family == "ipv6" else "static_route",
            vdom=route.vdom,
            source_name=source_name,
            source_field="sdwan_zone",
            names=route.sdwan_zone,
            kinds=(ReferenceKind.SDWAN_ZONE,),
        )

    for phase2 in config.ipsec_policy_phase2:
        if phase2.phase1name:
            check(
                source_kind="ipsec_policy_phase2", vdom=phase2.vdom, source_name=phase2.name,
                source_field="phase1name", names=(phase2.phase1name,),
                kinds=(ReferenceKind.IPSEC_POLICY_PHASE1,),
            )

    for server in config.dhcp_servers:
        if server.interface:
            check(
                source_kind="dhcp_server",
                vdom=server.vdom,
                source_name=str(server.id),
                source_field="interface",
                names=(server.interface,),
                kinds=(ReferenceKind.INTERFACE,),
            )

    for group in config.vip_groups6:
        check(
            source_kind="vip_group6", vdom=group.vdom, source_name=group.name,
            source_field="members", names=group.members, kinds=(ReferenceKind.VIP6,),
        )

    for vip in config.vips:
        if vip.extintf:
            check(
                source_kind="vip", vdom=vip.vdom, source_name=vip.name,
                source_field="extintf", names=(vip.extintf,),
                kinds=(ReferenceKind.INTERFACE,),
            )
        check(
            source_kind="vip", vdom=vip.vdom, source_name=vip.name,
            source_field="extaddr", names=vip.extaddr,
            kinds=(ReferenceKind.ADDRESS,),
        )
        if vip.mapped_addr:
            check(
                source_kind="vip", vdom=vip.vdom, source_name=vip.name,
                source_field="mapped_addr", names=(vip.mapped_addr,),
                kinds=(ReferenceKind.ADDRESS,),
            )
        check(
            source_kind="vip", vdom=vip.vdom, source_name=vip.name,
            source_field="service", names=vip.service, kinds=service_like,
        )
        for server in vip.realservers:
            if server.address:
                check(
                    source_kind="vip", vdom=vip.vdom, source_name=vip.name,
                    source_field=f"realservers[{server.id}].address",
                    names=(server.address,), kinds=(ReferenceKind.ADDRESS,),
                )
            if server.monitor and index.objects.get(ReferenceKind.LDB_MONITOR):
                check(
                    source_kind="vip", vdom=vip.vdom, source_name=vip.name,
                    source_field=f"realservers[{server.id}].monitor",
                    names=server.monitor, kinds=(ReferenceKind.LDB_MONITOR,),
                )
        if vip.monitor and index.objects.get(ReferenceKind.LDB_MONITOR):
            check(
                source_kind="vip", vdom=vip.vdom, source_name=vip.name,
                source_field="monitor", names=vip.monitor, kinds=(ReferenceKind.LDB_MONITOR,),
            )

    for group in config.vip_groups:
        if group.interface:
            check(
                source_kind="vip_group", vdom=group.vdom, source_name=group.name,
                source_field="interface", names=(group.interface,),
                kinds=(ReferenceKind.INTERFACE,),
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


_BUILTIN_PROFILE_KINDS = frozenset({
    ReferenceKind.AV_PROFILE,
    ReferenceKind.WEBFILTER_PROFILE,
    ReferenceKind.DNSFILTER_PROFILE,
    ReferenceKind.APPLICATION_LIST,
    ReferenceKind.SSL_SSH_PROFILE,
    ReferenceKind.FILE_FILTER_PROFILE,
    ReferenceKind.EMAILFILTER_PROFILE,
    ReferenceKind.VOIP_PROFILE,
    ReferenceKind.WAF_PROFILE,
})
_BUILTIN_PROFILE_NAMES = frozenset({
    "default", "all", "certificate-inspection", "no-inspection",
    "deep-inspection", "custom-deep-inspection", "wifi-default",
    "flow-monitor-default", "monitor-all", "sniffer-profile",
    "g-default", "g-wifi-default", "read-only", "block-high-risk",
    "g-block-high-risk", "scan", "av-monitor", "high-security",
    "web-filter-flow",
})
_BUILTIN_MONITORS = frozenset({"ping", "tcp", "udp", "http", "https"})


def _implicit_reference(
    name: str,
    kinds: tuple[ReferenceKind, ...],
) -> ReferenceKind | None:
    if ReferenceKind.ADMIN_PROFILE in kinds and name == "super_admin":
        return ReferenceKind.ADMIN_PROFILE

    if ReferenceKind.LDB_MONITOR in kinds and name.lower() in _BUILTIN_MONITORS:
        return ReferenceKind.LDB_MONITOR

    for kind in kinds:
        if kind in _BUILTIN_PROFILE_KINDS and name in _BUILTIN_PROFILE_NAMES:
            return kind

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
