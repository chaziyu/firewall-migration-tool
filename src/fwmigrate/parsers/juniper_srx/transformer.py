"""Canonical IR Transformer for Juniper SRX parsed source configuration."""

from __future__ import annotations

from typing import Dict, List, Optional

from fwmigrate.core.constants import IR_KEYWORD_ANY
from fwmigrate.ir.core import (
    IRAddress,
    IRAddressGroup,
    IRConfig,
    IRInterface,
    IRInterfaceSecondaryIP,
    IRMetadata,
    IRNATRule,
    IRPolicy,
    IRRoute,
    IRSchedule,
    IRService,
    IRServiceGroup,
    IRServicePort,
    IRVPNTunnel,
    IRZone,
)
from fwmigrate.ir.enums import AddressType, NATTranslationMode, NATType, PolicyAction, ServiceProtocol
from fwmigrate.parsers.juniper_srx.handlers.applications import resolve_icmp_code, resolve_icmp_type
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperSRXConfig
from fwmigrate.parsers.juniper_srx.resolver import JuniperReferenceResolver


class JuniperToIRTransformer:
    """Transforms Junos source model (JuniperSRXConfig) into Canonical IRConfig."""

    def __init__(
        self,
        config: JuniperSRXConfig,
        zone_mapping: Optional[Dict[str, str]] = None,
    ) -> None:
        self.config = config
        self.zone_mapping = zone_mapping or {}

    def map_zone(self, zone_name: Optional[str]) -> Optional[str]:
        if not zone_name:
            return None
        return self.zone_mapping.get(zone_name, zone_name)

    def transform(self) -> IRConfig:
        ir = IRConfig(
            metadata=IRMetadata(
                hostname=self.config.hostname or "juniper-srx",
                source_vendor="juniper_srx",
                source_version=self.config.version,
                input_type="junos_display_set",
            )
        )

        for ctx_name, context in self.config.contexts.items():
            resolver = JuniperReferenceResolver(context)
            self._transform_context(context, ir, resolver)

        return ir

    def _transform_context(
        self,
        context: JuniperContextConfig,
        ir: IRConfig,
        resolver: JuniperReferenceResolver,
    ) -> None:
        # 1. Interfaces & Units
        interface_to_zone: Dict[str, str] = {}
        for z in context.zones.values():
            mapped_z = self.map_zone(z.name)
            for intf_ref in z.interfaces:
                interface_to_zone[intf_ref] = mapped_z or z.name

        for intf in context.interfaces.values():
            if not intf.units:
                # Top-level interface without explicit units
                z_name = interface_to_zone.get(intf.name)
                ir.interfaces.append(
                    IRInterface(
                        name=intf.name,
                        zone=z_name,
                        description=intf.description,
                        status=not intf.disabled,
                        source_attributes=intf.source_attributes,
                    )
                )
            else:
                for unit in intf.units.values():
                    logical_name = f"{intf.name}.{unit.unit}"
                    z_name = interface_to_zone.get(logical_name) or interface_to_zone.get(intf.name)

                    primary_ip: Optional[str] = None
                    secondary_ips: List[IRInterfaceSecondaryIP] = []
                    requires_review = False

                    if unit.addresses:
                        # Determine primary address
                        primaries = [a for a in unit.addresses if a.primary or a.preferred]
                        if primaries:
                            primary_ip = primaries[0].address
                            non_primaries = [a for a in unit.addresses if a != primaries[0]]
                        elif len(unit.addresses) == 1:
                            primary_ip = unit.addresses[0].address
                            non_primaries = []
                        else:
                            # Multiple addresses without explicit primary -> preserve all, do not guess!
                            primary_ip = None
                            non_primaries = unit.addresses
                            requires_review = True

                        for npa in non_primaries:
                            secondary_ips.append(
                                IRInterfaceSecondaryIP(
                                    ip=npa.address,
                                    source_attributes=npa.source_attributes,
                                )
                            )

                    ir.interfaces.append(
                        IRInterface(
                            name=logical_name,
                            parent=intf.name,
                            vlanid=unit.vlan_id,
                            zone=z_name,
                            ip=primary_ip,
                            secondary_ips=secondary_ips,
                            description=unit.description or intf.description,
                            status=not (intf.disabled or unit.disabled),
                            requires_manual_review=requires_review,
                            source_attributes=unit.source_attributes,
                        )
                    )

        # 2. Zones (Only created from source config; no fake zones synthesized!)
        for zone in context.zones.values():
            mapped_name = self.map_zone(zone.name) or zone.name
            ir.zones.append(
                IRZone(
                    name=mapped_name,
                    interfaces=zone.interfaces,
                    description=zone.description,
                )
            )

        # 3. Address Books & Addresses
        for book in context.address_books.values():
            for addr in book.addresses.values():
                self._transform_address(addr, book.name, ir)

            for aset in book.address_sets.values():
                self._transform_address_set(aset, book.name, ir, resolver)

        # 4. Applications (Services) & Application Sets (Service Groups)
        for app in context.applications.values():
            self._transform_application(app, ir)

        for appset in context.application_sets.values():
            ir.service_groups.append(
                IRServiceGroup(
                    name=appset.name,
                    members=appset.applications,
                    description=appset.description,
                    source_attributes=appset.source_attributes,
                )
            )

        # 5. Schedulers
        for sched in context.schedulers.values():
            ir.schedules.append(
                IRSchedule(
                    name=sched.name,
                    start=sched.start_date,
                    end=sched.stop_date,
                    days=sched.daily or list(sched.weekdays.keys()),
                    source_attributes=sched.source_attributes,
                )
            )

        # 6. Policies (Zone policies + Global policies)
        for p in context.policies:
            self._transform_policy(p, ir, resolver, is_global=False)

        for gp in context.global_policies:
            self._transform_policy(gp, ir, resolver, is_global=True)

        # 7. Static Routes
        for idx, r in enumerate(context.routes, 1):
            self._transform_route(r, idx, ir)

        # 8. NAT Rules
        self._transform_nat(context, ir, resolver)

        # 9. VPN
        self._transform_vpn(context, ir)

    def _transform_address(self, addr, book_name: str, ir: IRConfig) -> None:
        canonical_name = addr.name if book_name == "global" else f"{book_name}__{addr.name}"

        addr_kwargs = {
            "name": canonical_name,
            "description": addr.description,
            "source_attributes": {
                "junos_address_book": book_name,
                "junos_original_name": addr.name,
                **addr.source_attributes,
            },
        }

        if addr.type == "dns-name":
            addr_kwargs["type"] = AddressType.FQDN
            addr_kwargs["fqdn"] = addr.fqdn
        elif addr.type == "range-address":
            addr_kwargs["type"] = AddressType.RANGE
            addr_kwargs["ip_range_start"] = addr.range_start
            addr_kwargs["ip_range_end"] = addr.range_end
        elif addr.type == "wildcard-address":
            addr_kwargs["type"] = AddressType.WILDCARD_MASK
            addr_kwargs["wildcard_mask"] = addr.wildcard
        else:
            val = addr.prefix or "0.0.0.0/0"
            is_host = False
            if "/" in val:
                prefix_len = val.split("/")[1]
                if prefix_len in ("32", "128"):
                    is_host = True
            elif " " not in val:
                val = f"{val}/32"
                is_host = True

            addr_kwargs["type"] = AddressType.HOST if is_host else AddressType.NETWORK
            addr_kwargs["subnet"] = val

        ir.addresses.append(IRAddress(**addr_kwargs))

    def _transform_address_set(
        self, aset, book_name: str, ir: IRConfig, resolver: JuniperReferenceResolver
    ) -> None:
        canonical_name = aset.name if book_name == "global" else f"{book_name}__{aset.name}"
        members, has_cycle = resolver.expand_address_set(
            resolver.context.address_books.get(book_name, aset), aset.name
        )

        ir.address_groups.append(
            IRAddressGroup(
                name=canonical_name,
                members=members,
                description=aset.description,
                requires_manual_review=has_cycle,
                audit_note="Cyclic address-set reference detected" if has_cycle else None,
                source_attributes={
                    "junos_address_book": book_name,
                    "junos_original_name": aset.name,
                    **aset.source_attributes,
                },
            )
        )

    def _transform_application(self, app, ir: IRConfig) -> None:
        ports: List[IRServicePort] = []
        requires_review = False
        unmodeled_settings: List[str] = []

        for term in app.terms:
            proto_val = term.protocol
            if not proto_val:
                # No protocol extracted -> DO NOT default to TCP!
                requires_review = True
                proto_enum = ServiceProtocol.IP
            else:
                p_lower = proto_val.lower()
                if p_lower == "tcp":
                    proto_enum = ServiceProtocol.TCP
                elif p_lower == "udp":
                    proto_enum = ServiceProtocol.UDP
                elif p_lower == "icmp":
                    proto_enum = ServiceProtocol.ICMP
                elif p_lower == "icmp6" or p_lower == "icmpv6":
                    proto_enum = ServiceProtocol.ICMPV6
                elif p_lower == "sctp":
                    proto_enum = ServiceProtocol.SCTP
                else:
                    proto_enum = ServiceProtocol.IP

            dest_ports = term.destination_ports or (["any"] if proto_val else ["any"])
            src_port = term.source_ports[0] if term.source_ports else None
            icmp_t = resolve_icmp_type(term.icmp_type)
            icmp_c = resolve_icmp_code(term.icmp_code)

            if term.application_protocol:
                unmodeled_settings.append(f"application-protocol: {term.application_protocol}")
                requires_review = True

            for dp in dest_ports:
                ports.append(
                    IRServicePort(
                        protocol=proto_enum,
                        port=dp,
                        source_port=src_port,
                        icmptype=icmp_t,
                        icmpcode=icmp_c,
                    )
                )

        ir.services.append(
            IRService(
                name=app.name,
                ports=ports,
                description=app.description,
                requires_manual_review=requires_review,
                migration_status="PARTIALLY_NORMALIZED" if requires_review else "NORMALIZED",
                source_unmodeled_semantic_settings=unmodeled_settings,
                source_attributes=app.source_attributes,
            )
        )

    def _transform_policy(
        self,
        pol,
        ir: IRConfig,
        resolver: JuniperReferenceResolver,
        is_global: bool,
    ) -> None:
        requires_review = False
        review_reasons: List[str] = []

        # 1. Action mapping
        if pol.action == "permit":
            act = PolicyAction.ALLOW
            src_act = "permit"
        elif pol.action == "deny":
            act = PolicyAction.DENY
            src_act = "deny"
        elif pol.action == "reject":
            act = PolicyAction.DENY
            src_act = "reject"
            requires_review = True
            review_reasons.append("Action 'reject' mapped to DENY (behavioral discrepancy)")
        else:
            # Action was None or missing -> DO NOT default to permit or deny!
            act = None
            src_act = pol.action
            requires_review = True
            review_reasons.append("Policy action is missing or unparsed")

        # 2. Source match resolution
        if not pol.source_addresses:
            # Missing source dimension -> DO NOT substitute any!
            norm_src: List[str] = []
            requires_review = True
            review_reasons.append("Policy source match statement missing")
        else:
            norm_src = []
            for s in pol.source_addresses:
                s_lower = s.lower()
                if s_lower in ("any", "any-ipv4", "any-ipv6"):
                    norm_src.append(s_lower)
                else:
                    first_from_zone = pol.from_zones[0] if pol.from_zones else None
                    resolved = (
                        resolver.resolve_global_policy(s)
                        if is_global
                        else resolver.resolve_policy_source(first_from_zone, s)
                    )
                    norm_src.append(resolved.name)
                    if resolved.is_unresolved:
                        requires_review = True
                        review_reasons.append(f"Unresolved source address: {s}")

        # 3. Destination match resolution
        if not pol.destination_addresses:
            norm_dst: List[str] = []
            requires_review = True
            review_reasons.append("Policy destination match statement missing")
        else:
            norm_dst = []
            for d in pol.destination_addresses:
                d_lower = d.lower()
                if d_lower in ("any", "any-ipv4", "any-ipv6"):
                    norm_dst.append(d_lower)
                else:
                    first_to_zone = pol.to_zones[0] if pol.to_zones else None
                    resolved = (
                        resolver.resolve_global_policy(d)
                        if is_global
                        else resolver.resolve_policy_destination(first_to_zone, d)
                    )
                    norm_dst.append(resolved.name)
                    if resolved.is_unresolved:
                        requires_review = True
                        review_reasons.append(f"Unresolved destination address: {d}")

        # 4. Service / Application match resolution
        if not pol.applications:
            norm_svc: List[str] = []
            requires_review = True
            review_reasons.append("Policy application match statement missing")
        else:
            norm_svc = []
            for a in pol.applications:
                if a.lower() in ("any", "junos-any"):
                    norm_svc.append("any")
                else:
                    norm_svc.append(a)

        # 5. Zone mapping
        if is_global:
            mapped_from = [self.map_zone(z) or z for z in pol.from_zones] if pol.from_zones else [IR_KEYWORD_ANY]
            mapped_to = [self.map_zone(z) or z for z in pol.to_zones] if pol.to_zones else [IR_KEYWORD_ANY]
            requires_review = True
            review_reasons.append("Global policy evaluation scope requires manual review")
        else:
            mapped_from = [self.map_zone(z) or z for z in pol.from_zones]
            mapped_to = [self.map_zone(z) or z for z in pol.to_zones]

        # 6. Extra settings
        extra_settings: Dict[str, Any] = {**pol.permit_options, **pol.unknown_match_conditions, **pol.unknown_then_options}
        if is_global:
            extra_settings["junos_policy_scope"] = "global"
        if pol.count:
            extra_settings["junos_count"] = True
        if pol.dynamic_applications:
            extra_settings["junos_dynamic_applications"] = pol.dynamic_applications
            requires_review = True
            review_reasons.append("Dynamic applications require manual review")
        if pol.source_identities:
            extra_settings["junos_source_identities"] = pol.source_identities
            requires_review = True
            review_reasons.append("Source identities require manual review")

        if pol.source_address_excluded:
            requires_review = True
            review_reasons.append("Source address exclusion requires manual review")
        if pol.destination_address_excluded:
            requires_review = True
            review_reasons.append("Destination address exclusion requires manual review")

        ir.policies.append(
            IRPolicy(
                name=pol.name,
                from_zone=mapped_from,
                to_zone=mapped_to,
                source=norm_src,
                destination=norm_dst,
                service=norm_svc,
                action=act,
                source_action=src_act,
                source_address_negate_setting="exclude" if pol.source_address_excluded else None,
                destination_address_negate_setting="exclude" if pol.destination_address_excluded else None,
                schedule=pol.scheduler_name,
                source_schedule=pol.scheduler_name,
                log_start=pol.log_session_init or None,
                log_end=pol.log_session_close or None,
                disabled=pol.disabled or None,
                description=pol.description,
                source_extra_settings=extra_settings,
                requires_manual_review=requires_review,
                review_reasons=review_reasons,
                migration_status="PARTIALLY_NORMALIZED" if requires_review else "NORMALIZED",
            )
        )

    def _transform_route(self, r, idx: int, ir: IRConfig) -> None:
        requires_review = False
        review_reasons: List[str] = []

        nh_val = r.next_hops[0].value if r.next_hops else None
        if not nh_val and not (r.discard or r.reject or r.receive or r.next_table):
            requires_review = True
            review_reasons.append("Route has no valid next-hop or discard action")

        is_blackhole = r.discard or r.reject

        src_attrs = {**r.source_attributes}
        if r.routing_instance:
            src_attrs["junos_routing_instance"] = r.routing_instance

        if len(r.next_hops) > 1:
            src_attrs["junos_multi_next_hops"] = [n.model_dump() for n in r.next_hops]
            requires_review = True
            review_reasons.append("Multi-next-hop ECMP route requires manual review")

        ir.routes.append(
            IRRoute(
                name=f"route_{idx}",
                destination=r.destination,
                next_hop=nh_val,
                administrative_distance=r.preference or (r.next_hops[0].preference if r.next_hops else None),
                metric=r.metric or (r.next_hops[0].metric if r.next_hops else None),
                route_tag=r.tag or (r.next_hops[0].tag if r.next_hops else None),
                blackhole=is_blackhole or None,
                disabled=r.disabled or None,
                requires_manual_review=requires_review,
                review_reasons=review_reasons,
                source_attributes=src_attrs,
            )
        )

    def _transform_nat(
        self,
        context: JuniperContextConfig,
        ir: IRConfig,
        resolver: JuniperReferenceResolver,
    ) -> None:
        seq = 1
        # Source NAT
        for rs in context.nat.source_rule_sets.values():
            from_z = [self.map_zone(z) or z for z in rs.from_context.zones]
            to_z = [self.map_zone(z) or z for z in rs.to_context.zones] if rs.to_context else []

            for r in rs.rules:
                mode: Optional[NATTranslationMode] = None
                pool_refs: List[str] = []
                trans_src: List[str] = []
                act_type = r.action.get("type")

                if act_type == "pool":
                    mode = NATTranslationMode.POOL
                    pool_name = r.action.get("pool_name", "")
                    pool_refs = [pool_name]
                    if pool_name in context.nat.source_pools:
                        trans_src = context.nat.source_pools[pool_name].addresses
                elif act_type == "interface":
                    mode = NATTranslationMode.INTERFACE_ADDRESS
                elif act_type == "off":
                    mode = NATTranslationMode.NONE

                ir.nat_rules.append(
                    IRNATRule(
                        name=r.name,
                        type=NATType.SOURCE,
                        sequence=seq,
                        from_zone=from_z,
                        to_zone=to_z,
                        source=r.match.source_addresses or r.match.source_address_names or [IR_KEYWORD_ANY],
                        destination=r.match.destination_addresses or r.match.destination_address_names or [IR_KEYWORD_ANY],
                        services=r.match.applications or [IR_KEYWORD_ANY],
                        source_translation_mode=mode,
                        source_pool_references=pool_refs,
                        translated_sources=trans_src,
                        description=r.description,
                        disabled=r.disabled,
                        source_attributes=r.source_attributes,
                    )
                )
                seq += 1

        # Destination NAT
        for rs in context.nat.destination_rule_sets.values():
            from_z = [self.map_zone(z) or z for z in rs.from_context.zones]
            to_z = [self.map_zone(z) or z for z in rs.to_context.zones] if rs.to_context else []

            for r in rs.rules:
                pool_name = r.action.get("pool_name", "")
                trans_dst = []
                if pool_name in context.nat.destination_pools:
                    trans_dst = context.nat.destination_pools[pool_name].addresses

                ir.nat_rules.append(
                    IRNATRule(
                        name=r.name,
                        type=NATType.DESTINATION,
                        sequence=seq,
                        from_zone=from_z,
                        to_zone=to_z,
                        source=r.match.source_addresses or r.match.source_address_names or [IR_KEYWORD_ANY],
                        destination=r.match.destination_addresses or r.match.destination_address_names or [IR_KEYWORD_ANY],
                        services=r.match.applications or [IR_KEYWORD_ANY],
                        translated_destinations=trans_dst,
                        description=r.description,
                        disabled=r.disabled,
                        source_attributes=r.source_attributes,
                    )
                )
                seq += 1

        # Static NAT: conservative mapping
        for rs in context.nat.static_rule_sets.values():
            from_z = [self.map_zone(z) or z for z in rs.from_context.zones]
            for r in rs.rules:
                ir.nat_rules.append(
                    IRNATRule(
                        name=r.name,
                        type=NATType.TWICE,
                        sequence=seq,
                        from_zone=from_z,
                        to_zone=[],
                        source=r.match.source_addresses or [IR_KEYWORD_ANY],
                        destination=r.match.destination_addresses or [IR_KEYWORD_ANY],
                        services=r.match.applications or [IR_KEYWORD_ANY],
                        translated_sources=[r.action.get("prefix", "")] if r.action.get("type") == "static_prefix" else [],
                        translated_destinations=[r.action.get("prefix", "")] if r.action.get("type") == "static_prefix" else [],
                        requires_manual_review=True,
                        migration_status="PARTIALLY_NORMALIZED",
                        review_reasons=["Junos static NAT requires manual review for exact bidirectional semantics"],
                        source_attributes=r.source_attributes,
                    )
                )
                seq += 1

    def _transform_vpn(self, context: JuniperContextConfig, ir: IRConfig) -> None:
        for vpn in context.vpn.ipsec_vpns.values():
            if not vpn.bind_interface:
                # Without bind interface, do not create invalid IRVPNTunnel with fake interface!
                continue

            gw = context.vpn.ike_gateways.get(vpn.ike_gateway, None) if vpn.ike_gateway else None
            peer_ip = gw.address if gw else None

            ir.vpn_tunnels.append(
                IRVPNTunnel(
                    name=vpn.name,
                    local_interface=vpn.bind_interface,
                    peer_address=peer_ip,
                    has_psk=True if (gw and gw.ike_policy in context.vpn.ike_policies and context.vpn.ike_policies[gw.ike_policy].has_pre_shared_key) else False,
                    ike_crypto_profile=gw.ike_policy if gw else None,
                    ipsec_crypto_profile=vpn.ipsec_policy,
                    source_attributes=vpn.source_attributes,
                )
            )
