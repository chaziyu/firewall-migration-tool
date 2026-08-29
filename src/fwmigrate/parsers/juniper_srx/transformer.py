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
        ctx_name = context.name
        # 1. Interfaces & Units
        interface_to_zone: Dict[str, str] = {}
        for z in context.zones.values():
            mapped_z = self.map_zone(z.name) or z.name
            canonical_z = f"{ctx_name}__{mapped_z}" if ctx_name != "root" else mapped_z
            for intf_ref in z.interfaces:
                interface_to_zone[intf_ref] = canonical_z

        for intf in context.interfaces.values():
            intf_attrs = {**intf.source_attributes}
            if ctx_name != "root":
                intf_attrs["junos_context"] = ctx_name

            if not intf.units:
                # Top-level interface without explicit units
                z_name = interface_to_zone.get(intf.name)
                ir.interfaces.append(
                    IRInterface(
                        name=intf.name,
                        zone=z_name,
                        description=intf.description,
                        status=not intf.disabled,
                        source_attributes=intf_attrs,
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

                    unit_attrs = {**unit.source_attributes}
                    if ctx_name != "root":
                        unit_attrs["junos_context"] = ctx_name

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
                            source_attributes=unit_attrs,
                        )
                    )

        # 2. Zones (Only created from source config; no fake zones synthesized!)
        for zone in context.zones.values():
            mapped_name = self.map_zone(zone.name) or zone.name
            z_name = f"{ctx_name}__{mapped_name}" if ctx_name != "root" else mapped_name
            zone_attrs = {**zone.source_attributes}
            if ctx_name != "root":
                zone_attrs["junos_context"] = ctx_name
            zone_disabled = zone.disabled or bool(zone_attrs.get("disabled"))
            if zone_disabled:
                zone_attrs["disabled"] = True
            ir.zones.append(
                IRZone(
                    name=z_name,
                    interfaces=zone.interfaces,
                    description=zone.description,
                    disabled=True if zone_disabled else None,
                    requires_manual_review=zone_disabled,
                    migration_status="PARTIALLY_NORMALIZED" if zone_disabled else "NORMALIZED",
                    review_reasons=["Zone is deactivated in Junos configuration"] if zone_disabled else [],
                    source_attributes=zone_attrs,
                )
            )

        # 3. Address Books & Addresses
        for book in context.address_books.values():
            for addr in book.addresses.values():
                self._transform_address(addr, book.name, ir, context_name=ctx_name)

            for aset in book.address_sets.values():
                self._transform_address_set(aset, book.name, ir, resolver, context_name=ctx_name)

        # 4. Applications (Services) & Application Sets (Service Groups)
        for app in context.applications.values():
            self._transform_application(app, ir, context_name=ctx_name)

        for appset in context.application_sets.values():
            sg_name = f"{ctx_name}__{appset.name}" if ctx_name != "root" else appset.name
            sg_attrs = {**appset.source_attributes}
            if ctx_name != "root":
                sg_attrs["junos_context"] = ctx_name
            members = [
                f"{ctx_name}__{a}" if ctx_name != "root" else a
                for a in appset.applications
            ]
            ir.service_groups.append(
                IRServiceGroup(
                    name=sg_name,
                    members=members,
                    description=appset.description,
                    requires_manual_review=appset.disabled,
                    source_attributes=sg_attrs,
                )
            )

        # 5. Schedulers
        for sched in context.schedulers.values():
            sched_name = f"{ctx_name}__{sched.name}" if ctx_name != "root" else sched.name
            sched_attrs = {**sched.source_attributes}
            if ctx_name != "root":
                sched_attrs["junos_context"] = ctx_name
            ir.schedules.append(
                IRSchedule(
                    name=sched_name,
                    start=sched.start_date,
                    end=sched.stop_date,
                    days=sched.daily or list(sched.weekdays.keys()),
                    source_attributes=sched_attrs,
                )
            )

        # 6. Policies (Zone policies + Global policies)
        for p in context.policies:
            self._transform_policy(p, ir, resolver, is_global=False, context_name=ctx_name)

        for gp in context.global_policies:
            self._transform_policy(gp, ir, resolver, is_global=True, context_name=ctx_name)

        # 7. Static Routes
        for idx, r in enumerate(context.routes, 1):
            self._transform_route(r, idx, ir, context_name=ctx_name)

        # 8. NAT Rules
        self._transform_nat(context, ir, resolver)

        # 9. VPN
        self._transform_vpn(context, ir)

    def _transform_address(
        self, addr, book_name: str, ir: IRConfig, context_name: str = "root"
    ) -> None:
        if context_name != "root":
            canonical_name = (
                f"{context_name}__{addr.name}"
                if book_name == "global"
                else f"{context_name}__{book_name}__{addr.name}"
            )
        else:
            canonical_name = addr.name if book_name == "global" else f"{book_name}__{addr.name}"

        requires_review = addr.disabled
        review_reasons: List[str] = []
        parse_error: Optional[str] = None
        src_attrs = {
            "junos_address_book": book_name,
            "junos_original_name": addr.name,
            **addr.source_attributes,
        }
        if addr.disabled:
            src_attrs["disabled"] = True
            review_reasons.append("Address is deactivated in Junos configuration")
        if context_name != "root":
            src_attrs["junos_context"] = context_name

        addr_kwargs: Dict[str, Any] = {
            "name": canonical_name,
            "description": addr.description,
            "source_attributes": src_attrs,
            "disabled": addr.disabled,
        }

        if addr.type == "dns-name":
            addr_kwargs["type"] = AddressType.FQDN
            addr_kwargs["fqdn"] = addr.fqdn
            if not addr.fqdn:
                requires_review = True
                review_reasons.append("Missing FQDN definition")
        elif addr.type == "range-address":
            addr_kwargs["type"] = AddressType.RANGE
            addr_kwargs["ip_range_start"] = addr.range_start
            addr_kwargs["ip_range_end"] = addr.range_end
            if not addr.range_start or not addr.range_end:
                requires_review = True
                review_reasons.append("Malformed or incomplete range address")
                parse_error = "Incomplete range address definition"
        elif addr.type == "wildcard-address":
            addr_kwargs["type"] = AddressType.WILDCARD_MASK
            addr_kwargs["wildcard_mask"] = addr.wildcard
            if not addr.wildcard:
                requires_review = True
                review_reasons.append("Missing wildcard mask")
        else:
            # ip-prefix: Never default to 0.0.0.0/0
            val = addr.prefix
            if not val:
                addr_kwargs["type"] = AddressType.NETWORK
                addr_kwargs["subnet"] = None
                requires_review = True
                review_reasons.append("Missing IP prefix definition")
                parse_error = "Missing IP prefix"
            else:
                is_host = False
                if "/" in val:
                    parts = val.split("/")
                    if len(parts) == 2 and parts[1] in ("32", "128"):
                        is_host = True
                    addr_kwargs["type"] = AddressType.HOST if is_host else AddressType.NETWORK
                    addr_kwargs["subnet"] = val
                else:
                    if ":" in val:
                        addr_kwargs["type"] = AddressType.HOST
                        addr_kwargs["subnet"] = f"{val}/128"
                    elif "." in val:
                        addr_kwargs["type"] = AddressType.HOST
                        addr_kwargs["subnet"] = f"{val}/32"
                    else:
                        addr_kwargs["type"] = AddressType.NETWORK
                        addr_kwargs["subnet"] = val
                        requires_review = True
                        review_reasons.append(f"Invalid IP prefix format: {val}")
                        parse_error = f"Invalid IP prefix format: {val}"

        addr_kwargs["requires_manual_review"] = requires_review
        addr_kwargs["review_reasons"] = review_reasons
        addr_kwargs["migration_status"] = "PARTIALLY_NORMALIZED" if requires_review else "NORMALIZED"
        if parse_error:
            addr_kwargs["parse_error"] = parse_error

        ir.addresses.append(IRAddress(**addr_kwargs))

    def _transform_address_set(
        self,
        aset,
        book_name: str,
        ir: IRConfig,
        resolver: JuniperReferenceResolver,
        context_name: str = "root",
    ) -> None:
        if context_name != "root":
            canonical_name = (
                f"{context_name}__{aset.name}"
                if book_name == "global"
                else f"{context_name}__{book_name}__{aset.name}"
            )
        else:
            canonical_name = aset.name if book_name == "global" else f"{book_name}__{aset.name}"

        members, has_cycle = resolver.expand_address_set(
            resolver.context.address_books.get(book_name, aset), aset.name
        )

        src_attrs = {
            "junos_address_book": book_name,
            "junos_original_name": aset.name,
            **aset.source_attributes,
        }
        if aset.disabled:
            src_attrs["disabled"] = True
        if context_name != "root":
            src_attrs["junos_context"] = context_name

        ir.address_groups.append(
            IRAddressGroup(
                name=canonical_name,
                members=members,
                description=aset.description,
                requires_manual_review=has_cycle or aset.disabled,
                audit_note="Cyclic address-set reference detected" if has_cycle else None,
                source_attributes=src_attrs,
            )
        )

    def _transform_application(
        self, app, ir: IRConfig, context_name: str = "root"
    ) -> None:
        canonical_name = f"{context_name}__{app.name}" if context_name != "root" else app.name
        ports: List[IRServicePort] = []
        requires_review = app.disabled
        review_reasons: List[str] = []
        unmodeled_settings: List[str] = []
        src_attrs = {**app.source_attributes}
        if app.disabled:
            src_attrs["disabled"] = True
            review_reasons.append("Application is deactivated in Junos configuration")
        if context_name != "root":
            src_attrs["junos_context"] = context_name

        for term in app.terms:
            proto_val = term.protocol
            if not proto_val:
                # Missing protocol -> do not default to TCP
                requires_review = True
                review_reasons.append("Missing protocol definition in application term")
                proto_enum = ServiceProtocol.IP
            else:
                p_lower = proto_val.lower()
                if p_lower == "tcp":
                    proto_enum = ServiceProtocol.TCP
                elif p_lower == "udp":
                    proto_enum = ServiceProtocol.UDP
                elif p_lower == "icmp":
                    proto_enum = ServiceProtocol.ICMP
                elif p_lower in ("icmp6", "icmpv6"):
                    proto_enum = ServiceProtocol.ICMPV6
                elif p_lower == "sctp":
                    proto_enum = ServiceProtocol.SCTP
                elif p_lower.isdigit():
                    proto_enum = ServiceProtocol.IP
                    requires_review = True
                    review_reasons.append(f"Numeric IP protocol ({proto_val}) requires manual review")
                    unmodeled_settings.append(f"protocol-number: {proto_val}")
                else:
                    proto_enum = ServiceProtocol.IP
                    requires_review = True
                    review_reasons.append(f"Unknown service protocol ({proto_val}) requires manual review")
                    unmodeled_settings.append(f"protocol: {proto_val}")

            dest_ports = term.destination_ports or (["any"] if proto_val else ["any"])
            src_port = term.source_ports[0] if term.source_ports else None
            if len(term.source_ports) > 1:
                requires_review = True
                review_reasons.append(f"Multiple source ports ({term.source_ports}) reduced to first port")
                unmodeled_settings.append(f"source-ports: {term.source_ports}")

            icmp_t = resolve_icmp_type(term.icmp_type)
            icmp_c = resolve_icmp_code(term.icmp_code)
            if term.icmp_type is not None and icmp_t is None:
                requires_review = True
                review_reasons.append(f"Unrecognized symbolic ICMP type: {term.icmp_type}")
                unmodeled_settings.append(f"icmp-type: {term.icmp_type}")

            if term.icmp_code is not None and icmp_c is None:
                requires_review = True
                review_reasons.append(f"Unrecognized symbolic ICMP code: {term.icmp_code}")
                unmodeled_settings.append(f"icmp-code: {term.icmp_code}")

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

        proto_num: Optional[int] = None
        for term in app.terms:
            if term.protocol and term.protocol.isdigit():
                proto_num = int(term.protocol)
                break

        ir.services.append(
            IRService(
                name=canonical_name,
                ports=ports,
                description=app.description,
                requires_manual_review=requires_review,
                audit_note="; ".join(review_reasons) if review_reasons else None,
                migration_status="PARTIALLY_NORMALIZED" if requires_review else "NORMALIZED",
                source_protocol_number=proto_num,
                source_unmodeled_semantic_settings=unmodeled_settings,
                source_attributes=src_attrs,
            )
        )

    def _transform_policy(
        self,
        pol,
        ir: IRConfig,
        resolver: JuniperReferenceResolver,
        is_global: bool,
        context_name: str = "root",
    ) -> None:
        requires_review = pol.disabled
        review_reasons: List[str] = []

        if context_name != "root":
            requires_review = True
            review_reasons.append(f"Policy in logical system '{context_name}' requires manual review")

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
                    _, _, canonical_app = resolver.resolve_application(a)
                    if canonical_app:
                        norm_svc.append(canonical_app)
                    else:
                        fallback_app = f"{context_name}__{a}" if context_name != "root" else a
                        norm_svc.append(fallback_app)
                        requires_review = True
                        review_reasons.append(f"Unresolved application reference: {a}")

        # 5. Zone mapping & Deactivated zone check
        if is_global:
            mapped_from = [
                f"{context_name}__{self.map_zone(z) or z}" if context_name != "root" else (self.map_zone(z) or z)
                for z in pol.from_zones
            ] if pol.from_zones else [IR_KEYWORD_ANY]
            mapped_to = [
                f"{context_name}__{self.map_zone(z) or z}" if context_name != "root" else (self.map_zone(z) or z)
                for z in pol.to_zones
            ] if pol.to_zones else [IR_KEYWORD_ANY]
            requires_review = True
            review_reasons.append("Global policy evaluation scope requires manual review")
        else:
            mapped_from = [
                f"{context_name}__{self.map_zone(z) or z}" if context_name != "root" else (self.map_zone(z) or z)
                for z in pol.from_zones
            ]
            mapped_to = [
                f"{context_name}__{self.map_zone(z) or z}" if context_name != "root" else (self.map_zone(z) or z)
                for z in pol.to_zones
            ]

        # Check deactivated zone reference
        for z_name in pol.from_zones + pol.to_zones:
            if z_name in resolver.context.zones and resolver.context.zones[z_name].source_attributes.get("disabled"):
                requires_review = True
                review_reasons.append(f"Referenced zone '{z_name}' is deactivated in Junos configuration")

        # Check deactivated scheduler reference
        if pol.scheduler_name:
            sched_obj = resolver.context.schedulers.get(pol.scheduler_name)
            if sched_obj and sched_obj.source_attributes.get("disabled"):
                requires_review = True
                review_reasons.append(f"Referenced scheduler '{pol.scheduler_name}' is deactivated in Junos configuration")

        # 6. Extra settings
        extra_settings: Dict[str, Any] = {
            **pol.permit_options,
            **pol.unknown_match_conditions,
            **pol.unknown_then_options,
        }
        if context_name != "root":
            extra_settings["junos_context"] = context_name
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

        pol_name = f"{context_name}__{pol.name}" if context_name != "root" else pol.name
        sched_name = (
            f"{context_name}__{pol.scheduler_name}"
            if (context_name != "root" and pol.scheduler_name)
            else pol.scheduler_name
        )
        ir.policies.append(
            IRPolicy(
                name=pol_name,
                from_zone=mapped_from,
                to_zone=mapped_to,
                source=norm_src,
                destination=norm_dst,
                service=norm_svc,
                action=act,
                source_action=src_act,
                source_address_negate_setting="exclude" if pol.source_address_excluded else None,
                destination_address_negate_setting="exclude" if pol.destination_address_excluded else None,
                schedule=sched_name,
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

    def _transform_route(
        self, r, idx: int, ir: IRConfig, context_name: str = "root"
    ) -> None:
        requires_review = r.disabled
        review_reasons: List[str] = []

        nh_val = r.next_hops[0].value if r.next_hops else None
        if not nh_val and not (r.discard or r.reject or r.receive or r.next_table):
            requires_review = True
            review_reasons.append("Route has no valid next-hop or discard action")

        is_blackhole = r.discard or r.reject

        src_attrs = {**r.source_attributes}
        if context_name != "root":
            src_attrs["junos_context"] = context_name
            requires_review = True
            review_reasons.append(f"Route in logical system '{context_name}' requires manual review")

        if r.routing_instance:
            src_attrs["junos_routing_instance"] = r.routing_instance
            requires_review = True
            review_reasons.append(
                f"Route belongs to routing-instance '{r.routing_instance}', not root static routing"
            )

        if len(r.next_hops) > 1:
            src_attrs["junos_multi_next_hops"] = [n.model_dump() for n in r.next_hops]
            requires_review = True
            review_reasons.append("Multi-next-hop ECMP route requires manual review")

        if r.disabled:
            src_attrs["disabled"] = True

        r_name = f"{context_name}__route_{idx}" if context_name != "root" else f"route_{idx}"
        ir.routes.append(
            IRRoute(
                name=r_name,
                destination=r.destination,
                next_hop=nh_val,
                administrative_distance=r.preference or (r.next_hops[0].preference if r.next_hops else None),
                metric=r.metric or (r.next_hops[0].metric if r.next_hops else None),
                route_tag=r.tag or (r.next_hops[0].tag if r.next_hops else None),
                blackhole=is_blackhole or None,
                enabled=False if r.disabled else None,
                requires_manual_review=requires_review,
                review_reasons=review_reasons,
                migration_status="PARTIALLY_NORMALIZED" if requires_review else "NORMALIZED",
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
        ctx_name = context.name

        # Source NAT
        for rs in context.nat.source_rule_sets.values():
            from_z = [
                f"{ctx_name}__{self.map_zone(z) or z}" if ctx_name != "root" else (self.map_zone(z) or z)
                for z in rs.from_context.zones
            ]
            to_z = [
                f"{ctx_name}__{self.map_zone(z) or z}" if ctx_name != "root" else (self.map_zone(z) or z)
                for z in rs.to_context.zones
            ] if rs.to_context else []

            rs_requires_review = rs.disabled
            rs_review_reasons: List[str] = []

            # Check non-zone contexts (interfaces, routing-instances)
            if rs.from_context.interfaces or rs.from_context.routing_instances:
                rs_requires_review = True
                rs_review_reasons.append("NAT from-context contains interface or routing-instance restrictions")
            if rs.to_context and (rs.to_context.interfaces or rs.to_context.routing_instances):
                rs_requires_review = True
                rs_review_reasons.append("NAT to-context contains interface or routing-instance restrictions")

            for r in rs.rules:
                requires_review = rs_requires_review or r.disabled
                review_reasons = list(rs_review_reasons)
                mode: Optional[NATTranslationMode] = None
                pool_refs: List[str] = []
                trans_src: List[str] = []
                src_attrs = {**r.source_attributes}
                act_type = r.action.get("type")

                if act_type == "pool":
                    mode = NATTranslationMode.POOL
                    pool_name = r.action.get("pool_name", "")
                    pool_refs = [pool_name]
                    if pool_name in context.nat.source_pools:
                        p_obj = context.nat.source_pools[pool_name]
                        trans_src = p_obj.addresses
                        if p_obj.ports or p_obj.source_attributes:
                            requires_review = True
                            p_info = p_obj.ports or "custom PAT/port constraints"
                            review_reasons.append(
                                f"Source NAT pool '{pool_name}' contains port/PAT constraints ({p_info}) that require manual review"
                            )
                            if p_obj.ports:
                                src_attrs["pool_ports"] = p_obj.ports
                            if p_obj.source_attributes:
                                src_attrs["pool_source_attributes"] = p_obj.source_attributes
                    else:
                        requires_review = True
                        review_reasons.append(f"Unresolved source NAT pool: {pool_name}")
                elif act_type == "interface":
                    mode = NATTranslationMode.INTERFACE_ADDRESS
                elif act_type == "off":
                    mode = NATTranslationMode.NONE
                elif not act_type:
                    requires_review = True
                    review_reasons.append("Missing source NAT translation action")
                else:
                    requires_review = True
                    review_reasons.append(f"Unknown source NAT action: {act_type}")

                # Unknown match conditions
                if r.match.unknown_match_conditions:
                    requires_review = True
                    review_reasons.append(
                        f"Unknown NAT match conditions ({r.match.unknown_match_conditions}) require manual review"
                    )

                # Source address resolution (resolve address-name against global book)
                norm_src: List[str] = []
                if r.match.source_addresses:
                    norm_src.extend(r.match.source_addresses)
                for s_name in r.match.source_address_names:
                    res = resolver.resolve_nat(s_name)
                    norm_src.append(res.name)
                    if res.is_unresolved:
                        requires_review = True
                        review_reasons.append(f"Unresolved NAT source address: {s_name}")
                if not norm_src:
                    norm_src = [IR_KEYWORD_ANY]

                # Destination address resolution
                norm_dst: List[str] = []
                if r.match.destination_addresses:
                    norm_dst.extend(r.match.destination_addresses)
                for d_name in r.match.destination_address_names:
                    res = resolver.resolve_nat(d_name)
                    norm_dst.append(res.name)
                    if res.is_unresolved:
                        requires_review = True
                        review_reasons.append(f"Unresolved NAT destination address: {d_name}")
                if not norm_dst:
                    norm_dst = [IR_KEYWORD_ANY]

                # Services / ports / protocol
                norm_svc: List[str] = []
                if r.match.applications:
                    norm_svc.extend(r.match.applications)
                
                if r.match.protocols or r.match.source_ports or r.match.destination_ports:
                    requires_review = True
                    review_reasons.append(
                        f"NAT port/protocol match criteria (protocol={r.match.protocols}, src_port={r.match.source_ports}, dst_port={r.match.destination_ports}) requires manual review"
                    )
                if not norm_svc:
                    norm_svc = [IR_KEYWORD_ANY]

                src_attrs = {**r.source_attributes}
                if r.match.unknown_match_conditions:
                    src_attrs["unknown_match_conditions"] = r.match.unknown_match_conditions
                if ctx_name != "root":
                    src_attrs["junos_context"] = ctx_name
                    requires_review = True
                    review_reasons.append(f"NAT in logical system '{ctx_name}' requires manual review")

                rule_name = f"{ctx_name}__{r.name}" if ctx_name != "root" else r.name
                ir.nat_rules.append(
                    IRNATRule(
                        name=rule_name,
                        type=NATType.SOURCE,
                        sequence=seq,
                        from_zone=from_z,
                        to_zone=to_z,
                        source=norm_src,
                        destination=norm_dst,
                        services=norm_svc,
                        source_translation_mode=mode,
                        source_pool_references=pool_refs,
                        translated_sources=trans_src,
                        description=r.description,
                        disabled=r.disabled or None,
                        requires_manual_review=requires_review,
                        review_reasons=review_reasons,
                        migration_status="PARTIALLY_NORMALIZED" if requires_review else "NORMALIZED",
                        source_attributes=src_attrs,
                    )
                )
                seq += 1

        # Destination NAT
        for rs in context.nat.destination_rule_sets.values():
            from_z = [
                f"{ctx_name}__{self.map_zone(z) or z}" if ctx_name != "root" else (self.map_zone(z) or z)
                for z in rs.from_context.zones
            ]
            to_z = [
                f"{ctx_name}__{self.map_zone(z) or z}" if ctx_name != "root" else (self.map_zone(z) or z)
                for z in rs.to_context.zones
            ] if rs.to_context else []

            rs_requires_review = rs.disabled
            rs_review_reasons: List[str] = []
            if rs.from_context.interfaces or rs.from_context.routing_instances:
                rs_requires_review = True
                rs_review_reasons.append("Destination NAT from-context contains interface or routing-instance restrictions")

            for r in rs.rules:
                requires_review = rs_requires_review or r.disabled
                review_reasons = list(rs_review_reasons)
                pool_name = r.action.get("pool_name", "")
                trans_dst = []
                if r.action.get("type") == "pool":
                    if pool_name in context.nat.destination_pools:
                        trans_dst = context.nat.destination_pools[pool_name].addresses
                    else:
                        requires_review = True
                        review_reasons.append(f"Unresolved destination NAT pool: {pool_name}")
                elif r.action.get("type") == "off":
                    pass
                elif not r.action.get("type"):
                    requires_review = True
                    review_reasons.append("Missing destination NAT translation action")
                else:
                    requires_review = True
                    review_reasons.append(f"Unknown destination NAT action: {r.action.get('type')}")

                # Unknown match conditions
                if r.match.unknown_match_conditions:
                    requires_review = True
                    review_reasons.append(
                        f"Unknown NAT match conditions ({r.match.unknown_match_conditions}) require manual review"
                    )

                norm_src = list(r.match.source_addresses)
                for s_name in r.match.source_address_names:
                    res = resolver.resolve_nat(s_name)
                    norm_src.append(res.name)
                    if res.is_unresolved:
                        requires_review = True
                        review_reasons.append(f"Unresolved destination NAT source address: {s_name}")
                if not norm_src:
                    norm_src = [IR_KEYWORD_ANY]

                norm_dst = list(r.match.destination_addresses)
                for d_name in r.match.destination_address_names:
                    res = resolver.resolve_nat(d_name)
                    norm_dst.append(res.name)
                    if res.is_unresolved:
                        requires_review = True
                        review_reasons.append(f"Unresolved destination NAT address: {d_name}")
                if not norm_dst:
                    norm_dst = [IR_KEYWORD_ANY]

                norm_svc = list(r.match.applications)
                if r.match.protocols or r.match.destination_ports or r.match.source_ports:
                    requires_review = True
                    review_reasons.append(
                        f"Destination NAT port/protocol match criteria (protocol={r.match.protocols}, dst_port={r.match.destination_ports}) requires manual review"
                    )
                if not norm_svc:
                    norm_svc = [IR_KEYWORD_ANY]

                src_attrs = {**r.source_attributes}
                if r.match.unknown_match_conditions:
                    src_attrs["unknown_match_conditions"] = r.match.unknown_match_conditions
                if ctx_name != "root":
                    src_attrs["junos_context"] = ctx_name
                    requires_review = True
                    review_reasons.append(f"Destination NAT in logical system '{ctx_name}' requires manual review")

                rule_name = f"{ctx_name}__{r.name}" if ctx_name != "root" else r.name
                ir.nat_rules.append(
                    IRNATRule(
                        name=rule_name,
                        type=NATType.DESTINATION,
                        sequence=seq,
                        from_zone=from_z,
                        to_zone=to_z,
                        source=norm_src,
                        destination=norm_dst,
                        services=norm_svc,
                        destination_pool_references=[pool_name] if pool_name else [],
                        translated_destinations=trans_dst,
                        description=r.description,
                        disabled=r.disabled or None,
                        requires_manual_review=requires_review,
                        review_reasons=review_reasons,
                        migration_status="PARTIALLY_NORMALIZED" if requires_review else "NORMALIZED",
                        source_attributes=src_attrs,
                    )
                )
                seq += 1

        # Static NAT: conservative mapping
        for rs in context.nat.static_rule_sets.values():
            from_z = [
                f"{ctx_name}__{self.map_zone(z) or z}" if ctx_name != "root" else (self.map_zone(z) or z)
                for z in rs.from_context.zones
            ]
            to_z = [
                f"{ctx_name}__{self.map_zone(z) or z}" if ctx_name != "root" else (self.map_zone(z) or z)
                for z in rs.to_context.zones
            ] if rs.to_context else []
            rs_requires_review = True
            rs_review_reasons = ["Junos static NAT requires manual review for exact bidirectional semantics"]
            if rs.from_context.interfaces or rs.from_context.routing_instances:
                rs_review_reasons.append("Static NAT from-context contains interface or routing-instance restrictions")

            for r in rs.rules:
                requires_review = True
                review_reasons = list(rs_review_reasons)
                if r.action.get("type") == "static_prefix_name":
                    review_reasons.append(f"Static NAT prefix-name '{r.action.get('prefix_name')}' requires manual review")
                if r.action.get("mapped_port"):
                    review_reasons.append(f"Static NAT mapped-port '{r.action.get('mapped_port')}' requires manual review")
                if r.match.unknown_match_conditions:
                    review_reasons.append(
                        f"Unknown NAT match conditions ({r.match.unknown_match_conditions}) require manual review"
                    )

                norm_src = list(r.match.source_addresses)
                for s_name in r.match.source_address_names:
                    res = resolver.resolve_nat(s_name)
                    norm_src.append(res.name)
                    if res.is_unresolved:
                        review_reasons.append(f"Unresolved static NAT source address: {s_name}")
                if not norm_src:
                    norm_src = [IR_KEYWORD_ANY]

                norm_dst = list(r.match.destination_addresses)
                for d_name in r.match.destination_address_names:
                    res = resolver.resolve_nat(d_name)
                    norm_dst.append(res.name)
                    if res.is_unresolved:
                        review_reasons.append(f"Unresolved static NAT destination address: {d_name}")
                if not norm_dst:
                    norm_dst = [IR_KEYWORD_ANY]

                src_attrs = {**r.source_attributes}
                if r.match.unknown_match_conditions:
                    src_attrs["unknown_match_conditions"] = r.match.unknown_match_conditions
                if ctx_name != "root":
                    src_attrs["junos_context"] = ctx_name
                    review_reasons.append(f"Static NAT in logical system '{ctx_name}' requires manual review")

                # Static NAT must NOT fabricate fake canonical translation endpoints (e.g. port:8443 or unresolved_static_target).
                # If static NAT action has a valid IP prefix (static_prefix), instantiate IRNATRule(TWICE).
                # Otherwise, the unrepresentable/incomplete rule is preserved strictly in ExtractionResult accounting.
                prefix_val = r.action.get("prefix")
                if r.action.get("type") == "static_prefix" and prefix_val:
                    rule_name = f"{ctx_name}__{r.name}" if ctx_name != "root" else r.name
                    ir.nat_rules.append(
                        IRNATRule(
                            name=rule_name,
                            type=NATType.TWICE,
                            sequence=seq,
                            from_zone=from_z,
                            to_zone=to_z,
                            source=norm_src,
                            destination=norm_dst,
                            services=r.match.applications or [IR_KEYWORD_ANY],
                            translated_sources=[prefix_val],
                            translated_destinations=[prefix_val],
                            requires_manual_review=True,
                            migration_status="PARTIALLY_NORMALIZED",
                            review_reasons=review_reasons,
                            disabled=r.disabled or None,
                            source_attributes=src_attrs,
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

            vpn_disabled = vpn.disabled
            vpn_attrs = {**vpn.source_attributes}
            if context.name != "root":
                vpn_attrs["junos_context"] = context.name

            # Check if dependent components are deactivated
            if gw and gw.source_attributes.get("disabled"):
                vpn_disabled = True
            if gw and gw.ike_policy in context.vpn.ike_policies and context.vpn.ike_policies[gw.ike_policy].source_attributes.get("disabled"):
                vpn_disabled = True
            if vpn.ipsec_policy in context.vpn.ipsec_policies and context.vpn.ipsec_policies[vpn.ipsec_policy].source_attributes.get("disabled"):
                vpn_disabled = True

            if vpn_disabled:
                vpn_attrs["disabled"] = True

            ir.vpn_tunnels.append(
                IRVPNTunnel(
                    name=f"{context.name}__{vpn.name}" if context.name != "root" else vpn.name,
                    local_interface=vpn.bind_interface,
                    peer_address=peer_ip,
                    has_psk=True if (gw and gw.ike_policy in context.vpn.ike_policies and context.vpn.ike_policies[gw.ike_policy].has_pre_shared_key) else False,
                    ike_crypto_profile=gw.ike_policy if gw else None,
                    ipsec_crypto_profile=vpn.ipsec_policy,
                    source_attributes=vpn_attrs,
                )
            )
