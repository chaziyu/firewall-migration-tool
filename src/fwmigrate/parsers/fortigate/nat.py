"""FortiGate NAT inventory and conservative, source-traceable normalization.

No target-vendor assumptions belong here. Extended NAT is inventory-ready, not
automatically deployment-ready: legacy generators cannot express all its fields.
"""

import ipaddress
import re
from collections import Counter

from fwmigrate.extraction.models import ExtractionStatus as Status, SourceObjectResult
from fwmigrate.ir.core import (
    IRAddress, IRAddressGroup, IRNATRule, IRService, IRServicePort,
    IRServiceGroup, IRAuditEntry,
)
from fwmigrate.ir.enums import AddressType, NATType, ServiceProtocol, MigrationConfidence
from fwmigrate.parsers.fortigate.extraction import sanitize_source_attributes
from fwmigrate.parsers.vendor_maps import normalize_to_ir
from fwmigrate.core.constants import IR_KEYWORD_ANY


def _values(value):
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [str(value)]


def _ipv4_span(value):
    parts = str(value).split("-")
    if len(parts) not in (1, 2):
        raise ValueError("Expected one IPv4 address or an IPv4 address range.")
    addresses = [ipaddress.IPv4Address(p.strip()) for p in parts]
    if len(addresses) == 2 and addresses[1] < addresses[0]:
        raise ValueError("Address range is reversed.")
    return str(addresses[0]) if addresses[0] == addresses[-1] else f"{addresses[0]}-{addresses[-1]}"


def _port(value, allow_any=False):
    if value is None or value == "":
        return None
    value = str(value)
    if allow_any and value == "0":
        return None
    if not re.fullmatch(r"\d+(?:-\d+)?", value):
        raise ValueError("Unsupported or malformed port range.")
    numbers = [int(n) for n in value.split("-")]
    if any(n < 1 or n > 65535 for n in numbers) or numbers[0] > numbers[-1]:
        raise ValueError("Port range is outside 1-65535 or reversed.")
    return str(numbers[0]) if numbers[0] == numbers[-1] else f"{numbers[0]}-{numbers[-1]}"


class NATExtractor:
    def __init__(self, fg, ir, zone_mapping):
        self.fg, self.ir = fg, ir
        self.report = ir.extraction
        self.records = {o.id: o for o in self.report.objects}
        self.scope = fg.scopes[0] if len(fg.scopes) == 1 else "root"
        self.zone_mapping = dict(zone_mapping)
        for zone in fg.system_zones:
            self.zone_mapping[zone.name] = zone.name
            for member in zone.interface:
                self.zone_mapping.setdefault(member, zone.name)
        self.interfaces = {i.name for i in fg.interfaces}
        self.interfaces.update(z.name for z in fg.system_zones)
        if fg.sdwan:
            self.interfaces.update(z.name for z in fg.sdwan.zones)
        self.pools = {}
        self.vips = {}
        self.groups = {}

    def record(self, item, section, sequence=0):
        if item.source_record:
            return self.records[item.source_record.id]
        # Typed callers remain supported, but cannot prove full source coverage.
        name = str(getattr(item, "id", None) or item.name)
        record = SourceObjectResult(
            id=f"{self.scope}:{section}:{name}:model", section=section,
            name=name, scope=self.scope, sequence=sequence,
            attributes=sanitize_source_attributes(item.model_dump(exclude={"source_record"}, exclude_unset=True)),
            notes=["Source object constructed programmatically; explicit source coverage is unknown."],
        )
        self.report.objects.append(record)
        self.records[record.id] = record
        return record

    def issue(self, record, message, status=Status.PARTIALLY_NORMALIZED):
        if message not in record.notes:
            record.notes.append(message)
        if record.status != Status.PARSE_ERROR:
            record.status = status
        record.blocking = True
        if status == Status.PARSE_ERROR:
            record.parsed = False

    def fields(self, record, supported):
        unknown = sorted(set(record.attributes) - set(supported) - {"_commands"})
        if unknown:
            self.issue(record, "Settings retained for review, not normalized: " + ", ".join(unknown))

    def indexed(self, items, section):
        counts = Counter((self.record(i, section).scope, i.name) for i in items)
        result = {}
        for i in items:
            record = self.record(i, section)
            if counts[record.scope, i.name] > 1:
                self.issue(record, "Duplicate source name in the same scope; no reference was guessed.", Status.PARSE_ERROR)
                continue
            result[record.scope, i.name] = i
        return result

    def run(self):
        self.pools = self.indexed(self.fg.ip_pools, "firewall ippool")
        self.vips = self.indexed(self.fg.vips, "firewall vip")
        self.groups = self.indexed(self.fg.vip_groups, "firewall vipgrp")
        for pool in self.pools.values():
            record = self.record(pool, "firewall ippool")
            self.fields(record, {"name", "startip", "endip", "type", "comments", "uuid", "arp_reply", "arp_intf", "associated_interface"})
            try:
                _ipv4_span(f"{pool.startip}-{pool.endip}")
            except ValueError:
                self.issue(record, "Invalid IPv4 pool range.", Status.PARSE_ERROR)
            if pool.type not in {"overload", "one-to-one"}:
                self.issue(record, f"Pool allocation type {pool.type!r} is inventory-only.", Status.UNSUPPORTED)
            record.notes.append("Translation resource, not an independent NAT rule. All explicit settings are retained.")
        for vip in self.vips.values():
            self.vip(vip)
        self.vip_groups()
        policy_ids = Counter((self.record(p, "firewall policy").scope, p.id) for p in self.fg.policies)
        for sequence, policy in enumerate(self.fg.policies, 1):
            record = self.record(policy, "firewall policy", sequence)
            if policy_ids[record.scope, policy.id] > 1:
                self.issue(record, "Duplicate policy ID; NAT order and linkage are ambiguous.", Status.PARSE_ERROR)
                continue
            self.policy(policy, record)
        central_ids = Counter((self.record(c, "firewall central-snat-map").scope, c.id) for c in self.fg.central_snat)
        for sequence, central in enumerate(self.fg.central_snat, 1):
            record = self.record(central, "firewall central-snat-map", sequence)
            if central_ids[record.scope, central.id] > 1:
                self.issue(record, "Duplicate central NAT ID; no rule was selected.", Status.PARSE_ERROR)
                continue
            self.central(central, record)
        for obj in self.report.objects:
            if obj.section == "system settings":
                obj.notes.append("Source mode settings retained; NAT uses central-nat and ngfw-mode where available.")
            if obj.blocking:
                self.ir.audit_entries.append(IRAuditEntry(
                    id=obj.id, category="NAT extraction", confidence=MigrationConfidence.UNSUPPORTED,
                    message=f"{obj.scope}/{obj.section}/{obj.name}: " + "; ".join(obj.notes),
                ))
        for message in self.report.blocking_issues:
            self.ir.audit_entries.append(IRAuditEntry(id="nat-source", category="NAT extraction", message=message, confidence=MigrationConfidence.UNSUPPORTED))
        if self.ir.nat_rules:
            self.report.diagnostics.append("NAT extraction is separate from target migration validation. Extended NAT generation is blocked until a target supports these semantics.")
        if not self.fg.source_version:
            self.report.diagnostics.append("FortiOS version was not provided. Defaults use the documented 7.4 baseline; review version-dependent behavior.")
        elif not self.fg.source_version.startswith("7.4."):
            self.report.diagnostics.append(f"Source version {self.fg.source_version} is outside the 7.4 reference baseline. Explicit settings are retained; defaults and behavior require version review.")

    def mode(self, scope):
        settings = self.fg.settings_by_scope.get(scope, {})
        if settings.get("ngfw_mode") == "policy-based":
            return True
        value = settings.get("central_nat", "disable")
        return value == "enable" if value in {"enable", "disable"} else None

    def interfaces_and_zones(self, names, record):
        zones = []
        for name in names:
            if name == "any":
                zones.append("any")
            elif name not in self.interfaces:
                self.issue(record, f"Unresolved interface/zone: {name}")
            elif name in self.zone_mapping:
                zones.append(self.zone_mapping[name])
        # Interface matches are preserved separately; never infer trust/untrust.
        return list(dict.fromkeys(zones))

    def refs(self, names, kind, record):
        values = [normalize_to_ir("fortigate", n) for n in names]
        objects = self.ir.addresses if kind == "address" else self.ir.services
        groups = self.ir.address_groups if kind == "address" else self.ir.service_groups
        known = {o.name for o in objects} | {g.name for g in groups} | {"any", IR_KEYWORD_ANY}
        group_map = {g.name: g.members for g in groups}
        def check(name, trail):
            if name not in known:
                self.issue(record, f"Unresolved {kind} reference: {name}")
            elif name in trail:
                self.issue(record, f"Cyclic {kind} group: {name}")
            elif name in group_map:
                for member in group_map[name]:
                    check(normalize_to_ir("fortigate", member), trail | {name})
            elif any(o.name == name and getattr(o, "requires_manual_review", False) for o in objects):
                self.issue(record, f"Referenced {kind} requires manual review: {name}")
        for name in values:
            check(name, set())
        return values

    def rule(self, record, **kwargs):
        rule = IRNATRule(
            source_id=record.id, source_section=record.section, scope_id=record.scope,
            sequence=record.sequence, migration_eligible=False,
            requires_manual_review=record.blocking, notes=list(record.notes), **kwargs,
        )
        self.ir.nat_rules.append(rule)
        record.canonical_ids.append(rule.name)
        if not record.blocking:
            record.status = Status.NORMALIZED
        return rule

    def source_translation(self, record, pool_names, interfaces):
        values, modes = [], []
        for name in pool_names:
            pool = self.pools.get((record.scope, name))
            if not pool:
                self.issue(record, f"Unresolved IP pool reference: {name}")
                continue
            pool_record = self.record(pool, "firewall ippool")
            pool_record.references.append(record.id)
            if pool_record.blocking:
                self.issue(record, f"IP pool {name} has unsupported or invalid settings.")
            try:
                values.append(_ipv4_span(f"{pool.startip}-{pool.endip}"))
            except ValueError:
                self.issue(record, f"Invalid translated range in pool {name}.")
            modes.append(pool.type)
            associated = pool_record.attributes.get("associated_interface")
            if associated and associated not in interfaces:
                self.issue(record, f"Pool {name} associated interface needs routing/interface resolution.")
        if not pool_names and (not interfaces or "any" in interfaces):
            self.issue(record, "Interface-address SNAT needs a resolvable outgoing interface.")
        return dict(
            translated_source=values[0] if len(values) == 1 else None,
            translated_sources=values, pool_references=pool_names,
            interface_address=not pool_names,
            translation_mode=(modes[0] if len(set(modes)) == 1 else "pool-selection") if pool_names else "interface-address",
        )

    def service_match(self, names, record):
        services = self.refs(names, "service", record)
        if not services:
            self.issue(record, "Missing original service match.")
            return "unresolved-service", []
        if len(services) == 1:
            return services[0], services
        name = f"nat_services_{record.scope}_{record.name}_{record.sequence}"
        if any(s.name == name for s in self.ir.services + self.ir.service_groups):
            self.issue(record, "Generated NAT service-group name conflicts with a source object.")
        else:
            self.ir.service_groups.append(IRServiceGroup(name=name, members=services))
        return name, services

    def policy(self, policy, record):
        # Link VIPs even when SNAT is disabled. This is provenance, not permission.
        def link(name, visited):
            if name in visited:
                self.issue(record, f"Cyclic VIP group reference: {name}")
                return
            vip = self.vips.get((record.scope, name))
            group = self.groups.get((record.scope, name))
            if vip:
                self.record(vip, "firewall vip").references.append(record.id)
            if group:
                self.record(group, "firewall vipgrp").references.append(record.id)
                for member in group.member:
                    link(member, visited | {name})
        for name in policy.dstaddr:
            link(name, set())
        if self.mode(record.scope) is None:
            self.issue(record, "Unknown central NAT mode; policy NAT was not guessed.")
            return
        if self.mode(record.scope):
            record.notes.append("Central NAT mode: policy NAT flags are retained but do not generate SNAT rules.")
            return
        if policy.nat not in {"enable", "disable"} or policy.ippool not in {"enable", "disable"}:
            self.issue(record, "Invalid NAT or IP pool enable/disable setting.", Status.PARSE_ERROR)
            return
        if policy.action not in {"accept", "deny", "ipsec"}:
            self.issue(record, "Unsupported policy action; no SNAT eligibility was guessed.", Status.UNSUPPORTED)
            return
        if policy.nat != "enable" or policy.action != "accept":
            record.notes.append("No policy SNAT rule: NAT is disabled or the policy does not accept traffic.")
            return
        policy_fields = set(type(policy).model_fields) - {"source_record"}
        self.fields(record, policy_fields | {"uuid", "fixedport"})
        if policy.internet_service != "disable":
            self.issue(record, "Internet-service policy matching requires review; NAT does not replace it with address/service ANY.")
        if record.attributes.get("fixedport", "disable") not in {"enable", "disable"}:
            self.issue(record, "Invalid fixedport setting.", Status.PARSE_ERROR)
        source = self.refs(policy.srcaddr, "address", record)
        destination = self.refs(policy.dstaddr, "address", record)
        if not source or not destination or not policy.srcintf or not policy.dstintf:
            self.issue(record, "Missing policy address or interface match; no any fallback was applied.")
        from_zone = self.interfaces_and_zones(policy.srcintf, record)
        to_zone = self.interfaces_and_zones(policy.dstintf, record)
        service, original_services = self.service_match(policy.service, record)
        if policy.schedule != "always" and not any(s.name == policy.schedule for s in self.ir.schedules):
            self.issue(record, f"Unresolved schedule: {policy.schedule}")
        if policy.status not in {"enable", "disable"}:
            self.issue(record, "Invalid policy status.", Status.PARSE_ERROR)
        if policy.ippool == "enable" and not policy.poolname:
            self.issue(record, "IP pool is enabled but poolname is missing.")
            translation = dict(translation_mode="unresolved-pool")
        else:
            translation = self.source_translation(record, policy.poolname if policy.ippool == "enable" else [], policy.dstintf)
        if any((record.scope, name) in self.vips or (record.scope, name) in self.groups for name in policy.dstaddr):
            self.issue(record, "Combined SNAT/DNAT requires translation-stage validation; both source settings are retained.")
        self.rule(record, name=f"SNAT_{record.scope}_{policy.id}", type=NATType.SOURCE,
                  source_policy=str(policy.id), enabled=policy.status == "enable",
                  source=source, destination=destination, from_zone=from_zone, to_zone=to_zone,
                  source_interfaces=policy.srcintf, destination_interfaces=policy.dstintf,
                  service=service, original_services=original_services, schedule=policy.schedule,
                  port_preserve=record.attributes.get("fixedport") == "enable",
                  description=policy.comments, **translation)

    def vip(self, vip):
        record = self.record(vip, "firewall vip")
        self.fields(record, {"name", "extip", "mappedip", "extintf", "portforward", "extport", "mappedport", "protocol", "comment", "type", "src_filter", "srcintf_filter", "status", "uuid", "arp_reply"})
        if vip.status not in {"enable", "disable"}:
            self.issue(record, "Invalid VIP status.", Status.PARSE_ERROR)
        if vip.type != "static-nat":
            self.issue(record, f"VIP type {vip.type!r} is inventory-only.", Status.UNSUPPORTED)
            return
        try:
            public = _ipv4_span(vip.extip)
            mapped = [_ipv4_span(v) for v in vip.mappedip.split()]
            if not mapped:
                raise ValueError()
        except ValueError:
            self.issue(record, "Invalid or unsupported VIP address mapping.", Status.PARSE_ERROR)
            return
        if len(mapped) != 1:
            self.issue(record, "Multiple mapped addresses retained; allocation semantics need manual review.")
        if public == "0.0.0.0":
            self.issue(record, "Interface-derived VIP external address retained; not converted into a 0.0.0.0 host.")
        elif any(a.name == vip.name for a in self.ir.addresses + self.ir.address_groups):
            self.issue(record, "VIP name conflicts with an existing address object; no object was overwritten.")
        else:
            if "-" in public:
                start, end = public.split("-")
                self.ir.addresses.append(IRAddress(name=vip.name, type=AddressType.RANGE, ip_range_start=start, ip_range_end=end))
            else:
                self.ir.addresses.append(IRAddress(name=vip.name, type=AddressType.HOST, subnet=public + "/32"))
        if "-" in public or any("-" in v for v in mapped):
            self.issue(record, "Address ranges retained exactly; range-to-range allocation requires review.")
        sources = vip.src_filter or ["any"]
        for source in vip.src_filter:
            try:
                ipaddress.ip_network(source, strict=False)
            except ValueError:
                self.issue(record, "Invalid VIP source filter.", Status.PARSE_ERROR)
        interfaces = vip.srcintf_filter or [vip.extintf]
        from_zone = self.interfaces_and_zones(interfaces, record)
        if vip.srcintf_filter and vip.extintf != "any" and vip.extintf not in vip.srcintf_filter:
            self.issue(record, "VIP external interface and source-interface filter need intersection review.")
        elif vip.srcintf_filter and vip.extintf != "any" and vip.srcintf_filter != [vip.extintf]:
            self.issue(record, "VIP external interface and multi-interface filter require intersection review.")
        service, original_port, translated_port = "any", None, None
        protocol = vip.protocol.lower() if vip.portforward == "enable" else "any"
        if vip.portforward not in {"enable", "disable"}:
            self.issue(record, "Invalid VIP portforward setting.", Status.PARSE_ERROR)
        if vip.portforward == "enable":
            try:
                original_port = _port(vip.extport)
                translated_port = _port(vip.mappedport) if vip.mappedport is not None else None
                if original_port is None or translated_port is None:
                    raise ValueError()
            except ValueError:
                self.issue(record, "Missing or invalid VIP original/translated port; no port was guessed.", Status.PARSE_ERROR)
            if protocol not in {"tcp", "udp", "sctp"}:
                self.issue(record, f"Unsupported VIP protocol: {protocol}", Status.UNSUPPORTED)
                service = "unresolved-vip-service"
            elif original_port:
                service = f"svc_vip_{record.scope}_{vip.name}_{protocol}_{original_port}"
                if any(s.name == service for s in self.ir.services + self.ir.service_groups):
                    self.issue(record, "Generated VIP service name conflicts with an existing object.")
                elif protocol in {p.value for p in ServiceProtocol}:
                    self.ir.services.append(IRService(name=service, ports=[IRServicePort(protocol=ServiceProtocol(protocol), port=original_port)]))
                else:
                    self.issue(record, f"Protocol {protocol} cannot be normalized by the service model.")
            else:
                service = "unresolved-vip-service"
        record.notes.append("VIP translation definition; firewall policy permissions are separate. See source-policy references in NAT Inventory.")
        self.rule(record, name=f"DNAT_{record.scope}_{vip.name}", type=NATType.DESTINATION,
                  source=sources, destination=[vip.name], original_destination_values=[public],
                  translated_destination=mapped[0] if len(mapped) == 1 else None,
                  translated_destinations=mapped, translated_port=translated_port,
                  source_interfaces=interfaces, from_zone=from_zone, service=service,
                  protocol=protocol, original_destination_port=original_port,
                  translation_mode="port-forward" if vip.portforward == "enable" else "static-destination",
                  enabled=vip.status == "enable", description=vip.comment)

    def vip_groups(self):
        for group in self.groups.values():
            record = self.record(group, "firewall vipgrp")
            self.fields(record, {"name", "interface", "member", "uuid", "comments", "color"})
            for member in group.member:
                vip = self.vips.get((record.scope, member))
                if not vip:
                    self.issue(record, f"Unresolved VIP group member: {member}")
                elif self.record(vip, "firewall vip").blocking:
                    self.issue(record, f"VIP group member requires review: {member}")
            if any(a.name == group.name for a in self.ir.addresses + self.ir.address_groups):
                self.issue(record, "VIP group name conflicts with an address or group.")
            else:
                self.ir.address_groups.append(IRAddressGroup(name=group.name, members=list(group.member)))
                record.canonical_ids.append(group.name)
            record.notes.append("VIP group membership preserved; this object is not an independent NAT rule.")

    def central(self, central, record):
        active = self.mode(record.scope)
        if active is None:
            self.issue(record, "Unknown central NAT mode.")
            return
        if not active:
            record.notes.append("Central NAT is disabled in this scope; rule retained as inactive inventory.")
            return
        self.fields(record, set(type(central).model_fields) - {"source_record"} | {"uuid"})
        if central.type != "ipv4":
            self.issue(record, "IPv6/transition central NAT retained for manual review.", Status.UNSUPPORTED)
            return
        if central.nat not in {"enable", "disable"} or central.status not in {"enable", "disable"}:
            self.issue(record, "Invalid central NAT enable/status setting.", Status.PARSE_ERROR)
            return
        if central.port_preserve not in {"enable", "disable"}:
            self.issue(record, "Invalid central NAT port-preserve setting.", Status.PARSE_ERROR)
        source = self.refs(central.orig_addr, "address", record)
        destination = self.refs(central.dst_addr, "address", record)
        if not source or not destination or not central.srcintf or not central.dstintf:
            self.issue(record, "Missing central NAT match fields; no any fallback was applied.")
        from_zone = self.interfaces_and_zones(central.srcintf, record)
        to_zone = self.interfaces_and_zones(central.dstintf, record)
        translation = self.source_translation(record, central.nat_ippool, central.dstintf) if central.nat == "enable" else dict(translation_mode="identity")
        srcport, dstport, natport = None, None, None
        try:
            srcport = _port(central.orig_port, True)
            dstport = _port(central.dst_port, True)
            natport = _port(central.nat_port, True)
        except ValueError:
            self.issue(record, "Invalid central NAT port fields; original values retained.", Status.PARSE_ERROR)
        protocol = {0: "any", 6: "tcp", 17: "udp", 132: "sctp"}.get(central.protocol, str(central.protocol))
        service = "any"
        if dstport:
            if protocol in {"tcp", "udp"}:
                service = f"svc_central_{record.scope}_{central.id}_{protocol}_{dstport}"
                if any(s.name == service for s in self.ir.services + self.ir.service_groups):
                    self.issue(record, "Generated central NAT service name conflicts with a source object.")
                else:
                    self.ir.services.append(IRService(name=service, ports=[IRServicePort(protocol=ServiceProtocol(protocol), port=dstport)]))
            else:
                self.issue(record, "Destination-port match with a non-TCP/UDP protocol needs review.")
        self.rule(record, name=f"CENTRAL_SNAT_{record.scope}_{central.id}", type=NATType.SOURCE,
                  source=source, destination=destination, enabled=central.status == "enable",
                  source_interfaces=central.srcintf, destination_interfaces=central.dstintf,
                  from_zone=from_zone, to_zone=to_zone, protocol=protocol, service=service,
                  original_source_port=srcport, original_destination_port=dstport,
                  translated_source_port=natport, port_preserve=central.port_preserve == "enable",
                  description=central.comments, **translation)


def extract_nat(fg, ir, zone_mapping):
    NATExtractor(fg, ir, zone_mapping).run()
