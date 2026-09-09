"""Static NAT relationships and bounded traffic analysis over parsed source data.

No CLI parsing or target generation happens here. UNKNOWN is intentional for
dynamic matches, incomplete scopes, central-policy composition and routing.
"""

from collections import Counter
from dataclasses import dataclass
from itertools import combinations

from fwmigrate.analysis.intervals import RFC1918, display, intersect, ipv4, merge, size, subtract
from fwmigrate.analysis.nat_models import (
    NATAnalysis, NATDiagnostic, NATInventoryItem, NATPolicySummary, NATTrafficCoverage,
)
from fwmigrate.parsers.fortigate.builtin_services import BUILTIN_PORTS, BUILTIN_SERVICES
from fwmigrate.parsers.fortigate.nat import POOL_FIELDS, POOL_TYPES, _port


@dataclass
class PolicyFacts:
    policy: object
    record: object
    source: list | None
    destination: list | None
    services: frozenset | None
    certain: bool


def contains(outer, inner):
    return not subtract(inner, outer)


def tokens_cover(outer, inner, wildcard="any"):
    return bool(outer and inner) and (wildcard in outer or set(inner).issubset(outer))


class NATAnalyzer:
    def __init__(self, extractor):
        self.ex = extractor
        self.fg, self.ir, self.report = extractor.fg, extractor.ir, extractor.report
        self.result = NATAnalysis()
        self.addresses = self.unique(self.fg.addresses + self.fg.address_groups)
        self.services = self.unique(self.fg.services + self.fg.service_groups)
        self.ambiguous_addresses = {n for n, count in Counter(o.name for o in self.fg.addresses + self.fg.address_groups).items() if count > 1}
        self.ambiguous_services = {n for n, count in Counter(o.name for o in self.fg.services + self.fg.service_groups).items() if count > 1}
        self.interfaces = self.unique(self.fg.interfaces)
        self.zones = {z.name: z.interface for z in self.fg.system_zones}
        if self.fg.sdwan:
            for zone in self.fg.sdwan.zones:
                self.zones[zone.name] = [m.interface for m in self.fg.sdwan.members if m.zone == zone.name]
        self.inventory = {}
        self.facts = []
        self.result.limitations = [
            "Effective means configuration-eligible, not live traffic, routing reachability or target migration readiness.",
            "Traffic rows cover source/destination/service/ingress/egress domains declared by policies, not every possible network path.",
            "Percentages measure source-address coverage within the displayed destination/service domain; they are not session or port percentages.",
            "VPN exemptions are configuration intent; selectors, return routes and tunnel health still need verification.",
            "Central NAT composition, dynamic/FQDN/negated matches, schedules and incomplete scopes require review.",
            "Known predefined services are recognized by name; missing definitions are not fabricated as custom IR services.",
        ]

    @staticmethod
    def unique(items):
        counts = Counter(o.name for o in items)
        return {o.name: o for o in items if counts[o.name] == 1}

    def diag(self, code, scope, severity, status, category, objects, finding, action):
        diagnostic = NATDiagnostic(diagnostic_id=code, scope=scope, severity=severity, status=status,
                                   category=category, objects=objects, finding=finding, recommended_action=action)
        if diagnostic not in self.result.diagnostics:
            self.result.diagnostics.append(diagnostic)

    def address(self, names, trail=frozenset()):
        if not names:
            return None
        spans = []
        for name in names:
            obj = self.addresses.get(name)
            if name in trail or name in self.ambiguous_addresses:
                return None
            if obj is None:
                if name in {"all", "any"}:
                    spans += ipv4("0.0.0.0/0")
                    continue
                return None
            attrs = obj.source_attributes
            if set(attrs) - set(type(obj).model_fields) - {"uuid", "color", "associated_interface", "allow_routing"}:
                return None
            if hasattr(obj, "member"):
                nested = self.address(obj.member, trail | {name})
                if nested is None:
                    return None
                spans += nested
            else:
                try:
                    if obj.type == "ipmask" and obj.subnet and not obj.is_ipv6:
                        spans += ipv4(obj.subnet)
                    elif obj.type == "iprange" and obj.start_ip and obj.end_ip:
                        spans += ipv4(f"{obj.start_ip}-{obj.end_ip}")
                    else:
                        return None
                except ValueError:
                    return None
        return merge(spans)

    def service_names(self, names, trail=frozenset()):
        if not names:
            return None
        resolved = set()
        for name in names:
            obj = self.services.get(name)
            if name in trail or name in self.ambiguous_services:
                return None
            if obj is not None:
                if set(obj.source_attributes) - set(type(obj).model_fields) - {"uuid", "color", "category"}:
                    return None
                if hasattr(obj, "member"):
                    nested = self.service_names(obj.member, trail | {name})
                    if nested is None:
                        return None
                    resolved.update(nested)
                else:
                    if not (obj.tcp_portrange or obj.udp_portrange or obj.protocol.lower() in {"icmp", "ip"}):
                        return None
                    try:
                        for value in (obj.tcp_portrange, obj.udp_portrange):
                            for term in (value or "").split():
                                for interval in term.split(":"):
                                    _port(interval)
                    except ValueError:
                        return None
                    resolved.add(name)
            elif name in BUILTIN_SERVICES:
                resolved.add(name)
            else:
                return None
        return frozenset(resolved)

    def service_ports(self, names):
        """Known transport-port domains. Source-port/ICMP details stay unknown."""
        if names is None:
            return None
        ports = {}
        for name in names:
            obj = self.services.get(name)
            if obj is None:
                known = BUILTIN_PORTS.get(name)
                if known is None:
                    return None
            elif obj.protocol.lower() == "ip" and obj.protocol_number in (None, 0):
                known = {"any": [(0, 65535)]}
            else:
                known = {}
                try:
                    for protocol, value in (("tcp", obj.tcp_portrange), ("udp", obj.udp_portrange)):
                        if value and ":" in value:
                            return None
                        for term in (value or "").split():
                            numbers = [int(n) for n in _port(term).split("-")]
                            known.setdefault(protocol, []).append((numbers[0], numbers[-1]))
                except (ValueError, AttributeError):
                    return None
                if not known:
                    return None
            for protocol, spans in known.items():
                ports.setdefault(protocol, []).extend(spans)
        return {protocol: merge(spans) for protocol, spans in ports.items()}

    def service_relation(self, outer, inner):
        if outer is None or inner is None:
            return "unknown"
        if set(inner).issubset(outer):
            return "full"
        left, right = self.service_ports(outer), self.service_ports(inner)
        if left is None or right is None:
            return "partial"
        if "any" in left:
            return "full"
        if "any" in right:
            return "partial"
        if not any(intersect(left.get(proto, []), spans) for proto, spans in right.items()):
            return "disjoint"
        return "full" if all(contains(left.get(proto, []), spans) for proto, spans in right.items()) else "partial"

    def interface_members(self, names):
        result = set()
        for name in names:
            result.update(self.zones.get(name, [name]))
        return result

    def egress_type(self, name):
        members = self.interface_members([name])
        kinds = set()
        for member in members:
            intf = self.interfaces.get(member)
            tunnel = next((p for p in self.fg.phase1_interfaces if p.name == member), None)
            if tunnel and (not intf or intf.status == "up"):
                kinds.add("VPN")
                continue
            if not intf or intf.status != "up":
                return "UNKNOWN"
            if intf.type == "tunnel" and any(p.name == member for p in self.fg.phase1_interfaces):
                kinds.add("VPN")
            elif intf.role == "wan":
                kinds.add("INTERNET")
            elif intf.role in {"lan", "dmz"}:
                kinds.add("INTERNAL")
            else:
                kinds.add("UNKNOWN")
        return next(iter(kinds)) if len(kinds) == 1 else "UNKNOWN"

    def scope_complete(self, scope):
        return (len(self.fg.scopes) <= 1 and not self.report.blocking_issues
                and self.report.unclassified_relevant_items == 0
                and not any(o.scope == scope and not o.parsed for o in self.report.objects))

    def build_facts(self):
        for index, p in enumerate(self.fg.policies, 1):
            r = self.ex.record(p, "firewall policy", index)
            # Analyze no-NAT policies too, without turning reporting-only checks
            # into new migration blockers for unrelated legacy policy consumers.
            validation = r.model_copy(deep=True)
            self.ex.refs(p.service, "service", validation)
            r.notes = list(dict.fromkeys(r.notes + validation.notes))
            r.reference_settings.update(validation.reference_settings)
            allowed = set(type(p).model_fields) | {"uuid", "policyid", "fixedport", "comments", "name"}
            certain = (r.parsed and not validation.blocking and not (set(r.attributes) - allowed - {"_commands"})
                       and p.status in {"enable", "disable"} and p.action in {"accept", "deny"}
                       and p.nat in {"enable", "disable"} and p.ippool in {"enable", "disable"}
                       and p.schedule == "always" and p.internet_service == "disable"
                       and p.srcintf and p.dstintf
                       and all(n in self.ex.interfaces or n == "any" for n in p.srcintf + p.dstintf))
            self.facts.append(PolicyFacts(p, r, self.address(p.srcaddr), self.address(p.dstaddr),
                                          self.service_names(p.service), bool(certain)))

    def resource_inventory(self):
        for r in self.report.objects:
            if r.section not in {"firewall ippool", "firewall vip", "firewall vipgrp"}:
                continue
            is_pool = r.section == "firewall ippool"
            a = r.attributes
            refs = [f for f in self.facts if f.record.id in r.references]
            # Keep configured pool references even when policy NAT is disabled/inactive.
            if is_pool:
                refs = [f for f in self.facts if f.record.scope == r.scope and r.name in f.policy.poolname]
            active = [str(f.policy.id) for f in refs if f.policy.status == "enable"]
            disabled = [str(f.policy.id) for f in refs if f.policy.status == "disable"]
            other = [ref for ref in r.references if ref not in {f.record.id for f in refs}]
            usage = "ACTIVE" if active else "DISABLED_ONLY" if disabled else "UNUSED" if is_pool else "UNREFERENCED"
            if any(f.policy.status not in {"enable", "disable"} for f in refs) or not self.scope_complete(r.scope):
                usage = "UNKNOWN"
            if other and not refs:
                usage = "CENTRAL_REFERENCED"
            validity = "INVALID" if not r.parsed else "UNKNOWN" if r.blocking else "VALID"
            pool = self.ex.pools.get((r.scope, r.name))
            if is_pool and pool and (pool.type not in POOL_TYPES or set(a) - POOL_FIELDS - {"_commands"}):
                validity = "UNKNOWN" if r.parsed else "INVALID"
            if pool and pool.type == "fixed-port-range" and not (pool.source_startip and pool.source_endip):
                validity = "UNKNOWN"
            item = NATInventoryItem(
                source_id=r.id, scope=r.scope, object_type="IP_POOL" if is_pool else "VIP" if r.section == "firewall vip" else "VIP_GROUP",
                name=r.name, nat_role="SNAT_RESOURCE" if is_pool else "DNAT_RESOURCE",
                subtype=str(a.get("type", "overload" if is_pool else "static-nat")),
                external_mapping=f"{a.get('startip', '')}-{a.get('endip', '')}" if is_pool else str(a.get("extip", "")),
                internal_mapping=f"{a.get('source_startip', '')}-{a.get('source_endip', '')}" if is_pool else str(a.get("mappedip", "")),
                interface=[str(a[k]) for k in ("associated_interface", "extintf", "interface") if a.get(k)],
                active_policy_refs=list(dict.fromkeys(active)), disabled_policy_refs=list(dict.fromkeys(disabled)),
                other_refs=other, usage_state=usage, source_validity=validity,
                migration_compatibility="SOURCE_VALID_TARGET_UNSUPPORTED" if validity == "VALID" and pool and pool.type in {"fixed-port-range", "port-block-allocation"} else "REVIEW_REQUIRED",
                notes=["Usage describes configured references, not session activity. Unused objects can still have ARP/local-address effects."],
            )
            self.inventory[r.id] = item
            self.result.inventory.append(item)
            if is_pool and usage in {"UNUSED", "DISABLED_ONLY"}:
                self.diag("NAT-005" if usage == "UNUSED" else "NAT-006", r.scope, "LOW", "WARN", usage, [r.name],
                          "IP pool has no firewall policy references." if usage == "UNUSED" else "IP pool is referenced only by disabled firewall policies.",
                          "Confirm ownership and intended use before changing or removing the pool.")
            if not is_pool and r.section == "firewall vip" and usage in {"UNREFERENCED", "DISABLED_ONLY"}:
                self.diag("NAT-007", r.scope, "LOW", "WARN", "CONFIGURED_NOT_EFFECTIVE", [r.name],
                          "VIP is configured but has no enabled referencing firewall policy.",
                          "Verify whether the VIP is intentional; review permissions and ARP effects before removal.")

    def translation(self, f):
        p, r = f.policy, f.record
        # A relevant VIP can affect outbound SNAT precedence. Unrelated VIPs
        # must not downgrade every SNAT policy in a scope.
        for (scope, _), vip in self.ex.vips.items():
            if scope != r.scope or vip.status != "enable":
                continue
            attrs = self.ex.record(vip, "firewall vip").attributes
            if vip.portforward == "enable" and attrs.get("nat_source_vip") != "enable":
                continue
            if vip.extintf != "any" and vip.extintf not in self.interface_members(p.dstintf):
                continue
            try:
                mapped = merge(span for value in vip.mappedip.split() for span in ipv4(value))
            except ValueError:
                return None
            if f.source is None or intersect(f.source, mapped):
                return None
        if p.ippool == "enable":
            if not p.poolname:
                return None
            values = []
            for name in p.poolname:
                pool = self.ex.pools.get((r.scope, name))
                if pool is None:
                    return None
                record = self.ex.record(pool, "firewall ippool")
                item = self.inventory.get(record.id)
                if not item or item.source_validity != "VALID":
                    return None
                associated = record.attributes.get("associated_interface")
                if associated and associated not in p.dstintf:
                    return None
                if pool.type == "fixed-port-range":
                    if f.source is None or not contains(ipv4(f"{pool.source_startip}-{pool.source_endip}"), f.source):
                        return None
                values.append(f"{name}: {pool.startip}-{pool.endip} ({pool.type})")
            return "; ".join(values) if len(values) == 1 else None
        if p.ippool != "disable" or "any" in p.dstintf:
            return None
        return "Outgoing interface address: " + ", ".join(p.dstintf)

    def match_relation(self, outer, inner, egress):
        """disjoint/full/partial/unknown for all dimensions except source IPv4."""
        if outer.record.scope != inner.record.scope:
            return "disjoint"
        oi, ii = self.interface_members(outer.policy.srcintf), self.interface_members(inner.policy.srcintf)
        oe = self.interface_members(outer.policy.dstintf)
        target = self.interface_members([egress])
        if not ("any" in oe or oe & target) or not ("any" in oi or "any" in ii or oi & ii):
            return "disjoint"
        if outer.destination is not None and inner.destination is not None and not intersect(outer.destination, inner.destination):
            return "disjoint"
        if not outer.certain or outer.destination is None or inner.destination is None or outer.services is None or inner.services is None:
            return "unknown"
        service_relation = self.service_relation(outer.services, inner.services)
        if service_relation == "disjoint":
            return "disjoint"
        full = (contains(outer.destination, inner.destination)
                and service_relation == "full"
                and tokens_cover(oi, ii) and tokens_cover(oe, target))
        # Different service names can overlap in ports. Never assume disjointness.
        return "full" if full else "partial"

    def policy_state(self, f, kind):
        p = f.policy
        if not f.certain or f.source is None or f.services is None or f.destination is None or not self.scope_complete(f.record.scope):
            return "UNKNOWN", None
        if self.ex.mode(f.record.scope) is not False or kind == "UNKNOWN":
            return "UNKNOWN", None
        if p.action != "accept":
            return "NO_MATCH", None
        if p.nat == "enable":
            translation = self.translation(f)
            return ("COVERED", translation) if translation else ("UNKNOWN", None)
        if kind == "VPN" and f.destination and contains(RFC1918, f.destination):
            return "EXEMPT", "Identity / intentional no-NAT VPN policy"
        if kind == "INTERNET" and f.source and contains(RFC1918, f.source) and not contains(RFC1918, f.destination):
            return "NOT_TRANSLATED", "No source NAT"
        return "UNKNOWN", None

    def policy_reachability(self, candidate, rule):
        """Earlier accepts and denies both consume first-match policy domains."""
        any_remaining, ambiguous = False, False
        for egress in candidate.policy.dstintf:
            remaining = list(candidate.source)
            for prior in self.facts:
                if prior is candidate:
                    break
                if prior.policy.status == "disable":
                    continue
                relation = self.match_relation(prior, candidate, egress)
                overlap = intersect(remaining, prior.source) if prior.source is not None else remaining
                if relation == "disjoint" or not overlap:
                    continue
                if relation == "full" and prior.source is not None:
                    remaining = subtract(remaining, overlap)
                else:
                    ambiguous = True
            any_remaining |= bool(remaining)
        if not any_remaining:
            rule.effective, rule.analysis_status = False, "SHADOWED"
        elif ambiguous:
            rule.effective, rule.analysis_status = None, "REVIEW_REQUIRED"

    def vip_policy_eligible(self, vip, f):
        """Existence of a matching configured flow; mapped ports are post-DNAT."""
        if not vip or not f.certain or f.source is None:
            return None
        ingress = self.interface_members(f.policy.srcintf)
        allowed = set(vip.srcintf_filter) if vip.srcintf_filter else {"any"}
        if vip.extintf != "any":
            allowed = {vip.extintf} if "any" in allowed else allowed & {vip.extintf}
        if not allowed or not ("any" in allowed or "any" in ingress or allowed & ingress):
            return False
        if vip.src_filter:
            try:
                filters = merge(span for value in vip.src_filter for span in ipv4(value))
                if not intersect(filters, f.source):
                    return False
            except ValueError:
                return None
        ports = self.service_ports(f.services)
        if ports is None:
            return None
        if "any" not in ports and vip.portforward == "enable":
            try:
                numbers = [int(n) for n in _port(vip.mappedport).split("-")]
                if not intersect(ports.get(vip.protocol.lower(), []), [(numbers[0], numbers[-1])]):
                    return False
            except (ValueError, AttributeError):
                return None
        # Conservative about preceding inbound rules: VIP precedence/match-vip
        # and translated-address policies need a dedicated packet-stage solver.
        for prior in self.facts:
            if prior is f:
                break
            if prior.record.scope != f.record.scope or prior.policy.status == "disable":
                continue
            if not (self.interface_members(prior.policy.srcintf) & ingress or "any" in prior.policy.srcintf):
                continue
            if set(prior.policy.dstaddr) & set(f.policy.dstaddr) or "all" in prior.policy.dstaddr:
                if prior.source is None or intersect(prior.source, f.source):
                    return None
        return True

    def effective_rules(self):
        by_record = {f.record.id: f for f in self.facts}
        for rule in self.ir.nat_rules:
            r = self.ex.records.get(rule.source_id)
            if not rule.enabled:
                rule.effective, rule.analysis_status = False, "DISABLED"
                continue
            if not r or not self.scope_complete(r.scope) or not r.parsed:
                rule.effective, rule.analysis_status = None, "REVIEW_REQUIRED"
                continue
            f = by_record.get(r.id)
            if f:
                valid = f.certain and f.source is not None and f.destination is not None and f.services is not None and self.translation(f) is not None
                rule.effective, rule.analysis_status = (True, "ACTIVE") if valid else (None, "REVIEW_REQUIRED")
                if valid:
                    self.policy_reachability(f, rule)
            elif r.section == "firewall vip":
                refs = [f for f in self.facts if f.record.id in r.references and f.policy.status == "enable" and f.policy.action == "accept"]
                if not refs:
                    rule.effective, rule.analysis_status = False, "CONFIGURED_NOT_EFFECTIVE"
                else:
                    vip = self.ex.vips.get((r.scope, r.name))
                    # A policy reference alone cannot prove matching services or ingress.
                    eligibility = [self.vip_policy_eligible(vip, f) for f in refs] if vip else [None]
                    if self.ex.mode(r.scope) is not False or r.blocking:
                        rule.effective, rule.analysis_status = None, "REVIEW_REQUIRED"
                    elif True in eligibility:
                        rule.effective, rule.analysis_status = True, "ACTIVE"
                    elif None in eligibility:
                        rule.effective, rule.analysis_status = None, "REVIEW_REQUIRED"
                    else:
                        rule.effective, rule.analysis_status = False, "CONFIGURED_NOT_EFFECTIVE"
                        self.diag("NAT-012", r.scope, "HIGH", "FAIL", "VIP_POLICY_MATCH", [r.name] + [f.policy.name or str(f.policy.id) for f in refs],
                                  "Enabled referencing policies do not match this VIP's ingress/source filters or post-DNAT destination service.",
                                  "Check the mapped destination port and protocol, permitted source and ingress; correct the intended specific policy service, not a blanket ALL rule.")
            else:
                rule.effective, rule.analysis_status = None, "REVIEW_REQUIRED"
            if rule.translation_mode == "identity":
                rule.analysis_status = "NAT_EXEMPT" if rule.effective else "REVIEW_REQUIRED"

    def traffic(self):
        seen = set()
        for candidate in self.facts:
            p, r = candidate.policy, candidate.record
            if p.action != "accept":
                continue
            # Outbound private domains only; inbound VIP permissions aren't SNAT coverage.
            if candidate.source is not None and not intersect(RFC1918, candidate.source):
                continue
            # Public/inbound wildcard domains are not evidence of an internal network.
            if candidate.source == ipv4("0.0.0.0/0"):
                continue
            for egress in p.dstintf or ["UNKNOWN"]:
                kind = self.egress_type(egress)
                if kind == "INTERNAL":
                    continue
                key = (r.scope, tuple(candidate.source or p.srcaddr), tuple(sorted(p.srcintf)), egress,
                       tuple(candidate.destination or p.dstaddr), candidate.services or tuple(p.service))
                if key in seen:
                    continue
                seen.add(key)
                original = candidate.source
                remaining = list(original or [])
                excluded = []
                # A more-specific earlier translated rule owns this sub-domain.
                # Do not hide denied/untranslated traffic or subtract partial service matches.
                for prior in self.facts:
                    if prior is candidate:
                        break
                    if (prior.policy.status == "enable" and prior.source and original
                            and size(prior.source) < size(original) and contains(original, prior.source)
                            and self.match_relation(prior, candidate, egress) == "full"
                            and self.policy_state(prior, kind)[0] == "COVERED"):
                        remaining = subtract(remaining, prior.source)
                        excluded.append(str(prior.policy.id))
                domain = list(remaining)
                outcomes, matches, translations, disabled = [], [], [], []
                unknown = (original is None or not candidate.certain or not self.scope_complete(r.scope)
                           or not contains(RFC1918, original or []) or self.ex.mode(r.scope) is not False)
                for f in self.facts:
                    relation = self.match_relation(f, candidate, egress)
                    if relation == "disjoint":
                        continue
                    overlap = intersect(remaining, f.source) if f.source is not None else remaining
                    if not overlap:
                        continue
                    if f.policy.status == "disable":
                        if f.policy.nat == "enable" and relation == "full" and f.source is not None and self.translation(f):
                            disabled.append((f, overlap))
                        continue
                    matches.append(f)
                    if relation != "full" or f.source is None:
                        unknown = True
                        outcomes.append(("UNKNOWN", size(overlap)))
                    else:
                        state, translation = self.policy_state(f, kind)
                        outcomes.append((state, size(overlap)))
                        if translation:
                            translations.append(translation)
                    remaining = subtract(remaining, overlap)
                if remaining:
                    disabled_spans = merge(span for _, spans in disabled for span in spans)
                    disabled_part = intersect(remaining, disabled_spans)
                    if disabled_part:
                        outcomes.append(("DISABLED_ONLY", size(disabled_part)))
                        matches += [f for f, spans in disabled if intersect(remaining, spans)]
                    uncovered = subtract(remaining, disabled_spans)
                    if uncovered:
                        outcomes.append(("NO_MATCH", size(uncovered)))
                states = {state for state, count in outcomes if count}
                if unknown or "UNKNOWN" in states or not domain:
                    state = "UNKNOWN" if not states or states == {"UNKNOWN"} else "PARTIAL"
                    percent = None
                else:
                    state = next(iter(states)) if len(states) == 1 else "PARTIAL"
                    percent = round(100 * sum(n for s, n in outcomes if s in {"COVERED", "EXEMPT"}) / size(domain), 2)
                status = "PASS" if state in {"COVERED", "EXEMPT"} else "FAIL" if state == "NOT_TRANSLATED" else "WARN"
                notes = ["Static policy-domain analysis; routes, upstream NAT, sessions and VPN selectors are not verified."]
                if excluded:
                    notes.append("Excluding source traffic owned by earlier specific policies: " + ", ".join(excluded))
                if state in {"UNKNOWN", "PARTIAL"}:
                    notes.append("REVIEW_REQUIRED: incomplete or overlapping match dimensions; no full-coverage claim.")
                if state == "DISABLED_ONLY":
                    notes.append("NAT configuration exists but all covering NAT policies are disabled.")
                unique_matches = list({f.record.id: f for f in matches}.values())
                row = NATTrafficCoverage(scope=r.scope, source=p.srcaddr, source_ranges=display(domain),
                    source_interfaces=p.srcintf, destination=p.dstaddr, services=p.service, egress=egress, egress_type=kind,
                    matching_policy=[str(f.policy.id) for f in unique_matches], policy_names=[f.policy.name or str(f.policy.id) for f in unique_matches],
                    policy_order=[f.record.sequence for f in unique_matches], nat_state=state, translation=list(dict.fromkeys(translations)),
                    coverage_percent=percent, status=status, severity="INFO" if status == "PASS" else "HIGH" if status == "FAIL" else "MEDIUM", notes=notes)
                self.result.traffic_coverage.append(row)
                objects = p.srcaddr + row.policy_names
                if state == "NOT_TRANSLATED":
                    self.diag("NAT-002", r.scope, "HIGH", "FAIL", "MISSING_SNAT", objects,
                              "Enabled Internet-bound firewall policy permits private source traffic without source NAT.",
                              "Confirm upstream translation/routing; enable the intended SNAT if this firewall provides Internet translation.")
                elif state == "DISABLED_ONLY":
                    self.diag("NAT-003", r.scope, "MEDIUM", "WARN", "DISABLED_ONLY", objects,
                              "NAT configuration exists but provides no effective coverage because all matching NAT policies are disabled.",
                              "Confirm intended guest/network access before enabling or replacing a policy.")
                elif state == "EXEMPT":
                    self.diag("NAT-008", r.scope, "INFO", "PASS", "NAT_EXEMPT", objects,
                              "Private traffic to an explicitly configured IPsec tunnel uses intentional no-NAT policy intent.",
                              "Preserve the exemption; verify tunnel selectors and return routing.")
                elif state in {"PARTIAL", "UNKNOWN", "NO_MATCH"}:
                    self.diag("NAT-REVIEW", r.scope, "MEDIUM", "WARN", state, objects,
                              "Coverage cannot be established for the complete displayed policy domain.",
                              "Review match restrictions, ordering, topology and extraction notes; do not assume 100% coverage.")

    def ordering_and_cardinality(self):
        for first, later in combinations(self.facts, 2):
            if (first.policy.status != "enable" or later.policy.status != "enable" or first.policy.nat != "enable"
                    or later.policy.nat != "enable" or first.policy.action != "accept" or later.policy.action != "accept"
                    or first.source is None or later.source is None or not intersect(first.source, later.source)
                    or not first.certain or not later.certain or self.ex.mode(first.record.scope) is not False):
                continue
            relations = [self.match_relation(first, later, e) for e in later.policy.dstintf]
            if not relations or all(rel == "disjoint" for rel in relations):
                continue
            same_domain = all(rel == "full" for rel in relations)
            specific_first = size(first.source) < size(later.source) and contains(later.source, first.source)
            good = same_domain and specific_first
            self.diag("NAT-009", first.record.scope, "INFO" if good else "MEDIUM", "PASS" if good else "WARN",
                      "POLICY_ORDER", [first.policy.name or str(first.policy.id), later.policy.name or str(later.policy.id)],
                      "More-specific source NAT policy precedes the broader source policy." if good else "Earlier overlapping policy may shadow some or all of the later NAT policy.",
                      "Preserve source policy order." if good else "Review all match dimensions before reordering overlapping policies.")
            if same_domain and contains(first.source, later.source):
                for rule in self.ir.nat_rules:
                    if rule.source_id == later.record.id:
                        rule.effective, rule.analysis_status = False, "SHADOWED"
        for f in self.facts:
            p, r = f.policy, f.record
            if p.nat != "enable" or p.ippool != "enable" or self.ex.mode(r.scope) is not False:
                continue
            for name in p.poolname:
                pool = self.ex.pools.get((r.scope, name))
                if pool and pool.type == "fixed-port-range" and pool.source_startip and pool.source_endip and f.source is not None:
                    try:
                        allocation = ipv4(f"{pool.source_startip}-{pool.source_endip}")
                        outside = subtract(f.source, allocation)
                        if outside:
                            self.diag("NAT-011", r.scope, "MEDIUM", "WARN", "POOL_SOURCE_RANGE_REVIEW", [p.name or str(p.id), name],
                                      f"Policy source contains {size(f.source)} addresses; only {size(intersect(f.source, allocation))} are inside the explicit fixed-port source allocation. Full deterministic coverage is not established.",
                                      "Align the intended source domain and pool source range; verify FortiOS allocation behavior before claiming full coverage.")
                    except ValueError:
                        pass  # The existing source parser reports invalid ranges.
                if not pool or pool.type != "one-to-one":
                    continue
                try:
                    count = size(ipv4(f"{pool.startip}-{pool.endip}"))
                except ValueError:
                    count = None
                source_count = size(f.source) if f.source is not None and f.certain else None
                good = source_count is not None and source_count == count
                self.diag("NAT-010", r.scope, "INFO" if good else "MEDIUM", "PASS" if good else "WARN", "ONE_TO_ONE_CARDINALITY",
                          [p.name or str(p.id), name], f"Source range cardinality: {source_count if source_count is not None else 'UNKNOWN'}; translated pool: {count if count is not None else 'UNKNOWN'}.",
                          "Cardinality matches; verify operational allocation and shared-pool capacity." if good else "Review source/pool sizing and concurrent use; mismatch is a capacity concern, not invalid FortiGate syntax.")

    def vip_diagnostics(self):
        for (scope, _), vip in self.ex.vips.items():
            if vip.extintf == "any":
                self.diag("NAT-004", scope, "MEDIUM", "WARN", "BROAD_VIP_INTERFACE", [vip.name],
                          "VIP uses extintf any rather than a specific external interface; actual exposure also depends on filters and policies.",
                          "Restrict the external interface where appropriate, especially for administrative services.")
        for ((scope, _), left), ((other_scope, _), right) in combinations(self.ex.vips.items(), 2):
            if scope != other_scope:
                continue
            if left.extintf != right.extintf and "any" not in {left.extintf, right.extintf}:
                continue
            try:
                if left.extip == "0.0.0.0" or right.extip == "0.0.0.0":
                    raise ValueError("dynamic VIP address")
                if not intersect(ipv4(left.extip), ipv4(right.extip)):
                    continue
                lp = left.protocol.lower() if left.portforward == "enable" else "any"
                rp = right.protocol.lower() if right.portforward == "enable" else "any"
                if lp != rp and "any" not in {lp, rp}:
                    continue
                def ports(v):
                    if v.portforward == "disable":
                        return [(1, 65535)]
                    port = _port(v.extport)
                    if port is None:
                        raise ValueError("Missing external port")
                    numbers = [int(n) for n in port.split("-")]
                    return [(numbers[0], numbers[-1])]
                if not intersect(ports(left), ports(right)):
                    continue
                if left.srcintf_filter and right.srcintf_filter and not set(left.srcintf_filter) & set(right.srcintf_filter):
                    continue
                if left.src_filter and right.src_filter:
                    a = merge(span for value in left.src_filter for span in ipv4(value))
                    b = merge(span for value in right.src_filter for span in ipv4(value))
                    if not intersect(a, b):
                        continue
                # Respect both extintf and srcintf-filter, not each in isolation.
                def ingress(v):
                    allowed = set(v.srcintf_filter) if v.srcintf_filter else {"any"}
                    if v.extintf != "any":
                        allowed = {v.extintf} if "any" in allowed else allowed & {v.extintf}
                    return allowed
                li, ri = ingress(left), ingress(right)
                if not li or not ri or not ("any" in li or "any" in ri or li & ri):
                    continue
                same = (left.extip, left.mappedip, left.extport, left.mappedport, left.portforward) == (right.extip, right.mappedip, right.extport, right.mappedport, right.portforward)
                complex_mapping = any("-" in value or " " in value for value in [left.mappedip, right.mappedip, left.extip, right.extip])
                fail = not same and not complex_mapping
                self.diag("NAT-001", scope, "CRITICAL" if fail else "MEDIUM", "FAIL" if fail else "WARN", "VIP_OVERLAP", [left.name, right.name],
                          "Overlapping external interface, IP, protocol and port map to different internal destinations." if fail else "Overlapping VIP match tuples require duplicate/range mapping review.",
                          "Resolve the overlapping mapping, including unreferenced VIPs; verify filters and intended policy exposure.")
            except ValueError:
                self.diag("NAT-001", scope, "MEDIUM", "WARN", "REVIEW_REQUIRED", [left.name, right.name],
                          "VIP overlap is UNKNOWN because an address or port mapping cannot be statically resolved.",
                          "Resolve dynamic addresses or malformed mappings before evaluating overlap.")

    def summaries(self):
        for f in self.facts:
            p, r = f.policy, f.record
            rules = [n for n in self.ir.nat_rules if n.source_id == r.id]
            coverage = [c for c in self.result.traffic_coverage if str(p.id) in c.matching_policy and c.scope == r.scope]
            classification = rules[0].analysis_status if rules else "NAT_EXEMPT" if any(c.nat_state == "EXEMPT" for c in coverage) else "NO_POLICY_SNAT"
            expected = (self.translation(f) or "UNKNOWN") if p.nat == "enable" else "Identity / no policy SNAT"
            if self.ex.mode(r.scope) is not False:
                classification, expected = "REVIEW_REQUIRED", "UNKNOWN: policy NAT flags do not determine central NAT translation"
            self.result.policy_summaries.append(NATPolicySummary(
                source_id=r.id, scope=r.scope, policy_id=str(p.id), policy_name=p.name or str(p.id), policy_status=p.status,
                srcintf=p.srcintf, dstintf=p.dstintf, source=p.srcaddr, destination=p.dstaddr, services=p.service,
                nat_enabled=p.nat, ippool_enabled=p.ippool, poolname=p.poolname,
                pool_type=[self.ex.pools[(r.scope, n)].type for n in p.poolname if (r.scope, n) in self.ex.pools],
                fixedport=str(r.attributes.get("fixedport", "disable")),
                expected_translation=expected,
                classification=classification))

    def run(self):
        self.build_facts()
        self.resource_inventory()
        self.effective_rules()
        self.traffic()
        self.ordering_and_cardinality()
        self.vip_diagnostics()
        self.summaries()
        self.result.diagnostics.sort(key=lambda d: (d.diagnostic_id, d.scope, d.objects))
        self.report.nat_analysis = self.result


def analyze_nat(extractor):
    NATAnalyzer(extractor).run()
