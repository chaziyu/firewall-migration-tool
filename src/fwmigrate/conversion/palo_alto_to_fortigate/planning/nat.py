"""Restricted isolated central NAT; unknown overlaps remain manual."""
from ipaddress import IPv4Address, IPv4Interface, IPv4Network

from ..models import digest
from .context import unsupported_fields
from .source_scope import identity, in_scope


def _disjoint_source_rules(ctx, rules):
    """Prove independence only for explicit, direct IPv4 source prefixes."""
    prefixes = []
    for rule in rules:
        if rule.destination_translation is not None or not rule.source:
            return False
        current = []
        for name in rule.source:
            addresses = [obj for obj in ctx.source.addresses if in_scope(obj, ctx.scope) and obj.name == name]
            if len(addresses) != 1 or not addresses[0].ip_netmask or addresses[0].raw_extra:
                return False
            try:
                current.append(IPv4Network(addresses[0].ip_netmask, strict=False))
            except (ValueError, TypeError):
                return False
        if any(left.overlaps(right) for left in current for previous in prefixes for right in previous):
            return False
        prefixes.append(current)
    return True


def plan_dnat(ctx, obj, rule_count):
    """One address-only VIP and one ingress rule on an explicitly empty traffic baseline."""
    reasons = unsupported_fields(obj, {"from_zones", "to_zones", "source", "destination", "service", "disabled", "destination_translation"})
    translation = obj.destination_translation
    policies = [p for p in ctx.source.security_rules if in_scope(p, ctx.scope)]
    if (rule_count != 1 or len(policies) != 1 or obj.source_translation is not None or obj.dynamic_destination_translation is not None
            or obj.disabled != "no" or obj.source != ["any"] or obj.service != "any" or obj.rulebase_position not in {None, "local"}):
        reasons.append("DNAT requires one active address-only NAT rule, one security rule, unrestricted source/service and local ordering.")
    if ctx.options.profile.get("nat_mode") != "central" or ctx.options.profile.get("traffic_baseline") != "empty":
        reasons.append("DNAT requires explicit central NAT and an empty target traffic baseline.")
    arp = ctx.options.profile.get("vip_arp_reply")
    if arp not in {"enable", "disable"}:
        reasons.append("Choose explicit VIP proxy ARP behavior for the destination network.")
    if translation is None or translation.translated_port is not None or translation.dns_rewrite is not None or translation.raw_extra:
        reasons.append("Port-translated, DNS-rewriting and unknown DNAT settings remain manual.")
    _, address_deps, errors = ctx.resolve(obj, "destination", obj.destination, ("address", "address_group"))
    reasons.extend(errors)
    external = [a for a in ctx.source.addresses if identity(a, "address") in address_deps]
    public, mapped = "", ""
    try:
        if len(external) != 1 or len(obj.destination or ()) != 1 or not external[0].ip_netmask:
            raise ValueError
        network = IPv4Network(external[0].ip_netmask)
        if network.prefixlen != 32:
            raise ValueError
        public = str(network.network_address)
        mapped = str(IPv4Address(translation.translated_address))
        if public == mapped:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        reasons.append("DNAT requires one explicit public IPv4 host object and a distinct literal mapped IPv4 host.")
    zones = [z for z in ctx.source.zones if in_scope(z, ctx.scope) and z.name in (obj.from_zones or ())]
    ingress = ""
    _, zone_deps, errors = ctx.resolve(obj, "from_zones", obj.from_zones, ("zone",))
    reasons.extend(errors)
    if len(zones) != 1 or len(zones[0].members or ()) != 1 or obj.to_zones != obj.from_zones:
        reasons.append("DNAT original zones must be one identical ingress zone with one mapped interface.")
    else:
        ingress = ctx.options.interfaces.get(zones[0].members[0], "")
        if not ingress:
            reasons.append("DNAT ingress interface mapping is required.")
    if len(policies) == 1:
        policy = policies[0]
        if (policy.source != ["any"] or policy.destination != obj.destination or policy.from_zones != obj.from_zones
                or policy.service != ["any"] or policy.action != "allow" or policy.disabled != "no"
                or policy.negate_source != "no" or policy.negate_destination != "no"):
            reasons.append("DNAT security match must exactly cover the original host, ingress, source and service.")
        egress_zones = [z for z in ctx.source.zones if in_scope(z, ctx.scope) and z.name in (policy.to_zones or ())]
        egress_interfaces = [i for i in (*ctx.source.interfaces, *ctx.source.interface_units)
                             if i.scope and i.scope.device_name == ctx.scope.device_name and any(i.name in (z.members or ()) for z in egress_zones)]
        try:
            if (len(egress_zones) != 1 or len(egress_interfaces) != 1 or len(egress_interfaces[0].ipv4_addresses or ()) != 1
                    or IPv4Address(mapped) not in IPv4Interface(egress_interfaces[0].ipv4_addresses[0]).network
                    or policy.to_zones == obj.from_zones):
                raise ValueError
        except (ValueError, TypeError):
            reasons.append("Mapped host must have one verified connected post-NAT zone, separate from ingress.")
    name = "dnat_" + digest(identity(obj, "nat"))[:12]
    host = ctx.item(obj, "dnat_address", "firewall address", {"type": "ipmask", "subnet": (mapped, "255.255.255.255")} if mapped else {},
                    reasons=reasons, target_name=name + "_host")
    settings = {"type": "static-nat", "status": "enable", "portforward": "disable", "nat-source-vip": "disable"}
    if public:
        settings["extip"] = public
    if mapped:
        settings["mappedip"] = mapped
    if ingress:
        settings.update({"extintf": ingress, "srcintf-filter": (ingress,)})
    if arp in {"enable", "disable"}:
        settings["arp-reply"] = arp
    vip = ctx.item(obj, "nat", "firewall vip", settings, (*address_deps, *zone_deps, host.key), reasons, target_name=name)
    return [host, vip]


def plan_nat(ctx):
    rules = [r for r in ctx.source.nat_rules if in_scope(r, ctx.scope)]
    active = [r for r in rules if r.disabled != "yes"]
    independent = len(active) == 1 or _disjoint_source_rules(ctx, active)
    result = []
    for number, obj in enumerate(rules, 1):
        if obj.disabled == "yes":
            result.append(ctx.item(obj, "inactive_nat", "", disposition="BLOCK", reasons=(
                "Explicitly disabled source NAT rule retained as inactive evidence; no target activation or traffic dependency.",)))
            continue
        if obj.destination_translation is not None:
            result.extend(plan_dnat(ctx, obj, len(active)))
            continue
        reasons = unsupported_fields(obj, {"from_zones", "to_zones", "source", "destination", "service", "disabled", "source_translation"})
        settings, dependencies = {}, []
        # shortcut: multiple SNAT rules require disjoint literal source prefixes; groups and exceptions need packet partitioning.
        if not independent:
            reasons.append("Multiple NAT rules need verified first-match overlap and no-NAT handling.")
        if ctx.options.profile.get("nat_mode") != "central":
            reasons.append("Restricted SNAT requires an explicitly confirmed central NAT target.")
        if obj.rulebase_position not in {None, "local"} or obj.disabled not in {"yes", "no"} or obj.service != "any":
            reasons.append("NAT needs local ordering, explicit state, and an unrestricted service match.")
        translation = obj.source_translation
        if obj.destination_translation is not None or obj.dynamic_destination_translation is not None:
            reasons.append("DNAT remains manual until exact-version commands and packet-flow equivalence are verified.")
        if translation is None or translation.translation_type != "dynamic-ip-and-port" or translation.raw_extra:
            reasons.append("Only explicit dynamic-ip-and-port source NAT is supported.")
        else:
            if translation.translated_addresses is not None and translation.interface is not None:
                reasons.append("Mixed source translation modes are unsupported.")
            if getattr(translation, "translated_addresses", None):
                if ctx.options.profile.get("pool_return_routing") != "confirmed":
                    reasons.append("Confirm return routing for the translated pool; proxy ARP is deliberately disabled.")
                addresses = translation.translated_addresses
                if len(addresses) != 1:
                    reasons.append("Only a single explicit pool IPv4 address is supported.")
                else:
                    try:
                        address = str(IPv4Address(addresses[0]))
                        pool = ctx.item(obj, "ip_pool", "firewall ippool", {"type": "overload", "startip": address, "endip": address, "arp-reply": "disable"}, reasons=reasons,
                                        target_name=ctx.name(obj)[:50] + "_pool")
                        result.append(pool)
                        settings["nat-ippool"] = pool.target_name
                        dependencies.append(pool.key)
                    except ValueError:
                        reasons.append("Pool object references and non-IPv4 translations require manual conversion.")
            elif getattr(translation, "interface", None):
                target = ctx.options.interfaces.get(translation.interface)
                source_interfaces = [i for i in (*ctx.source.interfaces, *ctx.source.interface_units) if i.name == translation.interface and i.scope and i.scope.device_name == ctx.scope.device_name]
                try:
                    if (not target or len(source_interfaces) != 1 or len(source_interfaces[0].ipv4_addresses or ()) != 1
                            or IPv4Address(translation.ip) != IPv4Interface(source_interfaces[0].ipv4_addresses[0]).ip):
                        raise ValueError
                except (ValueError, TypeError):
                    reasons.append("Interface SNAT needs an explicit translated IP equal to the mapped interface's sole IPv4 address.")
                # Match zones are expanded to their explicit interface members below.
                if obj.to_zones is None or len(obj.to_zones) != 1:
                    reasons.append("Interface SNAT requires one explicit outgoing zone.")
                zones = [z for z in ctx.source.zones if in_scope(z, ctx.scope) and z.name in (obj.to_zones or ())]
                if len(zones) != 1 or zones[0].members != [translation.interface]:
                    reasons.append("SNAT interface must be the only member of the outgoing zone.")
            else:
                reasons.append("Explicit translated address or interface is required.")
        for field, output, families in (("source", "orig-addr", ("address", "address_group")), ("destination", "dst-addr", ("address", "address_group"))):
            values, deps, errors = ctx.resolve(obj, field, getattr(obj, field), families)
            settings[output] = values
            dependencies.extend(deps)
            reasons.extend(errors)
        for field, output in (("from_zones", "srcintf"), ("to_zones", "dstintf")):
            _, deps, errors = ctx.resolve(obj, field, getattr(obj, field), ("zone",))
            members = [member for zone in ctx.source.zones if in_scope(zone, ctx.scope) and zone.name in (getattr(obj, field) or ()) for member in zone.members or ()]
            settings[output] = tuple(dict.fromkeys(ctx.options.interfaces.get(member, "") for member in members))
            if not members or any(member not in ctx.options.interfaces for member in members):
                reasons.append("Every NAT zone member requires an explicit physical/logical interface mapping.")
            dependencies.extend(deps)
            reasons.extend(errors)
        settings.update({"nat": "enable", "status": "disable" if obj.disabled == "yes" else "enable"})
        result.append(ctx.item(obj, "nat", "firewall central-snat-map", settings, dependencies, reasons, target_name=str(number)))
    return result
