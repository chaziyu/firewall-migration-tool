"""Authoritative parser orchestrator for Juniper JunOS SRX 'display set' configurations."""

from __future__ import annotations

from typing import Dict, List, Optional

from fwmigrate.extraction.models import ExtractionResult, ExtractionStatus
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.juniper_srx.coverage import build_extraction_result
from fwmigrate.parsers.juniper_srx.hierarchy_parser import looks_hierarchical, normalize_hierarchy
from fwmigrate.parsers.juniper_srx.handlers.address_book import handle_address_book_command
from fwmigrate.parsers.juniper_srx.handlers.applications import handle_applications_command
from fwmigrate.parsers.juniper_srx.handlers.appsecure import handle_appsecure_command
from fwmigrate.parsers.juniper_srx.handlers.interfaces import handle_interfaces_command
from fwmigrate.parsers.juniper_srx.handlers.chassis_cluster import handle_chassis_cluster_command
from fwmigrate.parsers.juniper_srx.handlers.vlans import handle_vlans_command
from fwmigrate.parsers.juniper_srx.handlers.groups import handle_groups_command
from fwmigrate.parsers.juniper_srx.handlers.nat import handle_nat_command
from fwmigrate.parsers.juniper_srx.handlers.policies import handle_policies_command
from fwmigrate.parsers.juniper_srx.handlers.routing import handle_routing_command
from fwmigrate.parsers.juniper_srx.handlers.schedulers import handle_schedulers_command
from fwmigrate.parsers.juniper_srx.handlers.system import (
    classify_system_branch,
    handle_system_command,
    preserve_context_system_command,
)
from fwmigrate.parsers.juniper_srx.handlers.vpn import handle_vpn_command
from fwmigrate.parsers.juniper_srx.handlers.access import handle_access_command
from fwmigrate.parsers.juniper_srx.handlers.dynamic_vpn import handle_dynamic_vpn_command
from fwmigrate.parsers.juniper_srx.handlers.user_identification import handle_user_identification_command
from fwmigrate.parsers.juniper_srx.handlers.utm import handle_utm_command
from fwmigrate.parsers.juniper_srx.handlers.idp import handle_idp_command
from fwmigrate.parsers.juniper_srx.handlers.ssl_proxy import handle_ssl_proxy_command
from fwmigrate.parsers.juniper_srx.handlers.security_intelligence import handle_security_intelligence_command
from fwmigrate.parsers.juniper_srx.handlers.zones import handle_zones_command
from fwmigrate.parsers.juniper_srx.handlers.firewall_filters import handle_firewall_filter_command
from fwmigrate.parsers.juniper_srx.handlers.screens import handle_screens_command
from fwmigrate.parsers.juniper_srx.handlers.class_of_service import handle_class_of_service_command
from fwmigrate.parsers.juniper_srx.handlers.policy_options import handle_policy_options_command
from fwmigrate.parsers.juniper_srx.handlers.dhcp import handle_dhcp_command
from fwmigrate.parsers.juniper_srx.handlers.link_monitor import handle_link_monitor_command
from fwmigrate.parsers.juniper_srx.handlers.rpm import handle_rpm_command
from fwmigrate.parsers.juniper_srx.handlers.chassis import handle_chassis_command
from fwmigrate.parsers.juniper_srx.handlers.snmp import handle_snmp_command
from fwmigrate.parsers.juniper_srx.handlers.pki import handle_pki_command
from fwmigrate.parsers.juniper_srx.handlers.security_flow import handle_security_flow_command
from fwmigrate.parsers.juniper_srx.model import (
    JuniperAddressSet,
    JuniperAddressSetMember,
    JuniperAddressBook,
    JuniperContextConfig,
    JuniperIKEGateway,
    JuniperIKEPolicy,
    JuniperIKEProposal,
    JuniperIPSecPolicy,
    JuniperIPSecProposal,
    JuniperIPSecVPN,
    JuniperRoutingInstance,
    JuniperSourceHierarchyItem,
    JuniperSRXConfig,
    JuniperZone,
    JuniperScheduler,
    JuniperPolicy,
    JuniperEffectiveCandidate,
)
from fwmigrate.parsers.juniper_srx.tokenizer import (
    JuniperSetTokenizer,
    JunosActivationState,
    JunosCommand,
    JunosOperation,
    validate_input_mode,
)
from fwmigrate.parsers.juniper_srx.transformer import JuniperToIRTransformer
from fwmigrate.parsers.juniper_srx.group_resolver import resolve_group_commands
from fwmigrate.parsers.juniper_srx.provenance import (
    record_inactive_candidate,
    record_non_effective_candidate,
)


class JuniperSRXParser:
    """Parser orchestrator for JunOS SRX firewall configurations in 'set' format."""

    def __init__(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> None:
        self.content = content
        self.zone_mapping = zone_mapping or {}
        self.tokenizer = JuniperSetTokenizer()
        self.activation_state = JunosActivationState()
        self.config = JuniperSRXConfig()

    def extract(self) -> ExtractionResult:
        """Execute the complete extraction pipeline returning authoritative ExtractionResult."""
        source = normalize_hierarchy(self.content) if looks_hierarchical(self.content) else self.content
        commands = self.tokenizer.tokenize(source)
        self.activation_state.apply(commands)
        effective_commands = resolve_group_commands(commands)
        for command in effective_commands:
            for record in command.candidate_records:
                candidate = JuniperEffectiveCandidate(**record)
                self.config.field_candidate_history.setdefault("group", []).append(candidate)

        # 1. Conservative relative display-set validation
        validate_input_mode(commands)

        # 2. Process activation/deactivation state
        self.activation_state.apply(effective_commands)

        # 3. Dispatch set commands through domain handlers with context-prefix normalization
        for cmd in effective_commands:
            if cmd.operation == JunosOperation.DEACTIVATE:
                context, effective_cmd = self._normalize_context(cmd)
                if effective_cmd.parse_error:
                    cmd.parse_error = effective_cmd.parse_error
                    cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                    self.config.unsupported_commands.append(cmd.to_sanitized_copy())
                    continue
                if effective_cmd.tokens[1:3] == ["system", "host-name"]:
                    self.config.hostname = None
                elif effective_cmd.tokens[1:3] == ["system", "time-zone"]:
                    self.config.time_zone = None
                self._record_inactive_child(effective_cmd, context)
                cmd.consumed = True
                cmd.handler = "activation"
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                cmd.context_type = effective_cmd.context_type
                cmd.context_name = effective_cmd.context_name
                continue
            if cmd.operation != JunosOperation.SET:
                continue

            if not cmd.tokens or len(cmd.tokens) < 2:
                cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                continue

            if handle_groups_command(cmd, self.config):
                continue

            # Context prefix routing: root vs logical-systems <name> vs tenants <name>
            context, effective_cmd = self._normalize_context(cmd)
            if effective_cmd.parse_error:
                cmd.parse_error = effective_cmd.parse_error
                cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                self.config.unsupported_commands.append(cmd.to_sanitized_copy())
                continue

            # A child deactivation applies to that statement only.  Skip its
            # value before handlers can merge it into a repeated list/object.
            system_child = effective_cmd.tokens[1:3]
            context_prefix = self._context_prefix(context)
            activation_path = context_prefix + effective_cmd.tokens[1:]
            if (self.activation_state.is_exactly_inactive(activation_path)
                    or (system_child in (["system", "host-name"], ["system", "time-zone"])
                        and self.activation_state.is_inactive(context_prefix + system_child))):
                if system_child == ["system", "host-name"]:
                    self.config.hostname = None
                self._record_inactive_child(effective_cmd, context)
                cmd.consumed = True
                cmd.handler = "activation"
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                continue

            # Tenant security-profile is a binding reference, not a resource
            # entitlement declaration. Preserve it without simulating quotas.
            if (context.context_type == "tenant"
                    and len(effective_cmd.tokens) >= 3
                    and effective_cmd.tokens[1].lower() == "security-profile"):
                profile_name = effective_cmd.tokens[2]
                context.security_profile = profile_name
                context.source_attributes["security_profile"] = {
                    "name": profile_name,
                    "raw": effective_cmd.raw_sanitized,
                    "line_number": effective_cmd.line_number,
                }
                effective_cmd.consumed = cmd.consumed = True
                effective_cmd.handler = cmd.handler = "security-profile"
                effective_cmd.extraction_status = cmd.extraction_status = (
                    ExtractionStatus.NORMALIZED if len(effective_cmd.tokens) == 3
                    else ExtractionStatus.EXTRACT_ONLY
                )
                continue

            # Handler dispatch chain
            handled = (
                handle_dhcp_command(effective_cmd, context)
                or self._handle_system_for_context(effective_cmd, context)
                or handle_snmp_command(effective_cmd, self.config)
                or handle_pki_command(effective_cmd, self.config)
                or handle_security_flow_command(effective_cmd, context)
                or handle_vlans_command(effective_cmd, context)
                or handle_interfaces_command(effective_cmd, context)
                or handle_chassis_cluster_command(effective_cmd, context)
                or handle_address_book_command(effective_cmd, context)
                or handle_zones_command(effective_cmd, context)
                or handle_screens_command(effective_cmd, context)
                or handle_firewall_filter_command(effective_cmd, context)
                or handle_policy_options_command(effective_cmd, context)
                or handle_class_of_service_command(effective_cmd, context)
                or handle_link_monitor_command(effective_cmd, context)
                or handle_rpm_command(effective_cmd, context)
                or handle_chassis_command(effective_cmd, context)
                or handle_applications_command(effective_cmd, context)
                or handle_appsecure_command(effective_cmd, context)
                or handle_policies_command(effective_cmd, context)
                or handle_schedulers_command(effective_cmd, context)
                or handle_routing_command(effective_cmd, context)
                or handle_nat_command(effective_cmd, context)
                or handle_vpn_command(effective_cmd, context)
                or handle_access_command(effective_cmd, context)
                or handle_dynamic_vpn_command(effective_cmd, context)
                or handle_user_identification_command(effective_cmd, context)
              or handle_utm_command(effective_cmd, context)
              or handle_idp_command(effective_cmd, context)
              or handle_ssl_proxy_command(effective_cmd, context)
              or handle_security_intelligence_command(effective_cmd, context)
            )

            # Mirror consumption & handler state back to original command
            cmd.consumed = effective_cmd.consumed
            cmd.handler = effective_cmd.handler
            if effective_cmd.extraction_status:
                cmd.extraction_status = effective_cmd.extraction_status
            if effective_cmd.parse_error:
                cmd.parse_error = effective_cmd.parse_error
                self.config.unsupported_commands.append(cmd.to_sanitized_copy())
            cmd.consumed_tokens = effective_cmd.consumed_tokens
            cmd.remaining_tokens = effective_cmd.remaining_tokens
            cmd.context_type = effective_cmd.context_type
            cmd.context_name = effective_cmd.context_name

            if handled and cmd.extraction_status == ExtractionStatus.NORMALIZED and cmd.remaining_tokens:
                cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
                cmd.requires_manual_review = True

            if not handled:
                cmd.consumed = False
                cmd.extraction_status = ExtractionStatus.UNSUPPORTED
                self.config.unsupported_commands.append(cmd.to_sanitized_copy())

        # 4. Apply activation state to models
        self._attach_non_effective_candidates(effective_commands)
        self._apply_activation_state_to_models()

        # 5. Transform to Canonical IR
        transformer = JuniperToIRTransformer(self.config, zone_mapping=self.zone_mapping)
        canonical_ir = transformer.transform()

        # 6. Build ExtractionResult with 100% command-level accounting
        return build_extraction_result(commands, canonical_ir)

    def _attach_non_effective_candidates(self, commands: List[JunosCommand]) -> None:
        """Attach resolver-owned non-effective records without replaying them as commands."""
        for command in commands:
            for record in command.candidate_records:
                candidate = JuniperEffectiveCandidate(**record)
                path = list(candidate.target_path)
                context = self.config.get_context("root", context_type="root")
                if len(path) >= 2 and path[0].lower() in {"logical-systems", "tenants"}:
                    context = self.config.get_context(path[1], context_type="logical-system" if path[0].lower() == "logical-systems" else "tenant")
                    path = path[2:]
                if candidate.provenance:
                    candidate.provenance = candidate.provenance.__class__(
                        **{**candidate.provenance.__dict__, "source_context": context.context,
                           "target_context": context.context}
                    )
                obj = None
                if path[:2] == ["security", "address-book"] and "address-set" in path:
                    book = context.address_books.get(path[2])
                    set_index = path.index("address-set")
                    if book and set_index + 1 < len(path):
                        obj = book.address_sets.get(path[set_index + 1])
                elif len(path) > 3 and path[:3] == ["security", "zones", "security-zone"]:
                    obj = context.zones.get(path[3])
                elif path[:2] == ["schedulers", "scheduler"] and len(path) > 2:
                    obj = context.schedulers.get(path[2])
                elif path[:2] == ["security", "policies"]:
                    name_index = path.index("policy") + 1 if "policy" in path else -1
                    name = path[name_index] if name_index > 0 and name_index < len(path) else None
                    pool = context.global_policies if "global" in path else context.policies
                    obj = next((p for p in pool if p.name == name), None)
                elif path and path[0] in {"routing-options", "routing-instances"}:
                    if "route" in path:
                        destination = path[path.index("route") + 1]
                        instance = path[1] if path[0] == "routing-instances" else None
                        obj = next((r for r in context.routes if r.destination == destination and r.routing_instance == instance), None)
                    elif path[0] == "routing-instances" and len(path) > 1:
                        obj = context.routing_instances.get(path[1])
                elif path[:3] == ["security", "nat", path[2] if len(path) > 2 else None]:
                    nat_type = path[2] if len(path) > 2 else ""
                    pools = context.nat.source_pools if nat_type == "source" else context.nat.destination_pools
                    if "pool" in path:
                        obj = pools.get(path[path.index("pool") + 1])
                    elif "rule" in path:
                        sets = context.nat.static_rule_sets if nat_type == "static" else context.nat.source_rule_sets if nat_type == "source" else context.nat.destination_rule_sets
                        rs = sets.get(path[path.index("rule") - 1]) if path.index("rule") else None
                        obj = next((r for r in rs.rules if r.name == path[path.index("rule") + 1]), None) if rs else None
                elif path[:2] in (["security", "ike"], ["security", "ipsec"]):
                    collections = {
                        ("ike", "proposal"): context.vpn.ike_proposals,
                        ("ike", "policy"): context.vpn.ike_policies,
                        ("ike", "gateway"): context.vpn.ike_gateways,
                        ("ipsec", "proposal"): context.vpn.ipsec_proposals,
                        ("ipsec", "policy"): context.vpn.ipsec_policies,
                        ("ipsec", "vpn"): context.vpn.ipsec_vpns,
                    }
                    if len(path) > 3:
                        obj = collections.get((path[1], path[2]), {}).get(path[3])
                if obj is None:
                    record_non_effective_candidate(context, path, candidate.field_key, candidate)
                    continue
                field = candidate.field_key
                if field.startswith("interface:") or field in {"address", "address-set"} or isinstance(getattr(obj, field, None), list):
                    history = obj.member_candidate_history.setdefault(field, [])
                else:
                    history = obj.field_candidate_history.setdefault(field, [])
                history.append(candidate)
                history.sort(key=lambda item: item.provenance.source_order if item.provenance else 0)

    def _handle_system_for_context(self, cmd: JunosCommand, context: JuniperContextConfig) -> bool:
        classification = classify_system_branch(cmd, context.context_type)
        if classification == "not-system":
            return False
        if context.context_type != "root" and classification != "context-local":
            return preserve_context_system_command(cmd, context)
        return handle_system_command(cmd, self.config, context if context.context_type != "root" else None)

    @staticmethod
    def _record_inactive_child(cmd: JunosCommand, context: JuniperContextConfig) -> None:
        toks = [t.lower() for t in cmd.tokens[1:]]
        try:
            if toks[:2] == ["schedulers", "scheduler"] and len(toks) >= 3:
                name = cmd.tokens[3]
                sched = context.schedulers.setdefault(name, JuniperScheduler(name=name))
                sched.source_attributes["disabled"] = True
                key = toks[3] if len(toks) > 3 else "object"
                value = " ".join(cmd.tokens[4:]) if len(cmd.tokens) > 4 else None
                record_inactive_candidate(sched.field_candidate_history, key.replace("-", "_"), value, cmd)
                return
            if toks[:2] == ["security", "zones"] and "security-zone" in toks:
                i = toks.index("security-zone")
                zone = context.zones.setdefault(cmd.tokens[i + 2], JuniperZone(name=cmd.tokens[i + 2]))
                if len(toks) > i + 3:
                    record_inactive_candidate(zone.field_candidate_history, toks[i + 3].replace("-", "_"), " ".join(cmd.tokens[i + 4:]), cmd)
                    if "host-inbound-traffic" in toks:
                        h = toks.index("host-inbound-traffic")
                        interface = cmd.tokens[h + 2] if len(toks) > h + 2 and toks[h + 1] == "interfaces" else None
                        offset = h + 3 if interface else h + 1
                        if len(toks) > offset + 1 and toks[offset] in {"system-services", "protocols"}:
                            key = f"{interface or '*'}:{toks[offset]}"
                            zone.disabled_host_inbound.setdefault(key, []).extend(
                                value for value in cmd.tokens[offset + 2:]
                                if value not in zone.disabled_host_inbound.setdefault(key, [])
                            )
                else:
                    zone.source_attributes["disabled"] = True
                    record_inactive_candidate(zone.field_candidate_history, "object", None, cmd)
                return
            if toks[:2] == ["security", "policies"] and "policy" in toks:
                i = toks.index("policy")
                name = cmd.tokens[i + 1]
                pool = context.global_policies if "global" in toks else context.policies
                pol = next((p for p in pool if p.name == name), None)
                if pol is None:
                    from_z = cmd.tokens[toks.index("from-zone") + 1] if "from-zone" in toks else None
                    to_z = cmd.tokens[toks.index("to-zone") + 1] if "to-zone" in toks else None
                    pol = JuniperPolicy(name=name, policy_scope="global" if "global" in toks else "zone", from_zone=from_z, to_zone=to_z)
                    pool.append(pol)
                pol.disabled = True
                field = toks[i + 2].replace("-", "_") if len(toks) > i + 2 else "object"
                record_inactive_candidate(pol.field_candidate_history, field, " ".join(cmd.tokens[i + 3:]) if len(toks) > i + 2 else None, cmd)
                return
            if toks[:2] == ["system", "host-name"]:
                context.source_attributes["disabled_system_host_name"] = True
                return
            if toks[:3] == ["system", "login", "user"] and len(toks) >= 4:
                name = cmd.tokens[4]
                item = context.source_attributes.setdefault("disabled_users", [])
                if name not in item:
                    item.append(name)
                return
            if len(toks) >= 4 and toks[:2] in (["security", "ike"], ["security", "ipsec"]):
                domain, kind, name = toks[1], toks[2], cmd.tokens[4]
                vpn_config = context.vpn
                collections = {
                    ("ike", "proposal"): vpn_config.ike_proposals,
                    ("ike", "policy"): vpn_config.ike_policies,
                    ("ike", "gateway"): vpn_config.ike_gateways,
                    ("ipsec", "proposal"): vpn_config.ipsec_proposals,
                    ("ipsec", "policy"): vpn_config.ipsec_policies,
                    ("ipsec", "vpn"): vpn_config.ipsec_vpns,
                }
                constructors = {
                    ("ike", "proposal"): JuniperIKEProposal,
                    ("ike", "policy"): JuniperIKEPolicy,
                    ("ike", "gateway"): JuniperIKEGateway,
                    ("ipsec", "proposal"): JuniperIPSecProposal,
                    ("ipsec", "policy"): JuniperIPSecPolicy,
                    ("ipsec", "vpn"): JuniperIPSecVPN,
                }
                collection = collections.get((domain, kind))
                constructor = constructors.get((domain, kind))
                if collection is not None and constructor is not None:
                    obj = collection.setdefault(name, constructor(name=name))
                    child = toks[4:]
                    obj.source_attributes.setdefault("disabled_children", []).append(child)
                    return
            if toks[:1] == ["routing-instances"] and len(toks) >= 2:
                instance = context.routing_instances.setdefault(
                    cmd.tokens[2], JuniperRoutingInstance(name=cmd.tokens[2])
                )
                if len(toks) == 2:
                    instance.source_attributes["disabled"] = True
                else:
                    instance.source_attributes.setdefault("disabled_children", []).append(toks[2:])
                return
            generic = {
                ("access", "profile"): context.access_profiles,
                ("security", "dynamic-vpn"): context.dynamic_vpns,
                ("security", "user-identification"): context.user_identification,
                ("security", "user"): context.user_identification,
                ("security", "utm"): context.utm_policies,
            }.get(tuple(toks[:2]))
            if generic is not None and len(toks) >= 3:
                name = toks[2] if toks[0] == "access" else (cmd.tokens[3] if len(cmd.tokens) > 3 else "__global__")
                item = generic.setdefault(name, JuniperSourceHierarchyItem(name=name))
                item.disabled = True
                item.settings.setdefault("disabled_paths", []).append(toks[3:] if toks[0] == "access" else toks[4:])
                return
            if toks[:2] == ["security", "address-book"] and len(toks) >= 7:
                book_name, set_name = cmd.tokens[3], cmd.tokens[5]
                book = context.address_books.setdefault(book_name, JuniperAddressBook(name=book_name))
                if toks[3] == "address-set" and toks[5] in {"address", "address-set"}:
                    aset = book.address_sets.setdefault(set_name, JuniperAddressSet(name=set_name, address_book=book.name))
                    member = JuniperAddressSetMember(
                        name=cmd.tokens[7], member_type=toks[5], disabled=True,
                        source_path=cmd.raw_sanitized,
                    )
                    if not any(m.name == member.name and m.member_type == member.member_type for m in aset.members):
                        aset.members.append(member)
                    return
            i = toks.index("security-zone")
            zone_name = cmd.tokens[i + 2]
            zone = context.zones.setdefault(zone_name, JuniperZone(name=zone_name))
            if "host-inbound-traffic" not in toks:
                return
            h = toks.index("host-inbound-traffic")
            interface = cmd.tokens[h + 2] if len(toks) > h + 2 and toks[h + 1] == "interfaces" else None
            offset = h + 3 if interface else h + 1
            if len(toks) <= offset + 1 or toks[offset] not in {"system-services", "protocols"}:
                return
            key = f"{interface or '*'}:{toks[offset]}"
            zone.disabled_host_inbound.setdefault(key, []).extend(
                v for v in toks[offset + 1:] if v not in zone.disabled_host_inbound.setdefault(key, [])
            )
        except (ValueError, IndexError):
            return

    def _apply_activation_state_to_models(self) -> None:
        """Apply activation state (deactivate/activate) to parsed source model objects."""
        for ctx_name, context in self.config.contexts.items():
            ctx_prefix = (
                ["logical-systems", ctx_name.lower()]
                if context.context_type == "logical-system"
                else (["tenants", ctx_name.lower()] if context.context_type == "tenant" else [])
            )

            for group_id, group in context.chassis_cluster.redundancy_groups.items():
                group_path = ctx_prefix + ["chassis", "cluster", "redundancy-group", group_id.lower()]
                if group.preempt is not None:
                    if self.activation_state.is_inactive(group_path + ["preempt"]):
                        group.preempt.enabled = False
                    for option in ("delay", "limit", "period"):
                        if self.activation_state.is_inactive(group_path + ["preempt", option]):
                            setattr(group.preempt, option, None)
                if self.activation_state.is_inactive(group_path + ["hold-down-interval"]):
                    group.hold_down_interval = None
                if self.activation_state.is_inactive(group_path + ["gratuitous-arp-count"]):
                    group.gratuitous_arp_count = None

            # 1. Interfaces
            for intf in context.interfaces.values():
                intf_path = ctx_prefix + ["interfaces", intf.name.lower()]
                if self.activation_state.is_inactive(intf_path):
                    intf.disabled = True
                for unit in intf.units.values():
                    unit_path = intf_path + ["unit", str(unit.unit).lower()]
                    if intf.disabled or self.activation_state.is_inactive(unit_path):
                        unit.disabled = True

            for vlan in context.vlans.values():
                vlan_path = ctx_prefix + ["vlans", vlan.name.lower()]
                if self.activation_state.is_inactive(vlan_path):
                    vlan.disabled = True

            # 1.5 Zones
            for zone in context.zones.values():
                zone_path = ctx_prefix + ["security", "zones", "security-zone", zone.name.lower()]
                zones_root_path = ctx_prefix + ["security", "zones"]
                if self.activation_state.is_inactive(zones_root_path) or self.activation_state.is_inactive(zone_path):
                    zone.source_attributes["disabled"] = True

            # 2. Address Books, Addresses, and Address Sets
            for book_name, book in context.address_books.items():
                if book_name == "global":
                    book_path = ctx_prefix + ["security", "address-book", "global"]
                elif book_name.startswith("zone_"):
                    z_name = book_name[5:]
                    book_path = ctx_prefix + ["security", "zones", "security-zone", z_name.lower(), "address-book"]
                else:
                    book_path = ctx_prefix + ["security", "address-book", book_name.lower()]

                book_inactive = self.activation_state.is_inactive(book_path)
                for addr in book.addresses.values():
                    addr_path = book_path + ["address", addr.name.lower()]
                    if book_inactive or self.activation_state.is_inactive(addr_path):
                        addr.disabled = True

                for aset in book.address_sets.values():
                    aset_path = book_path + ["address-set", aset.name.lower()]
                    if book_inactive or self.activation_state.is_inactive(aset_path):
                        aset.disabled = True

            # 3. Applications and Application Sets
            for app in context.applications.values():
                app_path = ctx_prefix + ["applications", "application", app.name.lower()]
                if self.activation_state.is_inactive(app_path):
                    app.disabled = True
                for term in app.terms:
                    term_path = app_path + (["term", term.name.lower()] if term.name and term.name != "__default__" else [])
                    if self.activation_state.is_inactive(term_path):
                        term.disabled = True

            for appset in context.application_sets.values():
                appset_path = ctx_prefix + ["applications", "application-set", appset.name.lower()]
                if self.activation_state.is_inactive(appset_path):
                    appset.disabled = True

            # 4. Policies (Zone-scoped & Global)
            for pol in context.policies:
                from_z = pol.from_zones[0].lower() if pol.from_zones else ""
                to_z = pol.to_zones[0].lower() if pol.to_zones else ""
                pol_path = ctx_prefix + [
                    "security",
                    "policies",
                    "from-zone",
                    from_z,
                    "to-zone",
                    to_z,
                    "policy",
                    pol.name.lower(),
                ]
                zone_pair_path = ctx_prefix + ["security", "policies", "from-zone", from_z, "to-zone", to_z]
                policies_root_path = ctx_prefix + ["security", "policies"]
                if (
                    self.activation_state.is_inactive(policies_root_path)
                    or self.activation_state.is_inactive(zone_pair_path)
                    or self.activation_state.is_inactive(pol_path)
                ):
                    pol.disabled = True

            for g_pol in context.global_policies:
                g_pol_path = ctx_prefix + ["security", "policies", "global", "policy", g_pol.name.lower()]
                global_path = ctx_prefix + ["security", "policies", "global"]
                policies_root_path = ctx_prefix + ["security", "policies"]
                if (
                    self.activation_state.is_inactive(policies_root_path)
                    or self.activation_state.is_inactive(global_path)
                    or self.activation_state.is_inactive(g_pol_path)
                ):
                    g_pol.disabled = True

            # 5. Schedulers
            for sched in context.schedulers.values():
                sched_path = ctx_prefix + ["schedulers", "scheduler", sched.name.lower()]
                sched_root_path = ctx_prefix + ["schedulers"]
                if self.activation_state.is_inactive(sched_root_path) or self.activation_state.is_inactive(sched_path):
                    sched.source_attributes["disabled"] = True

            # 6. Static Routes
            for instance in context.routing_instances.values():
                ri_path = ctx_prefix + ["routing-instances", instance.name.lower()]
                if self.activation_state.is_inactive(ri_path):
                    instance.source_attributes["disabled"] = True
                    for route in context.routes:
                        if route.routing_instance == instance.name:
                            route.disabled = True
            for r in context.routes:
                if r.routing_instance:
                    r_path = ctx_prefix + ["routing-instances", r.routing_instance.lower(), "routing-options", "static", "route", r.destination.lower()]
                else:
                    r_path = ctx_prefix + ["routing-options", "static", "route", r.destination.lower()]
                if self.activation_state.is_inactive(r_path):
                    r.disabled = True

            # 7. NAT Rules
            for rs_name, rs in context.nat.source_rule_sets.items():
                rs_path = ctx_prefix + ["security", "nat", "source", "rule-set", rs_name.lower()]
                rs_inactive = self.activation_state.is_inactive(rs_path)
                for r in rs.rules:
                    r_path = rs_path + ["rule", r.name.lower()]
                    if rs_inactive or self.activation_state.is_inactive(r_path):
                        r.disabled = True

            for rs_name, rs in context.nat.destination_rule_sets.items():
                rs_path = ctx_prefix + ["security", "nat", "destination", "rule-set", rs_name.lower()]
                rs_inactive = self.activation_state.is_inactive(rs_path)
                for r in rs.rules:
                    r_path = rs_path + ["rule", r.name.lower()]
                    if rs_inactive or self.activation_state.is_inactive(r_path):
                        r.disabled = True

            for rs_name, rs in context.nat.static_rule_sets.items():
                rs_path = ctx_prefix + ["security", "nat", "static", "rule-set", rs_name.lower()]
                rs_inactive = self.activation_state.is_inactive(rs_path)
                for r in rs.rules:
                    r_path = rs_path + ["rule", r.name.lower()]
                    if rs_inactive or self.activation_state.is_inactive(r_path):
                        r.disabled = True

            # 8. VPN (Proposals, Policies, Gateways, and Tunnels)
            for prop in context.vpn.ike_proposals.values():
                prop_path = ctx_prefix + ["security", "ike", "proposal", prop.name.lower()]
                if self.activation_state.is_inactive(prop_path):
                    prop.source_attributes["disabled"] = True

            for ipol in context.vpn.ike_policies.values():
                ipol_path = ctx_prefix + ["security", "ike", "policy", ipol.name.lower()]
                if self.activation_state.is_inactive(ipol_path):
                    ipol.source_attributes["disabled"] = True

            for gw in context.vpn.ike_gateways.values():
                gw_path = ctx_prefix + ["security", "ike", "gateway", gw.name.lower()]
                if self.activation_state.is_inactive(gw_path):
                    gw.source_attributes["disabled"] = True

            for iprop in context.vpn.ipsec_proposals.values():
                iprop_path = ctx_prefix + ["security", "ipsec", "proposal", iprop.name.lower()]
                if self.activation_state.is_inactive(iprop_path):
                    iprop.source_attributes["disabled"] = True

            for ipol in context.vpn.ipsec_policies.values():
                ipol_path = ctx_prefix + ["security", "ipsec", "policy", ipol.name.lower()]
                if self.activation_state.is_inactive(ipol_path):
                    ipol.source_attributes["disabled"] = True

            for vpn in context.vpn.ipsec_vpns.values():
                vpn_path = ctx_prefix + ["security", "ipsec", "vpn", vpn.name.lower()]
                if self.activation_state.is_inactive(vpn_path):
                    vpn.disabled = True

            for screen in context.screens.values():
                if self.activation_state.is_inactive(ctx_prefix + ["security", "screen", screen.name.lower()]):
                    screen.disabled = True
            for filt in context.firewall_filters.values():
                path = ctx_prefix + ["firewall", "family", filt.family.lower(), "filter", filt.name.lower()]
                if self.activation_state.is_inactive(path):
                    filt.source_attributes["disabled"] = True
            for policer in context.policers.values():
                if self.activation_state.is_inactive(ctx_prefix + ["firewall", "policer", policer.name.lower()]):
                    policer.source_attributes["disabled"] = True
            for prefix_list in context.prefix_lists.values():
                if self.activation_state.is_inactive(ctx_prefix + ["policy-options", "prefix-list", prefix_list.name.lower()]):
                    prefix_list.disabled = True

    def _normalize_context(self, cmd: JunosCommand) -> tuple[JuniperContextConfig, JunosCommand]:
        """Strip context prefix (logical-systems/tenants) and route to target context."""
        toks = cmd.tokens
        if len(toks) >= 2 and toks[1].lower() == "logical-systems" and len(toks) < 4:
            cmd.parse_error = "Malformed logical-systems context prefix"
            cmd.extraction_status = ExtractionStatus.PARSE_ERROR
            return self.config.get_context("root", context_type="root"), cmd
        if len(toks) >= 4 and toks[1].lower() == "logical-systems":
            ls_name = toks[2]
            ctx = self.config.get_context(ls_name, context_type="logical-system")
            stripped_tokens = [toks[0]] + toks[3:]
            effective_cmd = JunosCommand(
                operation=cmd.operation,
                tokens=stripped_tokens,
                raw_sanitized=cmd.raw_sanitized,
                line_number=cmd.line_number,
                original_tokens=list(toks),
                normalized_tokens=list(stripped_tokens),
                context_type=ctx.context_type,
                context_name=ctx.name,
                source_group=cmd.source_group,
                source_group_path=cmd.source_group_path,
                source_group_chain=list(cmd.source_group_chain),
                target_path=cmd.target_path,
                group_resolution=cmd.group_resolution,
                group_recursion_depth=cmd.group_recursion_depth,
                group_priority=cmd.group_priority,
                group_list_priority=cmd.group_list_priority,
                group_application_depth=cmd.group_application_depth,
                hierarchy_depth=cmd.hierarchy_depth,
                source_order=cmd.source_order,
            )
            cmd.original_tokens = list(toks)
            cmd.normalized_tokens = list(stripped_tokens)
            cmd.context_type = ctx.context_type
            cmd.context_name = ctx.name
            return ctx, effective_cmd

        if len(toks) >= 2 and toks[1].lower() == "tenants" and len(toks) < 4:
            cmd.parse_error = "Malformed tenants context prefix"
            cmd.extraction_status = ExtractionStatus.PARSE_ERROR
            return self.config.get_context("root", context_type="root"), cmd
        if len(toks) >= 4 and toks[1].lower() == "tenants":
            t_name = toks[2]
            ctx = self.config.get_context(t_name, context_type="tenant")
            stripped_tokens = [toks[0]] + toks[3:]
            effective_cmd = JunosCommand(
                operation=cmd.operation,
                tokens=stripped_tokens,
                raw_sanitized=cmd.raw_sanitized,
                line_number=cmd.line_number,
                original_tokens=list(toks),
                normalized_tokens=list(stripped_tokens),
                context_type=ctx.context_type,
                context_name=ctx.name,
                source_group=cmd.source_group,
                source_group_path=cmd.source_group_path,
                source_group_chain=list(cmd.source_group_chain),
                target_path=cmd.target_path,
                group_resolution=cmd.group_resolution,
                group_recursion_depth=cmd.group_recursion_depth,
                group_priority=cmd.group_priority,
                group_list_priority=cmd.group_list_priority,
                group_application_depth=cmd.group_application_depth,
                hierarchy_depth=cmd.hierarchy_depth,
                source_order=cmd.source_order,
            )
            cmd.original_tokens = list(toks)
            cmd.normalized_tokens = list(stripped_tokens)
            cmd.context_type = ctx.context_type
            cmd.context_name = ctx.name
            return ctx, effective_cmd

        root_ctx = self.config.get_context("root", context_type="root")
        cmd.original_tokens = list(toks)
        cmd.normalized_tokens = list(toks)
        cmd.context_type = root_ctx.context_type
        cmd.context_name = None
        return root_ctx, cmd

    @staticmethod
    def _context_prefix(context: JuniperContextConfig) -> List[str]:
        if context.context_type == "logical-system":
            return ["logical-systems", context.name.lower()]
        if context.context_type == "tenant":
            return ["tenants", context.name.lower()]
        return []

    def parse_raw(self) -> JuniperSRXConfig:
        """Helper for backward compatibility returning parsed source config."""
        self.extract()
        return self.config

    def transform_to_ir(self) -> IRConfig:
        """Helper for backward compatibility returning canonical IRConfig."""
        return self.extract().canonical_ir
