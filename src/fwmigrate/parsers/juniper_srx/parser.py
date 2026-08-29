"""Authoritative parser orchestrator for Juniper JunOS SRX 'display set' configurations."""

from __future__ import annotations

from typing import Dict, List, Optional

from fwmigrate.extraction.models import ExtractionResult, ExtractionStatus
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.juniper_srx.coverage import build_extraction_result
from fwmigrate.parsers.juniper_srx.handlers.address_book import handle_address_book_command
from fwmigrate.parsers.juniper_srx.handlers.applications import handle_applications_command
from fwmigrate.parsers.juniper_srx.handlers.interfaces import handle_interfaces_command
from fwmigrate.parsers.juniper_srx.handlers.nat import handle_nat_command
from fwmigrate.parsers.juniper_srx.handlers.policies import handle_policies_command
from fwmigrate.parsers.juniper_srx.handlers.routing import handle_routing_command
from fwmigrate.parsers.juniper_srx.handlers.schedulers import handle_schedulers_command
from fwmigrate.parsers.juniper_srx.handlers.system import handle_system_command
from fwmigrate.parsers.juniper_srx.handlers.vpn import handle_vpn_command
from fwmigrate.parsers.juniper_srx.handlers.zones import handle_zones_command
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperSRXConfig
from fwmigrate.parsers.juniper_srx.tokenizer import (
    JuniperSetTokenizer,
    JunosActivationState,
    JunosCommand,
    JunosOperation,
    validate_input_mode,
)
from fwmigrate.parsers.juniper_srx.transformer import JuniperToIRTransformer


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
        commands = self.tokenizer.tokenize(self.content)

        # 1. Conservative relative display-set validation
        validate_input_mode(commands)

        # 2. Process activation/deactivation state
        self.activation_state.apply(commands)

        # 3. Dispatch set commands through domain handlers with context-prefix normalization
        for cmd in commands:
            if cmd.operation != JunosOperation.SET:
                continue

            if not cmd.tokens or len(cmd.tokens) < 2:
                cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                continue

            # Context prefix routing: root vs logical-systems <name> vs tenants <name>
            context, effective_cmd = self._normalize_context(cmd)

            # Handler dispatch chain
            handled = (
                handle_system_command(effective_cmd, self.config)
                or handle_interfaces_command(effective_cmd, context)
                or handle_address_book_command(effective_cmd, context)
                or handle_zones_command(effective_cmd, context)
                or handle_applications_command(effective_cmd, context)
                or handle_policies_command(effective_cmd, context)
                or handle_schedulers_command(effective_cmd, context)
                or handle_routing_command(effective_cmd, context)
                or handle_nat_command(effective_cmd, context)
                or handle_vpn_command(effective_cmd, context)
            )

            # Mirror consumption & handler state back to original command
            cmd.consumed = effective_cmd.consumed
            cmd.handler = effective_cmd.handler
            if effective_cmd.extraction_status:
                cmd.extraction_status = effective_cmd.extraction_status
            if effective_cmd.parse_error:
                cmd.parse_error = effective_cmd.parse_error

            if not handled:
                cmd.consumed = False
                cmd.extraction_status = ExtractionStatus.UNSUPPORTED
                self.config.unsupported_commands.append(cmd.to_sanitized_copy())

        # 4. Apply activation state to models
        self._apply_activation_state_to_models()

        # 5. Transform to Canonical IR
        transformer = JuniperToIRTransformer(self.config, zone_mapping=self.zone_mapping)
        canonical_ir = transformer.transform()

        # 6. Build ExtractionResult with 100% command-level accounting
        return build_extraction_result(commands, canonical_ir)

    def _apply_activation_state_to_models(self) -> None:
        """Apply activation state (deactivate/activate) to parsed source model objects."""
        for ctx_name, context in self.config.contexts.items():
            ctx_prefix = (
                ["logical-systems", ctx_name.lower()]
                if context.context_type == "logical-system"
                else (["tenants", ctx_name.lower()] if context.context_type == "tenant" else [])
            )

            # 1. Interfaces
            for intf in context.interfaces.values():
                intf_path = ctx_prefix + ["interfaces", intf.name.lower()]
                if self.activation_state.is_inactive(intf_path):
                    intf.disabled = True
                for unit in intf.units.values():
                    unit_path = intf_path + ["unit", str(unit.unit).lower()]
                    if intf.disabled or self.activation_state.is_inactive(unit_path):
                        unit.disabled = True

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

    def _normalize_context(self, cmd: JunosCommand) -> tuple[JuniperContextConfig, JunosCommand]:
        """Strip context prefix (logical-systems/tenants) and route to target context."""
        toks = cmd.tokens
        if len(toks) >= 4 and toks[1].lower() == "logical-systems":
            ls_name = toks[2]
            ctx = self.config.get_context(ls_name, context_type="logical-system")
            stripped_tokens = [toks[0]] + toks[3:]
            effective_cmd = JunosCommand(
                operation=cmd.operation,
                tokens=stripped_tokens,
                raw_sanitized=cmd.raw_sanitized,
                line_number=cmd.line_number,
            )
            return ctx, effective_cmd

        if len(toks) >= 4 and toks[1].lower() == "tenants":
            t_name = toks[2]
            ctx = self.config.get_context(t_name, context_type="tenant")
            stripped_tokens = [toks[0]] + toks[3:]
            effective_cmd = JunosCommand(
                operation=cmd.operation,
                tokens=stripped_tokens,
                raw_sanitized=cmd.raw_sanitized,
                line_number=cmd.line_number,
            )
            return ctx, effective_cmd

        root_ctx = self.config.get_context("root", context_type="root")
        return root_ctx, cmd

    def parse_raw(self) -> JuniperSRXConfig:
        """Helper for backward compatibility returning parsed source config."""
        self.extract()
        return self.config

    def transform_to_ir(self) -> IRConfig:
        """Helper for backward compatibility returning canonical IRConfig."""
        return self.extract().canonical_ir
