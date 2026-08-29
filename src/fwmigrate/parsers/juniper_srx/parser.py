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
                self.config.unsupported_commands.append(cmd)

        # 4. Transform to Canonical IR
        transformer = JuniperToIRTransformer(self.config, zone_mapping=self.zone_mapping)
        canonical_ir = transformer.transform()

        # 5. Build ExtractionResult with 100% command-level accounting
        return build_extraction_result(commands, canonical_ir)

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
