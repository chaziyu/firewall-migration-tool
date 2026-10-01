"""Authoritative parser orchestrator for Juniper JunOS SRX source configurations."""

from __future__ import annotations

from typing import Dict, Optional

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.vendors.juniper_srx.command_evaluator import JuniperCommandEvaluator
from fwmigrate.vendors.juniper_srx.hierarchy_parser import (
    looks_hierarchical,
    normalize_hierarchy_with_provenance,
)
from fwmigrate.vendors.juniper_srx.model import JuniperContextConfig, JuniperSRXConfig
from fwmigrate.vendors.juniper_srx.tokenizer import (
    JuniperSetTokenizer,
    JunosCommand,
    JunosOperation,
    validate_input_mode,
)


class JuniperSRXParser:
    """Parse Junos source structure and delegate vendor semantics to the evaluator."""

    def __init__(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> None:
        self.content = content
        self.zone_mapping = zone_mapping or {}
        self.tokenizer = JuniperSetTokenizer()
        self.evaluator = JuniperCommandEvaluator()
        self.config = JuniperSRXConfig()

    def extract_source(self) -> JuniperSRXConfig:
        """Parse explicit Junos source state without entering the legacy IR path."""
        self.config = JuniperSRXConfig()
        source_format = "junos_hierarchical" if looks_hierarchical(self.content) else "junos_display_set"
        if source_format == "junos_hierarchical":
            source, original_lines = normalize_hierarchy_with_provenance(self.content)
        else:
            source, original_lines = self.content, ()
        commands = self.tokenizer.tokenize(source)
        if original_lines:
            for command in commands:
                normalized_line = command.normalized_line_number or command.line_number
                if 1 <= normalized_line <= len(original_lines):
                    command.line_number = original_lines[normalized_line - 1]
        self.source_format = source_format
        self.commands = commands

        validate_input_mode(commands)

        for cmd in commands:
            if cmd.access_denied:
                _, effective_cmd = self._normalize_context(cmd)
                if effective_cmd.parse_error:
                    self._record_context_parse_error(cmd, effective_cmd)
                    continue
                cmd.consumed = True
                cmd.handler = "access-denied"
                cmd.extraction_status = ExtractionStatus.UNSUPPORTED
                cmd.requires_manual_review = True
                self.config.unsupported_commands.append(cmd.to_sanitized_copy())
                continue

            if cmd.operation in (JunosOperation.ACTIVATE, JunosOperation.DEACTIVATE):
                context, effective_cmd = self._normalize_context(cmd)
                if effective_cmd.parse_error:
                    self._record_context_parse_error(cmd, effective_cmd)
                    continue
                self.evaluator.record_activation(cmd, effective_cmd, context, self.config)
                continue

            if cmd.operation != JunosOperation.SET:
                continue

            if not cmd.tokens or len(cmd.tokens) < 2:
                cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                cmd.requires_manual_review = True
                continue

            if self.evaluator.evaluate_global(cmd, self.config):
                continue

            context, effective_cmd = self._normalize_context(cmd)
            if effective_cmd.parse_error:
                self._record_context_parse_error(cmd, effective_cmd)
                continue

            self.evaluator.evaluate_context(cmd, effective_cmd, context, self.config)

        return self.config

    def _record_context_parse_error(self, cmd: JunosCommand, effective_cmd: JunosCommand) -> None:
        cmd.parse_error = effective_cmd.parse_error
        cmd.extraction_status = ExtractionStatus.PARSE_ERROR
        cmd.requires_manual_review = True
        self.config.unsupported_commands.append(cmd.to_sanitized_copy())

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
            effective_cmd = self._context_command(cmd, stripped_tokens, ctx)
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
            tenant_name = toks[2]
            ctx = self.config.get_context(tenant_name, context_type="tenant")
            stripped_tokens = [toks[0]] + toks[3:]
            effective_cmd = self._context_command(cmd, stripped_tokens, ctx)
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
    def _context_command(
        cmd: JunosCommand,
        stripped_tokens: list[str],
        context: JuniperContextConfig,
    ) -> JunosCommand:
        return JunosCommand(
            operation=cmd.operation,
            tokens=stripped_tokens,
            raw_sanitized=cmd.raw_sanitized,
            line_number=cmd.line_number,
            normalized_line_number=cmd.normalized_line_number,
            original_tokens=list(cmd.tokens),
            normalized_tokens=list(stripped_tokens),
            context_type=context.context_type,
            context_name=context.name,
            access_denied=cmd.access_denied,
            requires_manual_review=cmd.requires_manual_review,
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
