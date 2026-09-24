"""Authoritative parser orchestrator for Juniper JunOS SRX 'display set' configurations."""

from __future__ import annotations

from typing import Dict, Optional

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.vendors.juniper_srx.hierarchy_parser import looks_hierarchical, normalize_hierarchy
from fwmigrate.vendors.juniper_srx.handlers.address_book import handle_address_book_command
from fwmigrate.vendors.juniper_srx.handlers.applications import handle_applications_command
from fwmigrate.vendors.juniper_srx.handlers.appsecure import handle_appsecure_command
from fwmigrate.vendors.juniper_srx.handlers.interfaces import handle_interfaces_command
from fwmigrate.vendors.juniper_srx.handlers.chassis_cluster import handle_chassis_cluster_command
from fwmigrate.vendors.juniper_srx.handlers.vlans import handle_vlans_command
from fwmigrate.vendors.juniper_srx.handlers.groups import handle_groups_command
from fwmigrate.vendors.juniper_srx.handlers.nat import handle_nat_command
from fwmigrate.vendors.juniper_srx.handlers.policies import handle_policies_command
from fwmigrate.vendors.juniper_srx.handlers.routing import handle_routing_command
from fwmigrate.vendors.juniper_srx.handlers.schedulers import handle_schedulers_command
from fwmigrate.vendors.juniper_srx.handlers.system import (
    classify_system_branch,
    handle_system_command,
    preserve_context_system_command,
)
from fwmigrate.vendors.juniper_srx.handlers.vpn import handle_vpn_command
from fwmigrate.vendors.juniper_srx.handlers.access import handle_access_command
from fwmigrate.vendors.juniper_srx.handlers.dynamic_vpn import handle_dynamic_vpn_command
from fwmigrate.vendors.juniper_srx.handlers.user_identification import handle_user_identification_command
from fwmigrate.vendors.juniper_srx.handlers.utm import handle_utm_command
from fwmigrate.vendors.juniper_srx.handlers.idp import handle_idp_command
from fwmigrate.vendors.juniper_srx.handlers.ssl_proxy import handle_ssl_proxy_command
from fwmigrate.vendors.juniper_srx.handlers.security_intelligence import handle_security_intelligence_command
from fwmigrate.vendors.juniper_srx.handlers.zones import handle_zones_command
from fwmigrate.vendors.juniper_srx.handlers.firewall_filters import handle_firewall_filter_command
from fwmigrate.vendors.juniper_srx.handlers.screens import handle_screens_command
from fwmigrate.vendors.juniper_srx.handlers.class_of_service import handle_class_of_service_command
from fwmigrate.vendors.juniper_srx.handlers.policy_options import handle_policy_options_command
from fwmigrate.vendors.juniper_srx.handlers.dhcp import handle_dhcp_command
from fwmigrate.vendors.juniper_srx.handlers.apbr import handle_apbr_command
from fwmigrate.vendors.juniper_srx.handlers.remote_access import handle_remote_access_command
from fwmigrate.vendors.juniper_srx.handlers.link_monitor import handle_link_monitor_command
from fwmigrate.vendors.juniper_srx.handlers.rpm import handle_rpm_command
from fwmigrate.vendors.juniper_srx.handlers.chassis import handle_chassis_command
from fwmigrate.vendors.juniper_srx.handlers.snmp import handle_snmp_command
from fwmigrate.vendors.juniper_srx.handlers.pki import handle_pki_command
from fwmigrate.vendors.juniper_srx.handlers.security_flow import handle_security_flow_command
from fwmigrate.vendors.juniper_srx.model import (
    JuniperContextConfig,
    JuniperSRXConfig,
    JuniperActivationDirective,
)
from fwmigrate.vendors.juniper_srx.tokenizer import (
    JuniperSetTokenizer,
    JunosCommand,
    JunosOperation,
    validate_input_mode,
)


class JuniperSRXParser:
    """Parser orchestrator for JunOS SRX firewall configurations in 'set' format."""

    def __init__(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> None:
        self.content = content
        self.zone_mapping = zone_mapping or {}
        self.tokenizer = JuniperSetTokenizer()
        self.config = JuniperSRXConfig()

    def extract_source(self) -> JuniperSRXConfig:
        """Parse and evaluate Junos without entering the legacy IR path."""
        self.config = JuniperSRXConfig()
        source_format = (
            "junos_hierarchical"
            if looks_hierarchical(self.content)
            else "junos_display_set"
        )
        source = normalize_hierarchy(self.content) if source_format == "junos_hierarchical" else self.content
        commands = self.tokenizer.tokenize(source)
        self.source_format = source_format
        self.commands = commands

        # 1. Conservative relative display-set validation
        validate_input_mode(commands)

        # 2. Preserve activation as source evidence and dispatch only explicit SET statements.
        for cmd in commands:
            if cmd.operation in (JunosOperation.ACTIVATE, JunosOperation.DEACTIVATE):
                context, effective_cmd = self._normalize_context(cmd)
                if effective_cmd.parse_error:
                    cmd.parse_error = effective_cmd.parse_error
                    cmd.extraction_status = ExtractionStatus.PARSE_ERROR
                    self.config.unsupported_commands.append(cmd.to_sanitized_copy())
                    continue
                self.config.activation_directives.append(JuniperActivationDirective(
                    operation=cmd.operation.value,
                    hierarchy_path=tuple(effective_cmd.tokens[1:]),
                    context_type=context.context_type,
                    context_name=context.name if context.context_type != "root" else None,
                    source_order=cmd.line_number,
                    line_number=cmd.line_number,
                ))
                cmd.consumed = True
                cmd.handler = "activation"
                cmd.extraction_status = ExtractionStatus.EXTRACTED
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
                    ExtractionStatus.EXTRACTED if len(effective_cmd.tokens) == 3
                    else ExtractionStatus.SOURCE_ONLY
                )
                continue

            # Handler dispatch chain
            handled = (
                handle_dhcp_command(effective_cmd, context)
                or handle_apbr_command(effective_cmd, context)
                or handle_remote_access_command(effective_cmd, context)
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

            if handled and cmd.extraction_status == ExtractionStatus.EXTRACTED and cmd.remaining_tokens:
                cmd.extraction_status = ExtractionStatus.PARTIAL
                cmd.requires_manual_review = True

            if not handled:
                cmd.consumed = False
                cmd.extraction_status = ExtractionStatus.UNSUPPORTED
                self.config.unsupported_commands.append(cmd.to_sanitized_copy())

        return self.config

    def _handle_system_for_context(self, cmd: JunosCommand, context: JuniperContextConfig) -> bool:
        classification = classify_system_branch(cmd, context.context_type)
        if classification == "not-system":
            return False
        if context.context_type != "root" and classification != "context-local":
            return preserve_context_system_command(cmd, context)
        return handle_system_command(cmd, self.config, context if context.context_type != "root" else None)

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

