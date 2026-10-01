"""Evaluate Junos commands into explicit Juniper source state."""

from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.vendors.juniper_srx.handlers.access import handle_access_command
from fwmigrate.vendors.juniper_srx.handlers.address_book import handle_address_book_command
from fwmigrate.vendors.juniper_srx.handlers.applications import handle_applications_command
from fwmigrate.vendors.juniper_srx.handlers.appsecure import handle_appsecure_command
from fwmigrate.vendors.juniper_srx.handlers.apbr import handle_apbr_command
from fwmigrate.vendors.juniper_srx.handlers.chassis import handle_chassis_command
from fwmigrate.vendors.juniper_srx.handlers.chassis_cluster import handle_chassis_cluster_command
from fwmigrate.vendors.juniper_srx.handlers.class_of_service import handle_class_of_service_command
from fwmigrate.vendors.juniper_srx.handlers.dhcp import handle_dhcp_command
from fwmigrate.vendors.juniper_srx.handlers.dynamic_vpn import handle_dynamic_vpn_command
from fwmigrate.vendors.juniper_srx.handlers.firewall_filters import handle_firewall_filter_command
from fwmigrate.vendors.juniper_srx.handlers.groups import handle_groups_command
from fwmigrate.vendors.juniper_srx.handlers.idp import handle_idp_command
from fwmigrate.vendors.juniper_srx.handlers.interfaces import handle_interfaces_command
from fwmigrate.vendors.juniper_srx.handlers.link_monitor import handle_link_monitor_command
from fwmigrate.vendors.juniper_srx.handlers.nat import handle_nat_command
from fwmigrate.vendors.juniper_srx.handlers.pki import handle_pki_command
from fwmigrate.vendors.juniper_srx.handlers.policies import handle_policies_command
from fwmigrate.vendors.juniper_srx.handlers.policy_options import handle_policy_options_command
from fwmigrate.vendors.juniper_srx.handlers.remote_access import handle_remote_access_command
from fwmigrate.vendors.juniper_srx.handlers.routing import handle_routing_command
from fwmigrate.vendors.juniper_srx.handlers.rpm import handle_rpm_command
from fwmigrate.vendors.juniper_srx.handlers.schedulers import handle_schedulers_command
from fwmigrate.vendors.juniper_srx.handlers.screens import handle_screens_command
from fwmigrate.vendors.juniper_srx.handlers.security_flow import handle_security_flow_command
from fwmigrate.vendors.juniper_srx.handlers.security_intelligence import handle_security_intelligence_command
from fwmigrate.vendors.juniper_srx.handlers.snmp import handle_snmp_command
from fwmigrate.vendors.juniper_srx.handlers.ssl_proxy import handle_ssl_proxy_command
from fwmigrate.vendors.juniper_srx.handlers.system import (
    classify_system_branch,
    handle_system_command,
    preserve_context_system_command,
)
from fwmigrate.vendors.juniper_srx.handlers.user_identification import handle_user_identification_command
from fwmigrate.vendors.juniper_srx.handlers.utm import handle_utm_command
from fwmigrate.vendors.juniper_srx.handlers.vlans import handle_vlans_command
from fwmigrate.vendors.juniper_srx.handlers.vpn import handle_vpn_command
from fwmigrate.vendors.juniper_srx.handlers.zones import handle_zones_command
from fwmigrate.vendors.juniper_srx.model import (
    JuniperActivationDirective,
    JuniperContextConfig,
    JuniperSRXConfig,
)
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand


class JuniperCommandEvaluator:
    """Apply Junos command semantics without performing syntax parsing."""

    def evaluate_global(self, cmd: JunosCommand, config: JuniperSRXConfig) -> bool:
        """Evaluate source commands whose semantics precede context stripping."""
        return handle_groups_command(cmd, config)

    def record_activation(
        self,
        original_cmd: JunosCommand,
        effective_cmd: JunosCommand,
        context: JuniperContextConfig,
        config: JuniperSRXConfig,
    ) -> None:
        """Preserve explicit activate/deactivate source state."""
        config.activation_directives.append(
            JuniperActivationDirective(
                operation=original_cmd.operation.value,
                hierarchy_path=tuple(effective_cmd.tokens[1:]),
                context_type=context.context_type,
                context_name=context.name if context.context_type != "root" else None,
                source_order=original_cmd.line_number,
                line_number=original_cmd.line_number,
            )
        )
        original_cmd.consumed = True
        original_cmd.handler = "activation"
        original_cmd.extraction_status = ExtractionStatus.EXTRACTED
        original_cmd.context_type = effective_cmd.context_type
        original_cmd.context_name = effective_cmd.context_name

    def evaluate_context(
        self,
        original_cmd: JunosCommand,
        effective_cmd: JunosCommand,
        context: JuniperContextConfig,
        config: JuniperSRXConfig,
    ) -> bool:
        """Evaluate one context-normalized explicit SET command."""
        if (
            context.context_type == "tenant"
            and len(effective_cmd.tokens) >= 3
            and effective_cmd.tokens[1].lower() == "security-profile"
        ):
            profile_name = effective_cmd.tokens[2]
            context.security_profile = profile_name
            context.source_attributes["security_profile"] = {
                "name": profile_name,
                "raw": effective_cmd.raw_sanitized,
                "line_number": effective_cmd.line_number,
            }
            effective_cmd.consumed = original_cmd.consumed = True
            effective_cmd.handler = original_cmd.handler = "security-profile"
            effective_cmd.extraction_status = original_cmd.extraction_status = (
                ExtractionStatus.EXTRACTED
                if len(effective_cmd.tokens) == 3
                else ExtractionStatus.SOURCE_ONLY
            )
            return True

        handled = (
            handle_dhcp_command(effective_cmd, context)
            or handle_apbr_command(effective_cmd, context)
            or handle_remote_access_command(effective_cmd, context)
            or self._handle_system_for_context(effective_cmd, context, config)
            or handle_snmp_command(effective_cmd, config)
            or handle_pki_command(effective_cmd, config)
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

        self._mirror_command_state(original_cmd, effective_cmd, config)

        if handled and original_cmd.extraction_status == ExtractionStatus.EXTRACTED and original_cmd.remaining_tokens:
            original_cmd.extraction_status = ExtractionStatus.PARTIAL
            original_cmd.requires_manual_review = True

        if not handled:
            original_cmd.consumed = False
            original_cmd.extraction_status = ExtractionStatus.UNSUPPORTED
            config.unsupported_commands.append(original_cmd.to_sanitized_copy())

        return handled

    @staticmethod
    def _mirror_command_state(
        original_cmd: JunosCommand,
        effective_cmd: JunosCommand,
        config: JuniperSRXConfig,
    ) -> None:
        original_cmd.consumed = effective_cmd.consumed
        original_cmd.handler = effective_cmd.handler
        if effective_cmd.extraction_status:
            original_cmd.extraction_status = effective_cmd.extraction_status
        if effective_cmd.parse_error:
            original_cmd.parse_error = effective_cmd.parse_error
            config.unsupported_commands.append(original_cmd.to_sanitized_copy())
        original_cmd.consumed_tokens = effective_cmd.consumed_tokens
        original_cmd.remaining_tokens = effective_cmd.remaining_tokens
        original_cmd.context_type = effective_cmd.context_type
        original_cmd.context_name = effective_cmd.context_name

    @staticmethod
    def _handle_system_for_context(
        cmd: JunosCommand,
        context: JuniperContextConfig,
        config: JuniperSRXConfig,
    ) -> bool:
        classification = classify_system_branch(cmd, context.context_type)
        if classification == "not-system":
            return False
        if context.context_type != "root" and classification != "context-local":
            return preserve_context_system_command(cmd, context)
        return handle_system_command(cmd, config, context if context.context_type != "root" else None)


__all__ = ["JuniperCommandEvaluator"]
