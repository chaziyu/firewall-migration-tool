from __future__ import annotations

import ipaddress
from typing import Any, Dict, Optional

from fwmigrate.core.constants import IR_KEYWORD_ANY
from fwmigrate.ir import IRConfig
from fwmigrate.ir.enums import IRRouteNextHopType, NATTranslationMode
from fwmigrate.ir.network import IRInterface
from fwmigrate.ir.metadata import IRMetadata
from fwmigrate.ir.routing import IRRoute


class FTDToIRTransformer:
    """Transform the parsed FTD text source model into canonical IR."""

    def __init__(self, config, zone_mapping: Optional[Dict[str, str]] = None):
        self.config = config
        self.zone_mapping = zone_mapping or {}

    @staticmethod
    def _ipv4_interface(address: Optional[str], mask: Optional[str]) -> tuple[Optional[str], Optional[str]]:
        if not address or not mask:
            return None, None
        try:
            return str(ipaddress.IPv4Interface(f"{address}/{mask}")), None
        except ValueError:
            return None, f"Invalid management IPv4 address/netmask: {address} {mask}"

    def transform(self) -> IRConfig:
        from .cli.parser import FTD_TEXT_GENERATION_BLOCK_REASON

        cfg = self.config
        interfaces: list[IRInterface] = []
        interface_names = {item.name for item in cfg.interfaces}
        interface_names.update(item.nameif for item in cfg.interfaces if item.nameif)
        for item in cfg.interfaces:
            ip_value, parse_error = self._ipv4_interface(item.ip, item.mask)
            interfaces.append(IRInterface(
                name=item.name,
                zone=self.zone_mapping.get(item.name)
                or self.zone_mapping.get(item.nameif or ""),
                ip=ip_value,
                description=item.description,
                mtu=item.mtu,
                status=not item.shutdown,
                interface_type="management" if item.management_only or item.name.lower().startswith("management") else "physical",
                addressing_mode="static" if item.ip and item.mask else None,
                ipv6_source_settings={"addresses": [address.model_dump() for address in item.ipv6_addresses]},
                additional_ipv6_addresses=[{
                    "source_address": address.raw,
                    "address": address.address,
                    "prefix_length": address.prefix_length,
                    "eui64": address.eui64, "link_local": address.link_local,
                    "standby": address.standby,
                } for address in item.ipv6_addresses],
                migration_status=item.migration_status,
                requires_manual_review=item.requires_manual_review or bool(parse_error),
                parse_errors=[parse_error] if parse_error else [],
                source_attributes={
                    **item.source_attributes,
                    "nameif": item.nameif,
                    "management_only": item.management_only,
                    "security_level": item.security_level,
                    "interface_type": item.interface_type,
                    "parent_interface": item.parent_interface,
                    "vlan_id": item.vlan_id,
                    "etherchannel_id": item.etherchannel_id,
                    "etherchannel_mode": item.etherchannel_mode,
                    "bridge_group": item.bridge_group,
                    "standby_ip": item.standby_ip,
                    "raw_lines": item.raw_lines,
                    "ftd_policy_zone_not_inferred": True,
                },
            ))

        routes = []
        for item in cfg.static_routes:
            reasons = list(item.review_reasons)
            if item.interface and item.interface not in interface_names:
                reasons.append(f"Unresolved FTD route interface reference: {item.interface}")
            routes.append(IRRoute(
                name=item.name, address_family=item.address_family, destination=item.destination,
                source_destination=item.raw_line, interface=item.interface, next_hop=item.gateway,
                next_hop_type=IRRouteNextHopType.IP_ADDRESS if item.gateway else IRRouteNextHopType.NONE,
                administrative_distance=item.administrative_distance,
                migration_status="PARSE_ERROR" if item.migration_status == "PARSE_ERROR" else "PARTIALLY_NORMALIZED" if reasons else item.migration_status,
                requires_manual_review=bool(reasons), review_reasons=reasons,
                parse_error=reasons[0] if item.migration_status == "PARSE_ERROR" else None,
                source_attributes={"raw_line": item.raw_line},
            ))
        return IRConfig(
            metadata=IRMetadata(
                source_vendor=cfg.source_vendor, source_product=cfg.source_product,
                input_type="ftd-text-evidence",
                source_attributes={
                    "input_source_type": "ftd-text-evidence",
                    "policy_extraction_supported": False,
                    "nat_extraction_supported": False,
                    "object_extraction_supported": False,
                    "management_settings": [item.model_dump() for item in cfg.management_settings],
                    "cmi_enabled": cfg.cmi_enabled,
                    "management_ipv4": cfg.management_ipv4,
                    "management_netmask": cfg.management_netmask,
                    "management_gateway": cfg.management_gateway,
                    "management_dns_servers": cfg.management_dns_servers,
                    "ssh_access_list": cfg.ssh_access_list,
                    "diagnostic_interface": cfg.diagnostic_interface,
                },
            ),
            interfaces=interfaces,
            routes=routes,
            generation_safe=False,
            requires_manual_review=True,
            generation_blocking_reasons=[FTD_TEXT_GENERATION_BLOCK_REASON],
        )


class FMCToIRTransformer:
    """Build canonical IR from FMC-specific adapter state."""

    def __init__(self, parser: Any):
        self.parser = parser

    def transform(self) -> IRConfig:
        parser = self.parser
        ir = IRConfig(metadata=IRMetadata(
            source_vendor="cisco_ftd",
            source_product="Cisco Secure Firewall Management Center / FTD",
            input_type="fmc-rest-export",
            source_context=parser.context,
        ))
        parser._parse_objects(ir)
        parser._parse_access_policies(ir)
        parser._parse_nat_policies(ir)
        parser._parse_pbr_policies(ir)
        ir.addresses.extend(parser._synthetic_addresses.values())
        ir.services.extend(parser._synthetic_services.values())

        for policy in ir.policies:
            raw = policy.source_extra_settings.get("fmc_rule")
            if not isinstance(raw, dict):
                continue
            source_ports = raw.get("sourcePorts")
            destination_ports = raw.get("destinationPorts")
            if source_ports:
                policy.source_extra_settings["fmc_source_ports"] = source_ports
                if not destination_ports:
                    policy.service = [IR_KEYWORD_ANY]
                    policy.source_service_references = [IR_KEYWORD_ANY]
                reason = (
                    "FMC source-port match is source-preserved; canonical policy IR "
                    "has no independent source-port criterion"
                )
                if reason not in policy.review_reasons:
                    policy.review_reasons.append(reason)
                policy.requires_manual_review = True
                policy.migration_status = "PARTIALLY_NORMALIZED"
            if policy.source_users or policy.source_user_groups:
                policy.identity_dependency_review = True
                reason = (
                    "FMC user/identity criteria require target identity-provider validation"
                )
                if reason not in policy.review_reasons:
                    policy.review_reasons.append(reason)
                policy.requires_manual_review = True
                policy.migration_status = "PARTIALLY_NORMALIZED"

        for rule in ir.nat_rules:
            raw = rule.source_attributes.get("fmc_nat_rule")
            if isinstance(raw, dict) and raw.get("id"):
                rule.source_attributes["fmc_rule_uuid"] = raw["id"]
            if rule.source_translation_mode == NATTranslationMode.DYNAMIC_IP:
                reason = (
                    "Address-only dynamic NAT is canonicalized, but target-generator "
                    "support must be validated"
                )
                if reason not in rule.review_reasons:
                    rule.review_reasons.append(reason)
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"

        if hasattr(parser, "_mark_nat_order_conflicts"):
            parser._mark_nat_order_conflicts(ir.nat_rules)
        if parser._unresolved:
            ir.generation_safe = False
            for item in parser._unresolved:
                owner = item.get("owner") if isinstance(item, dict) else None
                field = item.get("field") if isinstance(item, dict) else None
                reason = f"Unresolved FMC reference: {owner or 'unknown'} / {field or 'unknown'}"
                if reason not in ir.generation_blocking_reasons:
                    ir.generation_blocking_reasons.append(reason)
        if any(item.requires_manual_review for item in [*ir.policies, *ir.nat_rules]):
            ir.generation_safe = False
            reason = "FMC policy/NAT semantics require manual target validation"
            if reason not in ir.generation_blocking_reasons:
                ir.generation_blocking_reasons.append(reason)
        return ir


class FDMToIRTransformer:
    """Build canonical IR from FDM-specific adapter state."""

    def __init__(self, parser: Any):
        self.parser = parser

    def transform(self) -> IRConfig:
        parser = self.parser
        ir = IRConfig(metadata=IRMetadata(
            source_vendor="cisco_ftd",
            source_product="Cisco Firepower Device Manager / FTD",
            input_type="fdm-rest-export",
            source_context=parser.context,
        ))
        parser._parse_addresses(ir)
        parser._parse_network_groups(ir)
        parser._parse_services(ir)
        parser._parse_interfaces(ir)
        parser._parse_nat_policies(ir)
        if parser._unresolved:
            ir.generation_safe = False
            ir.generation_blocking_reasons.append("Unresolved FDM object/policy reference")
        if parser._unresolved or any(rule.requires_manual_review for rule in ir.nat_rules):
            ir.generation_safe = False
            reason = "FDM policy/NAT semantics require manual target validation"
            if reason not in ir.generation_blocking_reasons:
                ir.generation_blocking_reasons.append(reason)
        return ir


__all__ = ["FMCToIRTransformer", "FDMToIRTransformer", "FTDToIRTransformer"]
