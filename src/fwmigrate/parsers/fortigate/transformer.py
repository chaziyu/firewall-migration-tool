from ipaddress import ip_address
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from pydantic import ValidationError

from fwmigrate.parsers.fortigate.model import (
    FGConfig,
    FGInterface,
    FGFCTEMS,
    FGService,
    FGPolicy,
    FGSystemGlobal,
)
from fwmigrate.ir.core import (
    IRConfig,
    IRMetadata,
    IRZone,
    IRInterface,
    IRInterfaceSecondaryIP,
    IRAddress,
    IRAddressTaggingEntry,
    AddressType,
    IRAddressGroup,
    IRAddressGroupTaggingEntry,
    IRServiceCategory,
    IRService,
    IRServicePort,
    ServiceProtocol,
    IRServiceGroup,
    IRSchedule,
    IRTrafficShaper,
    IRProxyAddress,
    IRWebProxySettings,
    IRPolicy,
    PolicyAction,
    IRIPPool,
    IRVirtualIP,
    IRVirtualIPRealServer,
    IRNATRule,
    NATType,
    NATTranslationMode,
    IRVPNTunnel,
    IRVPNPhase2,
    IRRoute,
    IRAuditEntry,
    MigrationConfidence,
    IRSecurityProfileGroup,
    IRInternetService,
    IRInternetServiceDefinition,
    IRInternetServiceDefinitionEntry,
    IRInternetServiceDefinitionPortRange,
    IRZTNAProvider,
    IRSessionHelper,
    IRSessionTTLOverride,
    IRSessionTTLSettings,
    IRExecutionContext,
    IRScheduleGroup,
    IRFortiGateSourceRule,
    IRDHCPServer,
    IRDHCPIPRange,
    IRDHCPReservation,
    IRCertificate,
    IRIPSSensor,
    IRIPSSensorEntry,
    IRVirtualIPGroup,
    IRSDWAN,
    IRSDWANZone,
    IRSDWANMember,
    IRSDWANHealthCheck,
    IRSDWANSLA,
    IRSDWANRule,
    IRSDWANRuleSLA,
    IRSDWANDuplicationRule,
    IRSDWANNeighbor,
    IRUserLDAP,
    IRFSSOProvider,
    IRFSSOADGroup,
    IRUserSAML,
    IRLocalUser,
    IRUserGroup,
    IRUserGroupMatch,
    IRIdentityDependency,
    IRUserAuthenticationSettings,
    IRUserQuarantineSettings,
    IRAdministrator,
    IRAdminProfile,
    IRAdminProfilePermissionBlock,
    IRFortiToken,
    IRSSLVPNPortal,
    IRSSLVPNHostCheck,
    IRSSLVPNHostCheckItem,
    IRSSLVPNSettings,
    IRSSLVPNAuthenticationRule,
    IRDoSPolicy,
    IRDoSAnomaly,
    IRFirewallSniffer,
    IRAuthenticationScheme,
    IRAuthenticationRule,
    IRSSHKey,
    IRSystemSettings,
    IRDNSSettings,
    IRSourceConfigCommand,
    IRSourceConfigNode,
)
from fwmigrate.parsers.fortigate.session_helper_defaults import (
    classify_session_helper,
    protocol_number_to_name,
)
from fwmigrate.parsers.fortigate.net_utils import (
    normalize_ipv4_network,
    normalize_ipv4_prefix,
    normalize_ipv6_prefix,
    normalize_ipv6_network,
)
from fwmigrate.parsers.vendor_maps import normalize_to_ir
from fwmigrate.core.constants import IR_KEYWORD_ANY

from fwmigrate.parsers.fortigate.source_tree import FGSourceNode


FORTIGATE_RESERVED_ADDRESS_NAMES = {
    "all",
    "none",
    "FABRIC_DEVICE",
    "FIREWALL_AUTH_PORTAL_ADDRESS",
}

# These settings affect presentation or inventory labels only.  Every other
# value retained in FGPolicy.extra_settings is treated as potentially
# traffic-affecting until it is explicitly modeled.
COSMETIC_POLICY_SETTINGS = frozenset({
    "color",
    "label",
    "global_label",
})

SOURCE_ONLY_DEFAULT_ENABLED = {
    "policy-route-ipv4": True,
    "policy-route-ipv6": True,
    "local-in-policy-ipv4": True,
    "local-in-policy-ipv6": True,
}

SOURCE_ONLY_DEFAULT_ACTION = {
    "policy-route-ipv4": "permit",
    "policy-route-ipv6": "permit",
    "local-in-policy-ipv4": "deny",
    "local-in-policy-ipv6": "deny",
}

SOURCE_ONLY_ALLOWED_ACTIONS = {
    "policy-route-ipv4": frozenset({"permit", "deny"}),
    "policy-route-ipv6": frozenset({"permit", "deny"}),
    "local-in-policy-ipv4": frozenset({"accept", "deny"}),
    "local-in-policy-ipv6": frozenset({"accept", "deny"}),
}

FORTIOS_VRF_MIN = 0
FORTIOS_VRF_MAX = 251
NON_DEFAULT_INTERFACE_VRF_REVIEW = (
    "FortiGate interface uses non-default VRF and requires routing-instance "
    "migration review"
)

# These source keys are represented by typed interface fields emitted into IR.
# Source-only interface settings are intentionally not included: retaining a
# setting in FGInterface.source_attributes is not the same as normalizing its
# traffic behavior into IRInterface.
INTERFACE_NORMALIZED_SOURCE_SETTINGS = frozenset({
    "vdom",
    "source_context",
    "ip",
    "remote_ip",
    "allowaccess",
    "type",
    "role",
    "alias",
    "description",
    "vlanid",
    "interface",
    "vrf",
    "status",
    "mode",
    "username",
    "device_identification",
})

# Keep this allowlist deliberately small. These settings are presentation or
# low-risk inventory metadata and do not change forwarding or addressing.
INTERFACE_LOW_RISK_SOURCE_SETTINGS = frozenset({
    "color",
    "comment",
    "comments",
    "snmp_index",
})


def _normalize_interface_ip(value: Optional[str]) -> Optional[str]:
    """Normalize a FortiOS interface address without repairing invalid input."""
    if not value:
        return None

    normalized = normalize_ipv4_prefix(value)

    # 0.0.0.0/0 means no usable configured IP.
    if normalized == "0.0.0.0/0":
        return None

    return normalized


FORTIGATE_INTERFACE_SPEED_RE = re.compile(
    r"^(?P<rate>\d+)(?P<unit>G)?"
    r"(?P<mode>full|half|auto|cr4?|sr4?)$",
    re.IGNORECASE,
)


def _normalize_interface_speed(
    value: Optional[str],
) -> tuple[Optional[str], Optional[str]]:
    """Decode a FortiOS combined speed token without guessing unknown syntax."""
    if not value:
        return None, None

    raw = value.strip()
    if raw.lower() == "auto":
        return "auto", "auto"

    match = FORTIGATE_INTERFACE_SPEED_RE.fullmatch(raw)
    if not match:
        return None, None

    rate = int(match.group("rate"))
    if match.group("unit"):
        rate *= 1000

    mode = match.group("mode").lower()
    duplex = mode if mode in {"full", "half", "auto"} else None
    return str(rate), duplex


def _normalize_device_identification(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = value.lower()
    return normalized if normalized in {"enable", "disable"} else None


class FGToIRTransformer:
    def __init__(
        self,
        fg_config: FGConfig,
        zone_mapping: Optional[Dict[str, str]] = None,
    ):
        self.fg = fg_config

        source_version = None
        if fg_config.source_version:
            source_version = f"FortiOS {fg_config.source_version}"
            if fg_config.source_build:
                source_version += f" build {fg_config.source_build}"

        self.ir = IRConfig(
            metadata=IRMetadata(
                hostname=(
                    fg_config.system_global.hostname
                    if fg_config.system_global
                    else None
                ),
                source_vendor="fortigate",
                source_version=source_version,
            )
        )

        self.zone_mapping = zone_mapping or {}

        self._intf_to_zone: Dict[Tuple[str, str], str] = {}

        self._interface_by_name = {
            (interface.source_context, interface.name): interface
            for interface in self.fg.interfaces
        }

        self._sdwan_zone_names: Set[Tuple[str, str]] = set()

        for sdwan in self.fg.sdwans:
            source_context = sdwan.source_context or "root"
            self._sdwan_zone_names.update(
                (source_context, zone.name)
                for zone in sdwan.zones
            )
            self._sdwan_zone_names.update(
                (source_context, member.zone)
                for member in sdwan.members
            )

        # Map FortiGate system-zone members to their zone.
        self.fg_zone_intf_map: Dict[Tuple[str, str], str] = {}

        for system_zone in self.fg.system_zones:
            for member_intf in system_zone.interface:
                self.fg_zone_intf_map[
                    (system_zone.source_context, member_intf)
                ] = system_zone.name

            self.fg_zone_intf_map[
                (system_zone.source_context, system_zone.name)
            ] = system_zone.name

            self._intf_to_zone[
                (system_zone.source_context, system_zone.name)
            ] = system_zone.name

    def transform(self) -> IRConfig:
        self._transform_system_settings()
        self._transform_execution_contexts()
        self._transform_interfaces_and_zones()

        # Operational / traffic-behaviour settings.
        self._transform_dhcp_servers()

        self._transform_addresses()
        self._propagate_address_group_review()
        self._mark_address_group_family_collisions()
        self._transform_services()

        # ALG / session behaviour.
        self._transform_session_helpers()
        self._transform_session_ttl_overrides()
        self._transform_session_ttl_settings()

        self._transform_schedules()
        self._transform_schedule_groups()
        self._transform_traffic_shapers()
        self._transform_proxy_settings()
        self._transform_ips_sensors()
        self._transform_certificates()
        self._transform_ssh_keys()
        self._transform_identity()
        self._transform_user_authentication_settings()
        self._transform_user_quarantine()
        self._transform_administrator_inventory()
        self._transform_authentication_inventory()
        self._transform_policies()
        self._transform_source_only_rule_families()

        self._transform_ip_pools()
        self._transform_virtual_ips()
        self._transform_vip_groups()
        self._transform_nat()

        self._transform_vpn()
        self._transform_routes()
        self._transform_sdwan()

        self._transform_internet_services()
        self._transform_internet_service_definitions()
        self._transform_ztna_providers()
        self._transform_ssl_vpn()
        self._transform_dos_policies()
        self._transform_firewall_sniffers()
        return self.ir

    def _transform_system_settings(self) -> None:
        if self.fg.system_global:
            typed_settings = isinstance(self.fg.system_global, FGSystemGlobal)
            self.ir.system_settings = IRSystemSettings(
                hostname=self.fg.system_global.hostname,
                timezone=(self.fg.system_global.timezone if typed_settings else None),
                admin_https_port=(
                    self.fg.system_global.admin_sport if typed_settings else None
                ),
                source_attributes=(
                    dict(self.fg.system_global.extra_settings) if typed_settings else {}
                ),
            )

        if self.fg.dns:
            dns_source_attributes = dict(self.fg.dns.extra_settings)
            for field in (
                "protocol", "server_select_method", "domain",
                "interface_select_method", "interface", "source_ip",
                "source_ip6", "ssl_certificate", "timeout", "retry",
            ):
                value = getattr(self.fg.dns, field, None)
                if value is not None:
                    dns_source_attributes[field] = value
            self.ir.dns_settings = IRDNSSettings(
                primary=self.fg.dns.primary,
                secondary=self.fg.dns.secondary,
                source_attributes=dns_source_attributes,
            )

    def _transform_execution_contexts(self) -> None:
        for context in self.fg.execution_contexts:
            interpretation_changing = (
                context.central_nat == "enable"
                or context.ngfw_mode == "policy-based"
            )
            self.ir.execution_contexts.append(
                IRExecutionContext(
                    vdom=context.vdom,
                    scope=context.scope,
                    central_nat=context.central_nat,
                    ngfw_mode=context.ngfw_mode,
                    opmode=context.opmode,
                    requires_manual_review=interpretation_changing,
                    source_attributes=dict(context.extra_settings),
                )
            )

    def _transform_ips_sensors(self) -> None:
        """Preserve FortiGate IPS sensors as source-only inventory."""
        for sensor in self.fg.ips_sensors:
            entries = []

            for entry in sensor.entries:
                source_attributes = dict(entry.extra_settings)
                if entry.status == "enable":
                    enabled = True
                elif entry.status == "disable":
                    enabled = False
                else:
                    enabled = None
                    if entry.status is not None:
                        source_attributes["status"] = entry.status

                entries.append(
                    IRIPSSensorEntry(
                        source_id=entry.id,
                        source_signature_ids=list(entry.rules),
                        severities=list(entry.severity),
                        location=entry.location,
                        protocols=list(entry.protocol),
                        enabled=enabled,
                        action=entry.action,
                        rate_count=entry.rate_count,
                        rate_duration=entry.rate_duration,
                        quarantine=entry.quarantine,
                        quarantine_expiry=entry.quarantine_expiry,
                        source_attributes=source_attributes,
                    )
                )

            source_attributes = dict(sensor.extra_settings)
            if sensor.block_malicious_url == "enable":
                block_malicious_url = True
            elif sensor.block_malicious_url == "disable":
                block_malicious_url = False
            else:
                block_malicious_url = None
                if sensor.block_malicious_url is not None:
                    source_attributes["block_malicious_url"] = (
                        sensor.block_malicious_url
                    )

            self.ir.ips_sensors.append(
                IRIPSSensor(
                    name=sensor.name,
                    source_context=sensor.source_context,
                    description=sensor.comment,
                    block_malicious_url=block_malicious_url,
                    scan_botnet_connections=sensor.scan_botnet_connections,
                    entries=entries,
                    migration_status="EXTRACT_ONLY",
                    requires_manual_review=True,
                    source_attributes=source_attributes,
                )
            )

    def _transform_certificates(self) -> None:
        """Preserve safe certificate inventory without migration behavior."""
        for certificate in self.fg.certificates:
            source_attributes = dict(certificate.extra_settings)
            source_last_updated = None

            if certificate.last_updated is not None:
                try:
                    source_last_updated = datetime.fromtimestamp(
                        certificate.last_updated,
                        tz=timezone.utc,
                    )
                except (OverflowError, OSError, ValueError):
                    source_attributes["last_updated"] = certificate.last_updated

            is_factory_local = (
                certificate.certificate_type == "local"
                and (certificate.source or "").lower() == "factory"
            )
            requires_manual_review = (
                bool(certificate.parse_error)
                or not is_factory_local
                or not certificate.has_certificate
            )

            self.ir.certificates.append(
                IRCertificate(
                    name=certificate.name,
                    certificate_type=certificate.certificate_type,
                    source_range=certificate.range,
                    source_origin=certificate.source,
                    public_certificate_pem=certificate.public_certificate,
                    subject=certificate.subject,
                    issuer=certificate.issuer,
                    serial_number=certificate.serial_number,
                    valid_from=certificate.valid_from,
                    valid_until=certificate.valid_until,
                    public_key_algorithm=certificate.public_key_algorithm,
                    public_key_size=certificate.public_key_size,
                    signature_algorithm=certificate.signature_algorithm,
                    sha256_fingerprint=certificate.sha256_fingerprint,
                    is_self_signed=certificate.is_self_signed,
                    is_ca=certificate.is_ca,
                    has_certificate=certificate.has_certificate,
                    has_private_key=certificate.has_private_key,
                    private_key_encrypted=certificate.private_key_encrypted,
                    has_password=certificate.has_password,
                    description=certificate.comments,
                    source_last_updated=source_last_updated,
                    migration_status="EXTRACT_ONLY",
                    requires_manual_review=requires_manual_review,
                    parse_error=certificate.parse_error,
                    source_attributes=source_attributes,
                )
            )

    # ------------------------------------------------------------------
    # DHCP
    # ------------------------------------------------------------------

    def _transform_dhcp_servers(self) -> None:
        """
        Preserve FortiGate DHCP server configuration.

        DHCP configuration is migration-relevant but target-platform
        implementation varies. It is therefore retained as
        extraction-only inventory requiring manual review.
        """

        for server in self.fg.dhcp_servers:
            dns_servers = [
                value
                for value in (
                    server.dns_server1,
                    server.dns_server2,
                    server.dns_server3,
                )
                if value
            ]

            ip_ranges = [
                IRDHCPIPRange(
                    source_id=ip_range.id,
                    start_ip=ip_range.start_ip,
                    end_ip=ip_range.end_ip,
                    source_attributes=dict(
                        ip_range.extra_settings
                    ),
                )
                for ip_range in server.ip_ranges
            ]

            reservations = [
                IRDHCPReservation(
                    source_id=reservation.id,
                    ip_address=reservation.ip,
                    mac_address=reservation.mac,
                    source_attributes=dict(
                        reservation.extra_settings
                    ),
                )
                for reservation in server.reserved_addresses
            ]

            self.ir.dhcp_servers.append(
                IRDHCPServer(
                    source_id=server.id,
                    enabled=(
                        server.status != "disable"
                    ),
                    interface=server.interface,
                    default_gateway=server.default_gateway,
                    netmask=server.netmask,
                    lease_time_seconds=server.lease_time,
                    dns_service=server.dns_service,
                    dns_servers=dns_servers,
                    timezone_option=server.timezone_option,
                    ip_ranges=ip_ranges,
                    reservations=reservations,
                    migration_status="EXTRACT_ONLY",
                    requires_manual_review=True,
                    source_attributes=dict(
                        server.extra_settings
                    ),
                )
            )

    # ------------------------------------------------------------------
    # Session helpers / session TTL
    # ------------------------------------------------------------------

    def _transform_session_helpers(self) -> None:
        """
        Preserve FortiGate session-helper / ALG configuration.

        Session helpers affect traffic processing. They are not normal
        firewall service objects and must remain extraction-only data.
        """

        for helper in self.fg.session_helpers:
            classification = classify_session_helper(
                source_id=helper.id,
                name=helper.name,
                protocol=helper.protocol,
                port=helper.port,
            )

            self.ir.session_helpers.append(
                IRSessionHelper(
                    source_id=helper.id,
                    name=(
                        helper.name
                        or f"session-helper-{helper.id}"
                    ),
                    protocol_number=helper.protocol,
                    protocol_name=(
                        protocol_number_to_name(
                            helper.protocol
                        )
                    ),
                    port=helper.port,
                    classification=classification,
                    migration_status="EXTRACT_ONLY",
                    requires_manual_review=(
                        classification != "DEFAULT"
                    ),
                    source_attributes=dict(
                        helper.extra_settings
                    ),
                )
            )

    def _transform_session_ttl_overrides(
        self,
    ) -> None:
        """
        Preserve explicit FortiGate session timeout overrides.

        Session lifetime behaviour is target-platform dependent and
        therefore requires migration review.
        """

        for override in self.fg.session_ttl_overrides:
            self.ir.session_ttl_overrides.append(
                IRSessionTTLOverride(
                    source_id=override.id,
                    protocol_number=override.protocol,
                    protocol_name=(
                        protocol_number_to_name(
                            override.protocol
                        )
                    ),
                    start_port=override.start_port,
                    end_port=override.end_port,
                    timeout_seconds=override.timeout,
                    migration_status="EXTRACT_ONLY",
                    requires_manual_review=True,
                    source_attributes=dict(
                        override.extra_settings
                    ),
                )
            )

    def _transform_session_ttl_settings(self) -> None:
        settings = self.fg.session_ttl_settings
        if settings is None:
            return
        self.ir.session_ttl_settings = IRSessionTTLSettings(
            default_timeout_seconds=settings.default_timeout,
            source_attributes=dict(settings.extra_settings),
        )

    # ------------------------------------------------------------------
    # Internet services / ZTNA
    # ------------------------------------------------------------------

    def _transform_internet_services(
        self,
    ) -> None:
        for internet_service in self.fg.internet_services:
            self.ir.internet_services.append(
                IRInternetService(
                    name=internet_service.name,
                    source_id=internet_service.id,
                    description=internet_service.comment,
                    source_attributes=dict(
                        internet_service.extra_settings
                    ),
                )
            )

    @staticmethod
    def _has_meaningful_fctems_configuration(
        item: FGFCTEMS,
    ) -> bool:
        """
        Return True only when an FCTEMS entry contains meaningful data.

        FortiGate configurations may contain empty placeholders such as:

            edit 2
            next

        Such entries should not become ZTNA provider records.
        """

        return any(
            [
                item.name,
                item.status == "enable",
                item.fortinetone_cloud_authentication,
                item.serial_number,
                item.tenant_id,
                item.capabilities,
                item.verifying_ca,
                item.verified_cn,
                item.extra_settings,
            ]
        )

    def _transform_ztna_providers(
        self,
    ) -> None:
        """
        Preserve FortiClient EMS integrations as ZTNA /
        endpoint-posture dependencies.

        Provider configuration is retained for migration review but is
        not automatically converted into target-vendor configuration.
        """

        for connector in self.fg.fctems_connectors:
            if not self._has_meaningful_fctems_configuration(
                connector
            ):
                continue

            self.ir.ztna_providers.append(
                IRZTNAProvider(
                    name=(
                        connector.name
                        or f"FCTEMS_{connector.id}"
                    ),
                    provider_type=(
                        "endpoint-posture-provider"
                    ),
                    enabled=(
                        connector.status == "enable"
                    ),
                    source_vendor="fortigate",
                    source_id=str(connector.id),
                    source_serial=connector.serial_number,
                    source_tenant_id=connector.tenant_id,
                    source_cloud_authentication=(
                        connector.fortinetone_cloud_authentication
                        == "enable"
                        if connector.fortinetone_cloud_authentication
                        is not None
                        else None
                    ),
                    verifying_ca=connector.verifying_ca,
                    verified_cn=connector.verified_cn,
                    capabilities=list(
                        connector.capabilities
                    ),
                    source_attributes=dict(
                        connector.extra_settings
                    ),
                    migration_status="EXTRACT_ONLY",
                    requires_manual_review=True,
                    migration_instruction=(
                        "Source endpoint-posture/ZTNA provider "
                        "detected. Firewall policies reference "
                        "ZTNA EMS tags. Review the target platform's "
                        "endpoint posture/ZTNA architecture and "
                        "recreate equivalent access-control intent. "
                        "The FortiClient EMS connector itself is "
                        "not automatically migrated."
                    ),
                )
            )

    def _transform_sdwan(self) -> None:
        for fg_sdwan in self.fg.sdwans:
            source_context = fg_sdwan.source_context or "root"
            self.ir.sdwans.append(
                IRSDWAN(
                    source_context=source_context,
                    status=fg_sdwan.status,
                    load_balance_mode=fg_sdwan.load_balance_mode,
                    zones=[
                        IRSDWANZone(
                            name=zone.name,
                            source_context=zone.source_context or source_context,
                            source_attributes=dict(zone.extra_settings),
                        )
                        for zone in fg_sdwan.zones
                    ],
                    members=[
                        IRSDWANMember(
                            source_id=member.id,
                            source_context=member.source_context or source_context,
                            interface=member.interface,
                            zone=member.zone,
                            gateway=member.gateway,
                            source=member.source,
                            gateway6=member.gateway6,
                            source6=member.source6,
                            cost=member.cost,
                            weight=member.weight,
                            priority=member.priority,
                            priority6=member.priority6,
                            spillover_threshold=member.spillover_threshold,
                            ingress_spillover_threshold=member.ingress_spillover_threshold,
                            volume_ratio=member.volume_ratio,
                            status=member.status,
                            description=member.comment,
                            source_explicit_fields=sorted(member.source_explicit_fields),
                            source_attributes={
                                **dict(member.extra_settings),
                                **(
                                    {"cost": str(member.cost)}
                                    if member.cost is not None
                                    and "cost" in member.source_explicit_fields
                                    else {}
                                ),
                            },
                        )
                        for member in fg_sdwan.members
                    ],
                    health_checks=[
                        IRSDWANHealthCheck(
                            name=check.name,
                            source_context=check.source_context or source_context,
                            server=check.server,
                            member_ids=list(check.members),
                            protocol=check.protocol,
                            port=check.port,
                            interval=check.interval,
                            probe_timeout=check.probe_timeout,
                            failtime=check.failtime,
                            recoverytime=check.recoverytime,
                            update_static_route=check.update_static_route,
                            vrf=check.vrf,
                            source=check.source,
                            sla=[
                                IRSDWANSLA(
                                    source_id=sla.id,
                                    source_context=sla.source_context or source_context,
                                    source_attributes=dict(sla.extra_settings),
                                )
                                for sla in check.sla
                            ],
                            source_attributes={
                                **dict(check.extra_settings),
                                **(
                                    {"failtime": str(check.failtime)}
                                    if check.failtime is not None
                                    and "failtime" in check.source_explicit_fields
                                    else {}
                                ),
                            },
                            source_explicit_fields=sorted(check.source_explicit_fields),
                        )
                        for check in fg_sdwan.health_checks
                    ],
                    rules=[
                        IRSDWANRule(
                            source_id=rule.id,
                            source_context=rule.source_context or source_context,
                            name=rule.name,
                            mode=rule.mode,
                            status=rule.status,
                            source_addresses=list(rule.src),
                            destination_addresses=list(rule.dst),
                            health_check=(
                                rule.health_check[0]
                                if len(rule.health_check) == 1
                                else None
                            ),
                            health_checks=list(rule.health_check),
                            priority_member_ids=list(rule.priority_members),
                            priority_zones=list(rule.priority_zone),
                            internet_service=rule.internet_service,
                            internet_service_names=list(rule.internet_service_name),
                            internet_service_app_ctrl=list(rule.internet_service_app_ctrl),
                            sla_compare_method=rule.sla_compare_method,
                            tie_break=rule.tie_break,
                            use_shortcut_sla=rule.use_shortcut_sla,
                            sla=[
                                IRSDWANRuleSLA(
                                    name=sla.name,
                                    source_id=sla.id,
                                    source_context=sla.source_context or source_context,
                                    source_attributes=dict(sla.extra_settings),
                                )
                                for sla in rule.sla
                            ],
                            source_attributes={
                                **dict(rule.extra_settings),
                                **(
                                    {"tie_break": rule.tie_break}
                                    if rule.tie_break is not None
                                    and "tie_break" in rule.source_explicit_fields
                                    else {}
                                ),
                            },
                            source_explicit_fields=sorted(rule.source_explicit_fields),
                        )
                        for rule in fg_sdwan.services
                    ],
                    duplication_rules=[
                        IRSDWANDuplicationRule(
                            source_id=rule.id,
                            source_context=rule.source_context or source_context,
                            service_id=rule.service_id,
                            source_addresses=list(rule.srcaddr),
                            destination_addresses=list(rule.dstaddr),
                            source_addresses6=list(rule.srcaddr6),
                            destination_addresses6=list(rule.dstaddr6),
                            source_interfaces=list(rule.srcintf),
                            destination_interfaces=list(rule.dstintf),
                            services=list(rule.service),
                            packet_duplication=rule.packet_duplication,
                            sla_match_service=rule.sla_match_service,
                            packet_de_duplication=rule.packet_de_duplication,
                            source_attributes=dict(rule.extra_settings),
                        )
                        for rule in fg_sdwan.duplication_rules
                    ],
                    neighbors=[
                        IRSDWANNeighbor(
                            name=neighbor.name,
                            source_context=neighbor.source_context or source_context,
                            source_attributes=dict(neighbor.extra_settings),
                        )
                        for neighbor in fg_sdwan.neighbors
                    ],
                    source_attributes=dict(fg_sdwan.extra_settings),
                )
            )

    def _transform_identity(self) -> None:
        self.ir.user_ldap_servers.extend(
            IRUserLDAP(
                name=item.name,
                server=item.server,
                cnid=item.cnid,
                dn=item.dn,
                source_type=item.type,
                username=item.username,
                has_password=item.has_password,
                source_attributes=dict(item.extra_settings),
            )
            for item in self.fg.user_ldap_servers
        )
        self.ir.fsso_providers.extend(
            IRFSSOProvider(
                name=item.name,
                server=item.server,
                has_password=item.has_password,
                source_attributes=dict(item.extra_settings),
            )
            for item in self.fg.fsso_servers
        )

        fsso_provider_names = {item.name for item in self.fg.fsso_servers}
        for item in self.fg.ad_groups:
            provider_resolved = bool(
                item.server_name and item.server_name in fsso_provider_names
            )
            self.ir.fsso_ad_groups.append(
                IRFSSOADGroup(
                    name=item.name,
                    provider_name=item.server_name,
                    provider_resolved=provider_resolved,
                    source_attributes=dict(item.extra_settings),
                )
            )
            if item.server_name and not provider_resolved:
                self.ir.audit_entries.append(
                    IRAuditEntry(
                        id=f"identity:fsso-ad-group:{item.name}:provider",
                        category="Identity",
                        message=(
                            f"FSSO AD group '{item.name}' references missing "
                            f"FSSO provider '{item.server_name}'."
                        ),
                        confidence=MigrationConfidence.MANUAL,
                    )
                )

        self.ir.user_saml_servers.extend(
            IRUserSAML(
                name=item.name,
                entity_id=item.entity_id,
                single_sign_on_url=item.single_sign_on_url,
                single_logout_url=item.single_logout_url,
                idp_entity_id=item.idp_entity_id,
                idp_single_sign_on_url=item.idp_single_sign_on_url,
                idp_single_logout_url=item.idp_single_logout_url,
                idp_cert=item.idp_cert,
                user_name=item.user_name,
                group_name=item.group_name,
                digest_method=item.digest_method,
                source_attributes=dict(item.extra_settings),
            )
            for item in self.fg.user_saml_servers
        )
        self.ir.local_users.extend(
            IRLocalUser(
                name=item.name,
                status=item.status,
                source_type=item.type,
                has_password=item.has_password,
                source_attributes=dict(item.extra_settings),
            )
            for item in self.fg.local_users
        )
        self.ir.user_groups.extend(
            IRUserGroup(
                name=item.name,
                group_type=item.group_type,
                members=list(item.member),
                matches=[
                    IRUserGroupMatch(
                        source_id=match.id,
                        server_name=match.server_name,
                        group_name=match.group_name,
                    )
                    for match in item.match
                ],
                source_attributes=dict(item.extra_settings),
            )
            for item in self.fg.user_groups
        )
        self._validate_identity_dependencies()

    def _build_identity_dependency_indexes(self) -> Dict[str, Set[str]]:
        return {
            "local_users": {item.name for item in self.ir.local_users},
            "user_groups": {item.name for item in self.ir.user_groups},
            "ldap_servers": {item.name for item in self.ir.user_ldap_servers},
            "saml_servers": {item.name for item in self.ir.user_saml_servers},
            "fsso_providers": {item.name for item in self.ir.fsso_providers},
            "fsso_ad_groups": {item.name for item in self.ir.fsso_ad_groups},
            "fortitokens": {item.serial for item in self.ir.fortitokens},
            "admin_profiles": {item.name for item in self.ir.admin_profiles},
            "certificates": {item.name for item in self.ir.certificates},
            "authentication_schemes": {item.name for item in self.ir.authentication_schemes},
            "addresses": {item.name for item in self.ir.addresses},
            "address_groups": {item.name for item in self.ir.address_groups},
        }

    def _add_identity_audit(self, audit_id: str, message: str) -> None:
        if any(entry.id == audit_id for entry in self.ir.audit_entries):
            return
        self.ir.audit_entries.append(IRAuditEntry(
            id=audit_id,
            category="Identity Dependency",
            message=message,
            confidence=MigrationConfidence.MANUAL,
        ))

    def _validate_identity_dependencies(self) -> None:
        indexes = self._build_identity_dependency_indexes()
        for group in self.ir.user_groups:
            group.resolved_members = []
            group.unresolved_members = []
            group.member_dependencies = []
            if group.group_type == "fsso-service":
                candidates = (("fsso-ad-group", indexes["fsso_ad_groups"]),)
            else:
                candidates = (
                    ("local-user", indexes["local_users"]),
                    ("ldap-server", indexes["ldap_servers"]),
                    ("saml-server", indexes["saml_servers"]),
                    ("user-group", indexes["user_groups"] - {group.name}),
                    ("fsso-ad-group", indexes["fsso_ad_groups"]),
                )
            for member in group.members:
                dependency_type = "unknown"
                resolved = False
                for candidate_type, names in candidates:
                    if member in names:
                        dependency_type = candidate_type
                        resolved = True
                        break
                group.member_dependencies.append(IRIdentityDependency(
                    reference=member,
                    dependency_type=dependency_type,
                    resolved=resolved,
                    target_name=member if resolved else None,
                    source_context=f"user group {group.name}",
                ))
                (group.resolved_members if resolved else group.unresolved_members).append(member)

            compatible_match_servers = (
                indexes["ldap_servers"]
                | indexes["saml_servers"]
                | indexes["fsso_providers"]
            )

            group.unresolved_match_servers = [
                match.server_name
                for match in group.matches
                if match.server_name and match.server_name not in compatible_match_servers
            ]
            if group.unresolved_members:
                if group.group_type == "fsso-service" and len(group.unresolved_members) == 1:
                    member_message = (
                        f"User group '{group.name}' references missing FSSO AD group "
                        f"'{group.unresolved_members[0]}'."
                    )
                else:
                    member_message = (
                        f"User group '{group.name}' contains unresolved member reference(s): "
                        f"{', '.join(group.unresolved_members)}. Source values were preserved "
                        "and require manual review."
                    )
                self._add_identity_audit(
                    f"identity:user-group:{group.name}:members",
                    member_message,
                )
            if group.unresolved_match_servers:
                self._add_identity_audit(
                    f"identity:user-group:{group.name}:match-servers",
                    f"User group '{group.name}' contains unresolved match server "
                    f"reference(s): {', '.join(group.unresolved_match_servers)}. Source "
                    "values were preserved and require manual review.",
                )

        certificate_names = indexes["certificates"]
        for saml in self.ir.user_saml_servers:
            if saml.idp_cert is None:
                saml.idp_certificate_resolved = None
            elif saml.idp_cert in certificate_names:
                saml.idp_certificate_resolved = True
            else:
                saml.idp_certificate_resolved = False
                saml.unresolved_certificate_references = [saml.idp_cert]
                self._add_identity_audit(
                    f"identity:saml:{saml.name}:idp-cert",
                    f"SAML server '{saml.name}' references missing IdP certificate "
                    f"'{saml.idp_cert}'. The source reference was preserved and requires "
                    "manual review.",
                )

    def _transform_user_authentication_settings(self) -> None:
        settings = self.fg.user_authentication_settings
        if settings is None:
            return
        certificate_names = {item.name for item in self.ir.certificates}
        auth_resolved = None if settings.auth_cert is None else settings.auth_cert in certificate_names
        ca_resolved = None if settings.auth_ca_cert is None else settings.auth_ca_cert in certificate_names
        self.ir.user_authentication_settings = IRUserAuthenticationSettings(
            auth_certificate=settings.auth_cert,
            auth_certificate_resolved=auth_resolved,
            auth_ca_certificate=settings.auth_ca_cert,
            auth_ca_certificate_resolved=ca_resolved,
            auth_timeout=settings.auth_timeout,
            auth_lockout_threshold=settings.auth_lockout_threshold,
            auth_lockout_duration=settings.auth_lockout_duration,
            ssl_min_proto_version=settings.ssl_min_proto_version,
            source_attributes=dict(settings.extra_settings),
        )
        missing = [
            name for name, resolved in (
                (settings.auth_cert, auth_resolved),
                (settings.auth_ca_cert, ca_resolved),
            ) if name is not None and resolved is False
        ]
        if missing:
            self._add_identity_audit(
                "identity:user-authentication-settings:certificates",
                "User authentication settings contain unresolved certificate "
                f"reference(s): {', '.join(missing)}. Source values were preserved "
                "and require manual review.",
            )

    def _transform_user_quarantine(self) -> None:
        settings = self.fg.user_quarantine
        if settings is None:
            return
        address_group_names = {item.name for item in self.ir.address_groups}
        resolved = [name for name in settings.firewall_groups if name in address_group_names]
        unresolved = [name for name in settings.firewall_groups if name not in address_group_names]
        self.ir.user_quarantine_settings = IRUserQuarantineSettings(
            firewall_groups=list(settings.firewall_groups),
            resolved_firewall_groups=resolved,
            unresolved_firewall_groups=unresolved,
            source_attributes=dict(settings.extra_settings),
        )
        if unresolved:
            self._add_identity_audit(
                "identity:user-quarantine:firewall-groups",
                "User quarantine configuration references unresolved firewall group(s): "
                f"{', '.join(unresolved)}. Source references were preserved and require "
                "manual review.",
            )

    def _transform_ssl_vpn(self) -> None:
        self.ir.ssl_vpn_host_checks.extend(
            IRSSLVPNHostCheck(
                name=check.name,
                check_type=check.type,
                source_type=check.type,
                os_type=check.os_type,
                guid=check.guid,
                version=check.version,
                check_items=[
                    IRSSLVPNHostCheckItem(
                        source_id=item.id,
                        action=item.action,
                        md5s=list(item.md5s),
                        target=item.target,
                        check_type=item.type,
                        version=item.version,
                        source_attributes=dict(item.extra_settings),
                    )
                    for item in check.check_items
                ],
                source_attributes=dict(check.extra_settings),
            )
            for check in self.fg.ssl_vpn_host_check_software
        )
        self.ir.ssl_vpn_portals.extend(
            IRSSLVPNPortal(
                name=portal.name,
                tunnel_mode=portal.tunnel_mode,
                ipv6_tunnel_mode=portal.ipv6_tunnel_mode,
                ip_pools=list(portal.ip_pools),
                ipv6_pools=list(portal.ipv6_pools),
                split_tunneling=portal.split_tunneling,
                limit_user_logins=portal.limit_user_logins,
                forticlient_download=portal.forticlient_download,
                host_check=portal.host_check,
                host_check_policies=list(portal.host_check_policy),
                host_check_interval=portal.host_check_interval,
                allow_user_access=list(portal.allow_user_access),
                auto_connect=portal.auto_connect,
                exclusive_routing=portal.exclusive_routing,
                ip_mode=portal.ip_mode,
                service_restriction=portal.service_restriction,
                split_tunneling_routing_addresses=list(
                    portal.split_tunneling_routing_address
                ),
                split_tunneling_routing_negate=(
                    portal.split_tunneling_routing_negate
                ),
                host_checks=[
                    IRSSLVPNHostCheck(
                        name=check.name,
                        source_type=check.type,
                        guid=check.guid,
                        version=check.version,
                        source_attributes=dict(check.extra_settings),
                    )
                    for check in portal.host_checks
                ],
                source_attributes=dict(portal.extra_settings),
            )
            for portal in self.fg.ssl_vpn_portals
        )
        settings = self.fg.ssl_vpn_settings
        if settings is not None:
            self.ir.ssl_vpn_settings = IRSSLVPNSettings(
                status=settings.status,
                ssl_min_proto_ver=settings.ssl_min_proto_ver,
                banned_cipher=list(settings.banned_cipher),
                server_certificate=settings.servercert,
                server_certificate_configured=settings.servercert_configured,
                ssl_max_proto_ver=settings.ssl_max_proto_ver,
                algorithm=settings.algorithm,
                client_signature_algorithms=list(settings.client_sigalgs),
                require_client_certificate=settings.reqclientcert,
                dtls_tunnel=settings.dtls_tunnel,
                login_attempt_limit=settings.login_attempt_limit,
                login_block_time=settings.login_block_time,
                auth_timeout=settings.auth_timeout,
                idle_timeout=settings.idle_timeout,
                port=settings.port,
                dns_server1=settings.dns_server1,
                dns_server2=settings.dns_server2,
                wins_server1=settings.wins_server1,
                wins_server2=settings.wins_server2,
                source_interfaces=list(settings.source_interface),
                source_addresses=list(settings.source_address),
                tunnel_ip_pools=list(settings.tunnel_ip_pools),
                default_portal=settings.default_portal,
                authentication_rules=[
                    IRSSLVPNAuthenticationRule(
                        source_id=rule.id,
                        auth=rule.auth,
                        cipher=rule.cipher,
                        client_cert=rule.client_cert,
                        realm=rule.realm,
                        source_addresses=list(rule.source_address),
                        source_address_negate=rule.source_address_negate,
                        source_addresses6=list(rule.source_address6),
                        source_address6_negate=rule.source_address6_negate,
                        source_interfaces=list(rule.source_interface),
                        user_peer=rule.user_peer,
                        users=list(rule.users),
                        groups=list(rule.groups),
                        portal=rule.portal,
                        source_attributes=dict(rule.extra_settings),
                    )
                    for rule in settings.authentication_rules
                ],
                source_attributes=dict(settings.extra_settings),
            )
        self._validate_ssl_vpn_references()

    def _validate_ssl_vpn_references(self) -> None:
        host_check_names = {item.name for item in self.ir.ssl_vpn_host_checks}
        portal_names = {item.name for item in self.ir.ssl_vpn_portals}
        group_names = {item.name for item in self.ir.user_groups}
        ipv4_address_names = {
            item.name for item in self.ir.addresses
            if item.address_family != "ipv6"
        }
        ipv4_address_names.update(
            item.name for item in self.ir.address_groups
            if item.address_family != "ipv6"
        )
        ipv6_address_names = {
            item.name for item in self.ir.addresses
            if item.address_family == "ipv6"
        }
        ipv6_address_names.update(
            item.name for item in self.ir.address_groups
            if item.address_family == "ipv6"
        )
        ipv4_pool_names = {
            item.name for item in self.ir.ip_pools if item.address_family == "ipv4"
        }
        ipv6_pool_names = {
            item.name for item in self.ir.ip_pools if item.address_family == "ipv6"
        }

        def add_audit(audit_id: str, message: str) -> None:
            if any(entry.id == audit_id for entry in self.ir.audit_entries):
                return
            self.ir.audit_entries.append(
                IRAuditEntry(
                    id=audit_id,
                    category="SSL VPN",
                    message=message,
                    confidence=MigrationConfidence.MANUAL,
                )
            )

        for portal in self.ir.ssl_vpn_portals:
            missing_checks = [
                name for name in portal.host_check_policies
                if name not in host_check_names
            ]
            portal.unresolved_host_check_policies = missing_checks
            if missing_checks:
                add_audit(
                    f"ssl-vpn-portal:{portal.name}:host-check-policy",
                    f"SSL VPN portal '{portal.name}' references missing "
                    f"host-check software object(s): {', '.join(missing_checks)}. "
                    "Source references were preserved and require manual review.",
                )

            for label, references, known in (
                (
                    "IPv4 pool", portal.ip_pools,
                    ipv4_address_names | ipv4_pool_names,
                ),
                (
                    "IPv6 pool", portal.ipv6_pools,
                    ipv6_address_names | ipv6_pool_names,
                ),
                (
                    "split-tunneling routing address",
                    portal.split_tunneling_routing_addresses,
                    ipv4_address_names,
                ),
            ):
                missing = [name for name in references if name not in known]
                if missing:
                    key = label.lower().replace(" ", "-")
                    add_audit(
                        f"ssl-vpn-portal:{portal.name}:{key}",
                        f"SSL VPN portal '{portal.name}' references missing "
                        f"{label} object(s): {', '.join(missing)}. Source "
                        "references were preserved and require manual review.",
                    )

        settings = self.ir.ssl_vpn_settings
        if settings is None:
            return
        if settings.default_portal and settings.default_portal not in portal_names:
            add_audit(
                "ssl-vpn-settings:default-portal",
                f"SSL VPN settings reference missing default portal "
                f"'{settings.default_portal}'. The source reference was preserved "
                "and requires manual review.",
            )
        for label, references, known in (
            ("source address", settings.source_addresses, ipv4_address_names),
            (
                "tunnel IP pool",
                settings.tunnel_ip_pools,
                ipv4_address_names | ipv4_pool_names,
            ),
        ):
            missing = [name for name in references if name not in known]
            if missing:
                key = label.lower().replace(" ", "-")
                add_audit(
                    f"ssl-vpn-settings:{key}",
                    f"SSL VPN settings reference missing {label} object(s): "
                    f"{', '.join(missing)}. Source references were preserved and "
                    "require manual review.",
                )

        for rule in settings.authentication_rules:
            if rule.portal and rule.portal not in portal_names:
                add_audit(
                    f"ssl-vpn-auth-rule:{rule.source_id}:portal",
                    f"SSL VPN authentication rule '{rule.source_id}' references "
                    f"missing portal '{rule.portal}'. The source reference was "
                    "preserved and requires manual review.",
                )
            missing_groups = [name for name in rule.groups if name not in group_names]
            rule.unresolved_groups = missing_groups
            if missing_groups:
                add_audit(
                    f"ssl-vpn-auth-rule:{rule.source_id}:groups",
                    f"SSL VPN authentication rule '{rule.source_id}' references "
                    f"missing user group(s): {', '.join(missing_groups)}. Source "
                    "references were preserved and require manual review.",
                )
            for family, references, known in (
                ("IPv4", rule.source_addresses, ipv4_address_names),
                ("IPv6", rule.source_addresses6, ipv6_address_names),
            ):
                missing = [name for name in references if name not in known]
                if missing:
                    add_audit(
                        f"ssl-vpn-auth-rule:{rule.source_id}:{family.lower()}-source-address",
                        f"SSL VPN authentication rule '{rule.source_id}' references "
                        f"missing {family} source address object(s): "
                        f"{', '.join(missing)}. Source references were preserved and "
                        "require manual review.",
                    )

    def _transform_internet_service_definitions(self) -> None:
        for definition in self.fg.internet_service_definitions:
            self.ir.internet_service_definitions.append(
                IRInternetServiceDefinition(
                    source_id=definition.id,
                    entries=[
                        IRInternetServiceDefinitionEntry(
                            source_sequence=entry.seq_num,
                            category_id=entry.category_id,
                            name=entry.name,
                            protocol_number=entry.protocol,
                            port_ranges=[
                                IRInternetServiceDefinitionPortRange(
                                    source_id=port_range.id,
                                    start_port=port_range.start_port,
                                    end_port=port_range.end_port,
                                    source_attributes=dict(port_range.extra_settings),
                                )
                                for port_range in entry.port_ranges
                            ],
                            source_attributes=dict(entry.extra_settings),
                        )
                        for entry in definition.entries
                    ],
                    source_attributes=dict(definition.extra_settings),
                )
            )

    def _transform_administrator_inventory(self) -> None:
        self.ir.administrators.extend(
            IRAdministrator(
                name=item.name,
                access_profile=item.accprofile,
                vdoms=list(item.vdom),
                trusthost1=item.trusthost1,
                trusthost2=item.trusthost2,
                trusted_hosts_ipv4=[
                    value for value in (
                        item.trusthost1, item.trusthost2, item.trusthost3,
                        item.trusthost4, item.trusthost5, item.trusthost6,
                        item.trusthost7, item.trusthost8, item.trusthost9,
                        item.trusthost10,
                    ) if value is not None
                ],
                trusted_hosts_ipv6=[
                    value for value in (
                        item.ip6_trusthost1, item.ip6_trusthost2,
                        item.ip6_trusthost3, item.ip6_trusthost4,
                        item.ip6_trusthost5, item.ip6_trusthost6,
                        item.ip6_trusthost7, item.ip6_trusthost8,
                        item.ip6_trusthost9, item.ip6_trusthost10,
                    ) if value is not None
                ],
                two_factor=item.two_factor,
                token_reference=item.fortitoken,
                email_to=item.email_to,
                remote_auth=item.remote_auth,
                remote_group=item.remote_group,
                guest_user_groups=list(item.guest_usergroups),
                schedule=item.schedule,
                peer_auth=item.peer_auth,
                peer_group=item.peer_group,
                ssh_certificate=item.ssh_certificate,
                ssh_public_keys=[
                    value for value in (
                        item.ssh_public_key1, item.ssh_public_key2,
                        item.ssh_public_key3,
                    ) if value is not None
                ],
                credential_configured=item.credential_configured,
                source_attributes={
                    **dict(item.extra_settings),
                    **{
                        key: value
                        for key, value in {
                            "accprofile_override": item.accprofile_override,
                            "vdom_override": item.vdom_override,
                            "two_factor_authentication": item.two_factor_authentication,
                            "two_factor_notification": item.two_factor_notification,
                            "guest_auth": item.guest_auth,
                            "guest_lang": item.guest_lang,
                            "wildcard": item.wildcard,
                        }.items()
                        if value is not None
                    },
                },
            )
            for item in self.fg.administrators
        )
        self.ir.admin_profiles.extend(
            IRAdminProfile(
                name=item.name,
                permission_blocks=[
                    IRAdminProfilePermissionBlock(
                        name=block.name,
                        settings=dict(block.settings),
                        source_attributes=dict(block.extra_settings),
                    )
                    for block in item.permission_blocks
                ],
                source_attributes=dict(item.extra_settings),
            )
            for item in self.fg.admin_profiles
        )
        self.ir.fortitokens.extend(
            IRFortiToken(
                serial=item.serial,
                status=item.status,
                assigned_user=item.assigned_user,
                description=item.comments,
                source_attributes=dict(item.extra_settings),
            )
            for item in self.fg.fortitokens
        )
        token_names = {item.serial for item in self.ir.fortitokens}
        custom_profiles = {item.name for item in self.ir.admin_profiles}
        built_in_profiles = {"super_admin", "super_admin_readonly"}
        for admin in self.ir.administrators:
            if admin.token_reference is not None:
                admin.fortitoken_resolved = admin.token_reference in token_names
                if not admin.fortitoken_resolved:
                    admin.unresolved_references.append(admin.token_reference)
                    self._add_identity_audit(
                        f"identity:administrator:{admin.name}:fortitoken",
                        f"Administrator '{admin.name}' references missing FortiToken "
                        f"'{admin.token_reference}'. The source reference was preserved "
                        "and requires manual review.",
                    )
            if admin.access_profile is not None:
                admin.access_profile_resolved = (
                    admin.access_profile in custom_profiles
                    or admin.access_profile in built_in_profiles
                )
                if not admin.access_profile_resolved:
                    admin.unresolved_references.append(admin.access_profile)
                    self._add_identity_audit(
                        f"identity:administrator:{admin.name}:access-profile",
                        f"Administrator '{admin.name}' references unresolved access "
                        f"profile '{admin.access_profile}'. The source reference was "
                        "preserved and requires manual review.",
                    )

    def _transform_dos_policies(self) -> None:
        self.ir.dos_policies.extend(
            IRDoSPolicy(
                source_id=policy.id,
                source_context=policy.source_context,
                address_family=policy.address_family,
                status=policy.status,
                interface=policy.interface,
                source_addresses=list(policy.srcaddr),
                destination_addresses=list(policy.dstaddr),
                services=list(policy.service),
                description=policy.comments,
                anomalies=[
                    IRDoSAnomaly(
                        name=anomaly.name,
                        status=anomaly.status,
                        log=anomaly.log,
                        action=anomaly.action,
                        threshold=anomaly.threshold,
                        source_attributes=dict(anomaly.extra_settings),
                    )
                    for anomaly in policy.anomalies
                ],
                source_attributes=dict(policy.extra_settings),
            )
            for policy in self.fg.dos_policies
        )

    def _transform_firewall_sniffers(self) -> None:
        self.ir.firewall_sniffers.extend(
            IRFirewallSniffer(
                source_id=item.id,
                source_uuid=item.uuid,
                logtraffic=item.logtraffic,
                ipv6=item.ipv6,
                non_ip=item.non_ip,
                application_list_status=item.application_list_status,
                application_list=item.application_list,
                ips_sensor_status=item.ips_sensor_status,
                ips_sensor=item.ips_sensor,
                av_profile_status=item.av_profile_status,
                av_profile=item.av_profile,
                webfilter_profile_status=item.webfilter_profile_status,
                webfilter_profile=item.webfilter_profile,
                source_attributes=dict(item.extra_settings),
            )
            for item in self.fg.firewall_sniffers
        )

    def _transform_authentication_inventory(self) -> None:
        self.ir.authentication_schemes.extend(
            IRAuthenticationScheme(
                name=item.name,
                method=item.method,
                user_database=item.user_database,
                source_attributes=dict(item.extra_settings),
            )
            for item in self.fg.authentication_schemes
        )
        self.ir.authentication_rules.extend(
            IRAuthenticationRule(
                name=item.name,
                source_interfaces=list(item.srcintf),
                source_addresses=list(item.srcaddr),
                active_auth_method=item.active_auth_method,
                source_attributes=dict(item.extra_settings),
            )
            for item in self.fg.authentication_rules
        )
        provider_types = (
            ("ldap-server", {item.name for item in self.ir.user_ldap_servers}),
            ("saml-server", {item.name for item in self.ir.user_saml_servers}),
            ("fsso-provider", {item.name for item in self.ir.fsso_providers}),
        )
        provider_names = set().union(*(names for _, names in provider_types))
        for scheme in self.ir.authentication_schemes:
            if not scheme.user_database:
                continue
            raw_reference = scheme.user_database
            references = [raw_reference]
            if raw_reference not in provider_names and "," in raw_reference:
                references = [item.strip() for item in raw_reference.split(",") if item.strip()]
            for reference in references:
                dependency_type = "unknown"
                resolved = False
                for candidate_type, names in provider_types:
                    if reference in names:
                        dependency_type = candidate_type
                        resolved = True
                        break
                scheme.user_database_dependencies.append(IRIdentityDependency(
                    reference=reference,
                    dependency_type=dependency_type,
                    resolved=resolved,
                    target_name=reference if resolved else None,
                    source_context=f"authentication scheme {scheme.name}",
                ))
                (scheme.resolved_user_databases if resolved else scheme.unresolved_user_databases).append(reference)
            if scheme.unresolved_user_databases:
                self._add_identity_audit(
                    f"identity:authentication-scheme:{scheme.name}:user-database",
                    f"Authentication scheme '{scheme.name}' contains unresolved user "
                    f"database reference(s): {', '.join(scheme.unresolved_user_databases)}. "
                    "Source values were preserved and require manual review.",
                )

        scheme_names = {item.name for item in self.ir.authentication_schemes}
        for rule in self.ir.authentication_rules:
            if rule.active_auth_method is None:
                continue
            rule.active_auth_method_resolved = rule.active_auth_method in scheme_names
            if not rule.active_auth_method_resolved:
                rule.unresolved_auth_methods = [rule.active_auth_method]
                self._add_identity_audit(
                    f"identity:authentication-rule:{rule.name}:scheme",
                    f"Authentication rule '{rule.name}' references missing authentication "
                    f"scheme '{rule.active_auth_method}'. Source reference was preserved "
                    "and requires manual review.",
                )

    # ------------------------------------------------------------------
    # Interfaces / zones
    # ------------------------------------------------------------------

    def _get_zone_for_intf(
        self,
        intf: FGInterface,
    ) -> Optional[str]:
        if intf.name in self.zone_mapping:
            return self.zone_mapping[intf.name]

        context_key = (intf.source_context, intf.name)
        if context_key in self.fg_zone_intf_map:
            return self.fg_zone_intf_map[context_key]

        # If part of SD-WAN, use the source SD-WAN zone.
        for sdwan in self.fg.sdwans:
            if sdwan.source_context != intf.source_context:
                continue
            for member in sdwan.members:
                if member.interface == intf.name:
                    return member.zone

        return None

    def _get_zone_type_for_intf(
        self,
        intf: FGInterface,
        zone_name: str,
    ) -> str:
        """Classify an interface-derived zone without merging source types."""
        # Caller-provided mappings and explicit system-zone membership describe
        # ordinary source zones. This also prevents a caller mapping that
        # happens to reuse an SD-WAN zone name from changing object identity.
        if intf.name in self.zone_mapping:
            return "system"

        if (intf.source_context, intf.name) in self.fg_zone_intf_map:
            return "system"

        for sdwan in self.fg.sdwans:
            if sdwan.source_context != intf.source_context:
                continue
            if any(
                member.interface == intf.name and member.zone == zone_name
                for member in sdwan.members
            ):
                return "sdwan"

        return "system"

    @staticmethod
    def _transform_source_config_node(
        node: FGSourceNode,
    ) -> IRSourceConfigNode:
        return IRSourceConfigNode(
            node_type=node.node_type,
            name=node.name,
            commands=[
                IRSourceConfigCommand(
                    operation=command.operation,
                    key=command.key,
                    values=list(command.values),
                )
                for command in node.commands
            ],
            children=[
                FGToIRTransformer._transform_source_config_node(
                    child
                )
                for child in node.children
            ],
        )

    @staticmethod
    def _resolve_interface_type(
        interface: FGInterface,
    ) -> Optional[str]:
        if interface.type:
            return interface.type

        if interface.interface and interface.vlanid is not None:
            return "vlan"

        return None

    @classmethod
    def _interface_topology_review_reasons(
        cls,
        interface: FGInterface,
    ) -> List[str]:
        """Return review reasons for topology not yet portable across targets."""
        interface_type = cls._resolve_interface_type(interface)
        if (interface_type or "").lower() not in {"aggregate", "redundant"}:
            return []

        members = list(interface.members)
        reasons = [
            (
                "FortiGate aggregate or redundant interface topology "
                "requires target-platform review"
            )
            if members
            else (
                "FortiGate aggregate or redundant interface has no "
                "configured members"
            )
        ]

        if interface.name in members:
            reasons.append(
                "FortiGate aggregate or redundant interface cannot "
                "reference itself as a member"
            )

        return list(dict.fromkeys(reasons))

    @staticmethod
    def _interface_vrf_review_reasons(
        interface: FGInterface,
    ) -> List[str]:
        """Return review reasons for source interface VRF semantics."""
        if "unparsed_vrf" in interface.source_attributes:
            return [
                "FortiGate interface VRF value "
                f"{interface.source_attributes['unparsed_vrf']!r} "
                "could not be parsed as an integer"
            ]

        if interface.vrf is None:
            return []

        if not FORTIOS_VRF_MIN <= interface.vrf <= FORTIOS_VRF_MAX:
            return [
                f"FortiGate interface VRF value {interface.vrf} is outside "
                f"the valid range {FORTIOS_VRF_MIN}-{FORTIOS_VRF_MAX}"
            ]

        if interface.vrf != FORTIOS_VRF_MIN:
            return [NON_DEFAULT_INTERFACE_VRF_REVIEW]

        return []

    def _interface_review_reasons(
        self,
        interface: FGInterface,
        additional_reasons: Optional[List[str]] = None,
    ) -> List[str]:
        """Return ordered reasons why an interface is not fully portable.

        ``FGInterface.source_attributes`` is an evidence-preservation map, not
        a normalization result. Only source keys represented by typed IR
        fields, or explicitly classified as low-risk metadata, are ignored.
        Unknown and source-only interface behavior therefore remains visible
        to migration safety checks.
        """

        reasons: List[str] = list(additional_reasons or [])

        def add(reason: str) -> None:
            if reason not in reasons:
                reasons.append(reason)

        for field, value in (
            ("ip", interface.ip),
            ("remote-ip", interface.remote_ip),
        ):
            if not value:
                continue
            try:
                _normalize_interface_ip(value)
            except (AttributeError, TypeError, ValueError) as exc:
                add(f"{field}: {exc}")

        if interface.ip6_address:
            try:
                normalize_ipv6_prefix(interface.ip6_address)
            except (AttributeError, TypeError, ValueError) as exc:
                add(f"ipv6-address: {exc}")

        for key in interface.source_attributes:
            normalized_key = str(key).replace("-", "_").lower()

            if (
                normalized_key == "device_identification"
                and _normalize_device_identification(interface.device_identification)
                is None
            ):
                add(
                    f"Unmodeled top-level interface setting '{key}' "
                    "may affect traffic behavior"
                )
                continue

            if normalized_key in INTERFACE_NORMALIZED_SOURCE_SETTINGS:
                continue

            if normalized_key in INTERFACE_LOW_RISK_SOURCE_SETTINGS:
                continue

            if normalized_key == "speed":
                normalized_speed, _ = _normalize_interface_speed(interface.speed)
                if normalized_speed is not None:
                    continue

            if normalized_key == "secondary_ip":
                configured = str(interface.source_attributes[key]).lower()
                has_typed_entries = bool(interface.secondary_ips)
                if configured in {"disable", "disabled"} and not has_typed_entries:
                    continue
                if configured in {"disable", "disabled"} and has_typed_entries:
                    add(
                        "Secondary IP entries are configured but secondary-IP is disabled"
                    )
                    continue
                if configured in {"enable", "enabled"} and has_typed_entries:
                    continue
                if configured in {"enable", "enabled"}:
                    add(
                        "Secondary IP enablement is configured without typed "
                        "secondary entries"
                    )
                    continue
                add(
                    "Secondary IP configuration is ambiguous: the parent "
                    "enablement does not unambiguously match typed entries"
                )
                continue

            add(
                f"Unmodeled top-level interface setting '{key}' "
                "may affect traffic behavior"
            )

        for secondary in interface.secondary_ips:
            source_id = secondary.id
            if secondary.extra_settings:
                add(
                    f"Secondary IP {source_id} has unmodeled source settings"
                )

            if not secondary.ip:
                add(f"Secondary IP {source_id} has no configured IP value")
                continue

            try:
                normalized = _normalize_interface_ip(secondary.ip)
            except (AttributeError, TypeError, ValueError):
                normalized = None
            if normalized is None:
                add(
                    f"Secondary IP {source_id} has invalid or unusable "
                    "IP/netmask syntax"
                )

        nested_names = set()
        for node in interface.nested_configs:
            nested_name = str(node.name)
            if nested_name in nested_names:
                continue
            nested_names.add(nested_name)

            normalized_name = nested_name.replace("_", "-").lower()
            if normalized_name == "ipv6":
                typed_ipv6_keys = {
                    "ip6-address",
                    "ip6-allowaccess",
                    "ip6-mode",
                    "ip6-send-adv",
                    "ip6-manage-flag",
                    "ip6-other-flag",
                }
                if node.children or any(
                    command.operation != "set"
                    or str(command.key).replace("_", "-").lower()
                    not in typed_ipv6_keys
                    for command in node.commands
                ):
                    add(
                        "FortiGate IPv6 interface contains source-specific "
                        "behavior requiring target-platform review"
                    )
            elif normalized_name == "vrrp":
                add("VRRP interface semantics require manual review")
            elif normalized_name == "tagging":
                add("Interface tagging semantics require manual review")
            elif normalized_name == "l2tp-client-settings":
                add(
                    "L2TP client interface settings require manual review"
                )
            else:
                add(
                    f"Nested interface configuration '{nested_name}' "
                    "is not normalized and requires manual review"
                )

        if interface.ipv6_source_settings and not any(
            str(node.name).replace("_", "-").lower() == "ipv6"
            for node in interface.nested_configs
        ):
            add(
                "IPv6 interface source-only semantics require manual review"
            )

        for reason in self._interface_topology_review_reasons(interface):
            add(reason)
        for reason in self._interface_vrf_review_reasons(interface):
            add(reason)

        return reasons

    def _transform_interfaces_and_zones(
        self,
    ) -> None:
        zones_map: Dict[Tuple[str, str, str], IRZone] = {}

        # Preserve explicitly configured FortiGate system zones.
        for system_zone in self.fg.system_zones:
            zone_key = (
                system_zone.source_context,
                "system",
                system_zone.name,
            )
            if zone_key not in zones_map:
                zones_map[zone_key] = IRZone(
                    name=system_zone.name,
                    zone_type="system",
                    source_context=system_zone.source_context,
                    source_path="system zone",
                    interfaces=list(
                        system_zone.interface
                    ),
                )

        # Expose SD-WAN zones in the shared inventory while retaining their
        # source type. Membership comes from SD-WAN member.zone relationships,
        # not from system-zone interface membership.
        for sdwan in self.fg.sdwans:
            source_context = sdwan.source_context or "root"
            for sdwan_zone in sdwan.zones:
                zone_context = sdwan_zone.source_context or source_context
                zone_key = (zone_context, "sdwan", sdwan_zone.name)
                if zone_key not in zones_map:
                    zones_map[zone_key] = IRZone(
                        name=sdwan_zone.name,
                        zone_type="sdwan",
                        source_context=zone_context,
                        source_path="system sdwan zone",
                    )

            for member in sdwan.members:
                zone_context = member.source_context or source_context
                zone_key = (zone_context, "sdwan", member.zone)
                if zone_key not in zones_map:
                    zones_map[zone_key] = IRZone(
                        name=member.zone,
                        zone_type="sdwan",
                        source_context=zone_context,
                        source_path="system sdwan zone",
                    )
                if member.interface not in zones_map[zone_key].interfaces:
                    zones_map[zone_key].interfaces.append(member.interface)

        for intf in self.fg.interfaces:
            zone_name = self._get_zone_for_intf(
                intf
            )

            if zone_name is not None:
                self._intf_to_zone[
                    (intf.source_context, intf.name)
                ] = zone_name

                zone_type = self._get_zone_type_for_intf(
                    intf,
                    zone_name,
                )
                zone_key = (
                    intf.source_context,
                    zone_type,
                    zone_name,
                )
                if zone_key not in zones_map:
                    zones_map[zone_key] = IRZone(
                        name=zone_name,
                        zone_type=zone_type,
                        source_context=intf.source_context,
                        source_path=(
                            "system sdwan zone"
                            if zone_type == "sdwan"
                            else "system zone"
                        ),
                    )

                if zone_type == "system" and intf.name not in zones_map[zone_key].interfaces:
                    zones_map[zone_key].interfaces.append(
                        intf.name
                    )

            parse_errors = []

            try:
                ip_cidr = _normalize_interface_ip(intf.ip)
            except ValueError as exc:
                ip_cidr = None
                parse_errors.append(f"ip: {exc}")

            try:
                remote_ip_cidr = _normalize_interface_ip(intf.remote_ip)
            except ValueError as exc:
                remote_ip_cidr = None
                parse_errors.append(f"remote-ip: {exc}")

            ipv6_address = None
            if intf.ip6_address:
                try:
                    ipv6_address = normalize_ipv6_prefix(intf.ip6_address)
                except ValueError as exc:
                    parse_errors.append(f"ipv6-address: {exc}")

            for parse_error in parse_errors:
                self.ir.audit_entries.append(
                    IRAuditEntry(
                        id=f"interface:{intf.name}:{parse_error.split(':', 1)[0]}",
                        category="Interface Network Normalization",
                        message=(
                            f"Interface '{intf.name}' {parse_error}. "
                            "The source value was preserved and no "
                            "replacement prefix was inferred."
                        ),
                        confidence=MigrationConfidence.MANUAL,
                    )
                )

            vrf_review_reasons = self._interface_vrf_review_reasons(intf)
            if vrf_review_reasons:
                for review_reason in vrf_review_reasons:
                    self.ir.audit_entries.append(
                        IRAuditEntry(
                            id=(
                                f"interface:{intf.source_context}:"
                                f"{intf.name}:vrf"
                            ),
                            category="Interface VRF",
                            message=(
                                f"Interface '{intf.name}' {review_reason}. "
                                "The configured source value was preserved and "
                                "requires manual review."
                            ),
                            confidence=MigrationConfidence.MANUAL,
                        )
                    )

                if "unparsed_vrf" in intf.source_attributes:
                    parse_errors.append(
                        "vrf: configured value could not be parsed as an integer"
                    )
                elif intf.vrf is not None and not (
                    FORTIOS_VRF_MIN <= intf.vrf <= FORTIOS_VRF_MAX
                ):
                    parse_errors.append(
                        f"vrf: value {intf.vrf} outside range "
                        f"{FORTIOS_VRF_MIN}-{FORTIOS_VRF_MAX}"
                    )

            transformed_secondary_ips = []
            inactive_secondary_ips = []
            secondary_ip_status = getattr(intf, "secondary_ip", None)
            secondary_ip_review_reasons = []
            source_secondary_ips = list(getattr(intf, "secondary_ips", []))

            if source_secondary_ips and secondary_ip_status != "enable":
                if secondary_ip_status == "disable":
                    secondary_ip_review_reasons.append(
                        "Secondary IP entries are configured but secondary-IP is disabled"
                    )
                    status_message = (
                        f"Interface '{intf.name}' has configured secondary IP entries, "
                        "but secondary-IP is disabled. The entries were retained as "
                        "inactive source data and are not exposed as active addresses."
                    )
                else:
                    secondary_ip_review_reasons.append(
                        "Secondary IP entries are configured but secondary-IP state is ambiguous"
                    )
                    status_message = (
                        f"Interface '{intf.name}' has configured secondary IP entries, "
                        "but the secondary-IP parent state is omitted or unrecognized. "
                        "The entries were retained without exposing them as active "
                        "addresses and require manual review."
                    )

                self.ir.audit_entries.append(
                    IRAuditEntry(
                        id=f"interface:{intf.name}:secondaryip:status",
                        category="Interface Secondary IP",
                        message=status_message,
                        confidence=MigrationConfidence.MANUAL,
                    )
                )

                for sec in source_secondary_ips:
                    if sec.extra_settings:
                        self.ir.audit_entries.append(
                            IRAuditEntry(
                                id=f"interface:{intf.name}:secondaryip:{sec.id}:source-settings",
                                category="Interface Secondary IP",
                                message=(
                                    f"Interface '{intf.name}' secondary IP {sec.id} "
                                    "contains unmodeled source settings requiring review: "
                                    f"{', '.join(sorted(sec.extra_settings))}."
                                ),
                                confidence=MigrationConfidence.MANUAL,
                            )
                        )

                    inactive_secondary_ips.append(
                        IRInterfaceSecondaryIP(
                            source_id=str(sec.id),
                            source_ip=sec.ip,
                            management_access=list(sec.allowaccess),
                            requires_manual_review=True,
                            source_attributes=dict(sec.extra_settings),
                        )
                    )
            else:
                for sec in source_secondary_ips:
                    sec_requires_review = bool(sec.extra_settings)
                    sec_parse_error = None

                    if sec.extra_settings:
                        self.ir.audit_entries.append(
                            IRAuditEntry(
                                id=f"interface:{intf.name}:secondaryip:{sec.id}:source-settings",
                                category="Interface Secondary IP",
                                message=(
                                    f"Interface '{intf.name}' secondary IP {sec.id} "
                                    "contains unmodeled source settings requiring review: "
                                    f"{', '.join(sorted(sec.extra_settings))}."
                                ),
                                confidence=MigrationConfidence.MANUAL,
                            )
                        )

                    if not sec.ip:
                        sec_ip_cidr = None
                        sec_parse_error = "Missing source secondary IP value."
                        sec_requires_review = True
                        self.ir.audit_entries.append(
                            IRAuditEntry(
                                id=f"interface:{intf.name}:secondaryip:{sec.id}",
                                category="Interface Network Normalization",
                                message=(
                                    f"Interface '{intf.name}' secondary IP {sec.id} "
                                    "has no configured IP/netmask value. "
                                    "No replacement value was inferred."
                                ),
                                confidence=MigrationConfidence.MANUAL,
                            )
                        )
                    else:
                        try:
                            sec_ip_cidr = _normalize_interface_ip(sec.ip)
                        except ValueError as exc:
                            sec_ip_cidr = None
                            sec_parse_error = str(exc)
                            sec_requires_review = True
                            self.ir.audit_entries.append(
                                IRAuditEntry(
                                    id=f"interface:{intf.name}:secondaryip:{sec.id}",
                                    category="Interface Network Normalization",
                                    message=(
                                        f"Interface '{intf.name}' secondary IP {sec.id} "
                                        f"contained invalid IP/netmask syntax '{sec.ip}'. "
                                        "The source value was preserved and no replacement "
                                        "prefix was inferred."
                                    ),
                                    confidence=MigrationConfidence.MANUAL,
                                )
                            )

                        if sec_ip_cidr is None and sec_parse_error is None:
                            sec_requires_review = True
                            self.ir.audit_entries.append(
                                IRAuditEntry(
                                    id=f"interface:{intf.name}:secondaryip:{sec.id}",
                                    category="Interface Network Normalization",
                                    message=(
                                        f"Interface '{intf.name}' secondary IP {sec.id} "
                                        f"source value '{sec.ip}' does not represent a usable "
                                        "configured secondary address. The source value was "
                                        "preserved and no replacement address was inferred."
                                    ),
                                    confidence=MigrationConfidence.MANUAL,
                                )
                            )

                    transformed_secondary_ips.append(
                        IRInterfaceSecondaryIP(
                            source_id=str(sec.id),
                            source_ip=sec.ip,
                            ip=sec_ip_cidr,
                            management_access=list(sec.allowaccess),
                            requires_manual_review=sec_requires_review,
                            parse_error=sec_parse_error,
                            source_attributes=dict(sec.extra_settings),
                        )
                    )

            nested_source_configs = [
                self._transform_source_config_node(node)
                for node in intf.nested_configs
            ]

            interface_review_reasons = self._interface_review_reasons(
                intf,
                additional_reasons=secondary_ip_review_reasons,
            )
            source_speed, source_duplex = _normalize_interface_speed(intf.speed)
            source_device_identification = _normalize_device_identification(
                intf.device_identification
            )
            topology_review_reasons = self._interface_topology_review_reasons(intf)
            if topology_review_reasons:
                self.ir.audit_entries.append(
                    IRAuditEntry(
                        id=(
                            f"interface:{intf.source_context}:"
                            f"{intf.name}:topology"
                        ),
                        category="Interface Topology",
                        message=(
                            f"Interface '{intf.name}' preserves FortiGate "
                            "aggregate/redundant member topology requiring "
                            "manual review: "
                            f"{'; '.join(topology_review_reasons)}."
                        ),
                        confidence=MigrationConfidence.MANUAL,
                    )
                )

            if nested_source_configs and interface_review_reasons:
                nested_names = ", ".join(
                    node.name
                    for node in intf.nested_configs
                )

                self.ir.audit_entries.append(
                    IRAuditEntry(
                        id=(
                            f"interface:{intf.name}:"
                            "nested-source-config"
                        ),
                        category="Interface Nested Configuration",
                        message=(
                            f"Interface '{intf.name}' contains "
                            "nested FortiGate configuration "
                            "preserved as extraction-only "
                            f"source data: {nested_names}. "
                            "Review these settings before "
                            "target migration."
                        ),
                        confidence=MigrationConfidence.MANUAL,
                    )
                )

            self.ir.interfaces.append(
                IRInterface(
                    name=intf.name,
                    source_context=intf.source_context,
                    zone=zone_name,
                    ip=ip_cidr,
                    ipv6_address=ipv6_address,
                    source_ipv6_address=intf.ip6_address,
                    source_ipv6_management_access=list(intf.ip6_allowaccess),
                    source_ipv6_mode=intf.ip6_mode,
                    source_ipv6_send_adv=intf.ip6_send_adv,
                    source_ipv6_manage_flag=intf.ip6_manage_flag,
                    source_ipv6_other_flag=intf.ip6_other_flag,
                    remote_ip=remote_ip_cidr,
                    source_secondary_ip_status=secondary_ip_status,
                    secondary_ips=transformed_secondary_ips,
                    inactive_secondary_ips=inactive_secondary_ips,
                    description=intf.description,
                    parent=intf.interface,
                    tag=intf.vlanid,
                    alias=intf.alias,
                    status=(intf.status != "down"),
                    vlanid=intf.vlanid,
                    pppoe_mode=(
                        intf.mode
                        if intf.mode == "pppoe"
                        else None
                    ),
                    pppoe_username=intf.username,
                    source_vdom=intf.vdom,
                    source_vrf=intf.vrf,
                    source_speed=source_speed,
                    source_duplex=source_duplex,
                    source_device_identification=source_device_identification,
                    interface_type=self._resolve_interface_type(
                        intf
                    ),
                    members=list(intf.members),
                    role=(
                        intf.role
                        if intf.role != "undefined"
                        else None
                    ),
                    addressing_mode=intf.mode,
                    management_access=list(
                        intf.allowaccess
                    ),
                    dhcp_client=(
                        intf.mode == "dhcp"
                    ),
                    requires_manual_review=bool(
                        parse_errors
                        or interface_review_reasons
                    ),
                    migration_status=(
                        "PARTIALLY_NORMALIZED"
                        if parse_errors or interface_review_reasons
                        else "NORMALIZED"
                    ),
                    review_reasons=interface_review_reasons,
                    parse_errors=parse_errors,
                    nested_source_configs=nested_source_configs,
                    ipv6_source_settings=dict(intf.ipv6_source_settings),
                    source_attributes=dict(
                        intf.source_attributes
                    ),
                )
            )

        self.ir.zones = list(
            zones_map.values()
        )

    # ------------------------------------------------------------------
    # Addresses
    # ------------------------------------------------------------------

    def _create_ir_address(
        self,
        name,
        addr_type,
        val,
        description,
        is_ipv6=False,
        is_multicast=False,
        source_uuid=None,
        source_context=None,
        associated_interface=None,
        allow_routing=None,
        source_color=None,
        source_sub_type=None,
        source_obj_tag=None,
        source_tag_type=None,
        source_obj_type=None,
        source_dirty=None,
        source_attributes=None,
        source_section=None,
        address_family=None,
        source_type=None,
        source_list_entries=None,
        source_tagging_entries=None,
    ):
        kwargs = {
            "name": name,
            "source_context": source_context,
            "type": addr_type,
            "description": description,
            "is_ipv6": is_ipv6,
            "is_multicast": is_multicast,
            "source_uuid": source_uuid,
            "source_section": source_section,
            "address_family": address_family,
            "source_type": source_type,
            "source_list_entries": list(source_list_entries or []),
            "source_tagging_entries": list(source_tagging_entries or []),
            "associated_interface": associated_interface,
            "allow_routing": allow_routing,
            "source_color": source_color,
            "source_sub_type": source_sub_type,
            "source_obj_tag": source_obj_tag,
            "source_tag_type": source_tag_type,
            "source_obj_type": source_obj_type,
            "source_dirty": source_dirty,
            "source_attributes": dict(source_attributes or {}),
        }

        if addr_type in (
            AddressType.NETWORK,
            AddressType.HOST,
        ):
            kwargs["subnet"] = val

        elif addr_type == AddressType.RANGE:
            if "-" in val:
                start, end = val.split("-", 1)
                kwargs[
                    "ip_range_start"
                ] = start
                kwargs[
                    "ip_range_end"
                ] = end

        elif addr_type in (
            AddressType.FQDN,
            AddressType.WILDCARD_FQDN,
        ):
            kwargs["fqdn"] = val

        elif addr_type == AddressType.MAC:
            kwargs["mac"] = val

        elif addr_type == AddressType.GEO:
            kwargs["geo_code"] = val

        elif (
            addr_type
            == AddressType.WILDCARD_MASK
        ):
            kwargs[
                "wildcard_mask"
            ] = val

        elif addr_type == AddressType.DYNAMIC:
            kwargs[
                "dynamic_filter"
            ] = val

        elif addr_type == AddressType.EMS_TAG:
            kwargs[
                "tag_name"
            ] = val

        try:
            return IRAddress(
                **kwargs
            )

        except ValidationError as exc:
            safe_kwargs = {
                **kwargs,
                "parse_error": str(exc),
                "raw_value": val,
                "requires_manual_review": True,
                "audit_note": (
                    f"Address '{name}' requires manual review after "
                    "strict validation failed."
                ),
            }

            for typed_field in (
                "subnet",
                "ip_range_start",
                "ip_range_end",
                "fqdn",
                "mac",
                "geo_code",
                "wildcard_mask",
                "dynamic_filter",
                "tag_name",
            ):
                safe_kwargs.pop(typed_field, None)

            self.ir.audit_entries.append(
                IRAuditEntry(
                    id=name,
                    category="Address",
                    message=(
                        f"Address '{name}' failed strict "
                        f"validation: {exc}"
                    ),
                    confidence=(
                        MigrationConfidence.UNSUPPORTED
                    ),
                )
            )

            return IRAddress(
                **safe_kwargs
            )

    @staticmethod
    def _address_source_section(addr) -> str:
        if addr.is_multicast:
            return "firewall multicast-address6" if addr.is_ipv6 else "firewall multicast-address"
        return "firewall address6" if addr.is_ipv6 else "firewall address"

    @staticmethod
    def _address_family(addr) -> str:
        return "ipv6" if addr.is_ipv6 else "ipv4"

    @staticmethod
    def _address_tagging_entries(addr) -> List[IRAddressTaggingEntry]:
        return [
            IRAddressTaggingEntry(
                name=entry.name,
                category=entry.category,
                tags=list(entry.tags),
                source_attributes=dict(entry.extra_settings),
            )
            for entry in addr.tagging
        ]

    def _preserve_source_only_address(
        self, addr, *, reason: str, original_value: str = ""
    ) -> IRAddress:
        source_attributes = dict(addr.extra_settings)
        for key, value in {
            "sdn": addr.sdn,
            "filter": addr.filter,
            "wildcard_fqdn": addr.wildcard_fqdn,
        }.items():
            if value is not None:
                source_attributes[key] = value
        return IRAddress(
            name=addr.name,
            source_context=addr.source_context,
            type=AddressType.SPECIAL,
            source_uuid=addr.uuid,
            source_section=self._address_source_section(addr),
            address_family=self._address_family(addr),
            source_type=addr.type,
            associated_interface=addr.associated_interface,
            allow_routing=self._fortios_enabled(addr.allow_routing),
            source_color=addr.color,
            source_sub_type=addr.sub_type,
            source_obj_tag=addr.obj_tag,
            source_tag_type=addr.tag_type,
            source_obj_type=addr.obj_type,
            source_dirty=addr.dirty,
            source_list_entries=[entry.name for entry in addr.address_list],
            source_tagging_entries=self._address_tagging_entries(addr),
            original_type=addr.type,
            original_value=original_value,
            source_attributes=source_attributes,
            migration_status="PARTIALLY_NORMALIZED",
            requires_manual_review=True,
            audit_note=reason,
            description=addr.comment,
            is_ipv6=addr.is_ipv6,
            is_multicast=addr.is_multicast,
        )

    def _transform_addresses(
        self,
    ) -> None:
        for addr in self.fg.addresses:
            if addr.name in FORTIGATE_RESERVED_ADDRESS_NAMES:
                source_attributes = dict(addr.extra_settings)
                source_attributes.update({
                    key: value
                    for key, value in {
                        "subnet": addr.subnet,
                        "ip6": addr.ip6,
                        "start_ip": addr.start_ip,
                        "end_ip": addr.end_ip,
                        "fqdn": addr.fqdn,
                        "country": addr.country,
                        "macaddr": addr.macaddr,
                        "mac": addr.mac,
                        "sdn": addr.sdn,
                        "filter": addr.filter,
                    }.items()
                    if value is not None
                })
                requires_manual_review = addr.name != "all"
                self.ir.addresses.append(
                    IRAddress(
                        name=addr.name,
                        source_context=addr.source_context,
                        type=AddressType.SPECIAL,
                        source_uuid=addr.uuid,
                        source_section=self._address_source_section(addr),
                        address_family=self._address_family(addr),
                        source_type=addr.type,
                        source_list_entries=[entry.name for entry in addr.address_list],
                        source_tagging_entries=self._address_tagging_entries(addr),
                        associated_interface=addr.associated_interface,
                        allow_routing=self._fortios_enabled(addr.allow_routing),
                        source_color=addr.color,
                        source_sub_type=addr.sub_type,
                        source_obj_tag=addr.obj_tag,
                        source_tag_type=addr.tag_type,
                        source_obj_type=addr.obj_type,
                        source_dirty=addr.dirty,
                        source_attributes=source_attributes,
                        original_type="fortigate_reserved",
                        original_value=addr.name,
                        requires_manual_review=requires_manual_review,
                        audit_note=(
                            "FortiGate reserved address semantics require "
                            "target-specific review."
                            if requires_manual_review
                            else None
                        ),
                        description=addr.comment,
                        is_ipv6=addr.is_ipv6,
                        is_multicast=addr.is_multicast,
                    )
                )
                continue

            addr_type = AddressType.NETWORK
            val = ""

            if not val:
                if addr.is_ipv6 and addr.ip6:
                    addr_type = AddressType.NETWORK
                    val = addr.ip6

                elif (
                    addr.type == "ipmask"
                    and addr.subnet
                ):
                    try:
                        val = normalize_ipv4_prefix(addr.subnet)
                    except ValueError as exc:
                        self.ir.addresses.append(
                            IRAddress(
                                name=addr.name,
                                source_context=addr.source_context,
                                type=AddressType.NETWORK,
                                parse_error=str(exc),
                                raw_value=addr.subnet,
                                requires_manual_review=True,
                                audit_note=(
                                    "Invalid source IPv4 subnet was "
                                    "preserved without inferred CIDR."
                                ),
                                description=addr.comment,
                                source_uuid=addr.uuid,
                                source_section=self._address_source_section(addr),
                                address_family=self._address_family(addr),
                                source_type=addr.type,
                                source_list_entries=[entry.name for entry in addr.address_list],
                                source_tagging_entries=self._address_tagging_entries(addr),
                                associated_interface=addr.associated_interface,
                                allow_routing=self._fortios_enabled(addr.allow_routing),
                                source_color=addr.color,
                                source_sub_type=addr.sub_type,
                                source_obj_tag=addr.obj_tag,
                                source_tag_type=addr.tag_type,
                                source_obj_type=addr.obj_type,
                                source_dirty=addr.dirty,
                                source_attributes=dict(addr.extra_settings),
                                is_ipv6=addr.is_ipv6,
                                is_multicast=addr.is_multicast,
                            )
                        )
                        self.ir.audit_entries.append(
                            IRAuditEntry(
                                id=f"address:{addr.name}:subnet",
                                category="Address Network Normalization",
                                message=(
                                    f"Address '{addr.name}' source subnet "
                                    f"{addr.subnet!r} failed normalization: {exc}. "
                                    "No replacement prefix was inferred."
                                ),
                                confidence=MigrationConfidence.MANUAL,
                            )
                        )
                        continue

                elif (
                    (
                        addr.type
                        in [
                            "ipmask",
                            "iprange",
                        ]
                        or addr.is_multicast
                    )
                    and addr.start_ip
                    and addr.end_ip
                ):
                    if (
                        addr.start_ip
                        == addr.end_ip
                    ):
                        addr_type = (
                            AddressType.HOST
                        )
                        prefix = 128 if addr.is_ipv6 else 32
                        val = f"{addr.start_ip}/{prefix}"
                    else:
                        addr_type = (
                            AddressType.RANGE
                        )
                        val = (
                            f"{addr.start_ip}-"
                            f"{addr.end_ip}"
                        )

                elif (
                    addr.type == "fqdn"
                    and addr.fqdn
                ):
                    addr_type = (
                        AddressType.FQDN
                    )
                    val = addr.fqdn

                elif (
                    addr.type == "iprange"
                    and addr.start_ip
                    and addr.end_ip
                ):
                    addr_type = (
                        AddressType.RANGE
                    )
                    val = (
                        f"{addr.start_ip}-"
                        f"{addr.end_ip}"
                    )

                elif addr.type == "mac":
                    raw_mac = (
                        addr.macaddr
                        or addr.mac
                        or addr.subnet
                    )

                    if raw_mac and re.fullmatch(
                        r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}",
                        raw_mac,
                    ):
                        self.ir.addresses.append(
                            IRAddress(
                                name=addr.name,
                                source_context=addr.source_context,
                                type=AddressType.MAC,
                                mac=raw_mac,
                                description=addr.comment,
                                source_uuid=addr.uuid,
                                source_section=self._address_source_section(addr),
                                address_family=self._address_family(addr),
                                source_type=addr.type,
                                source_list_entries=[entry.name for entry in addr.address_list],
                                source_tagging_entries=self._address_tagging_entries(addr),
                                associated_interface=addr.associated_interface,
                                allow_routing=self._fortios_enabled(
                                    addr.allow_routing
                                ),
                                source_color=addr.color,
                                source_sub_type=addr.sub_type,
                                source_obj_tag=addr.obj_tag,
                                source_tag_type=addr.tag_type,
                                source_obj_type=addr.obj_type,
                                source_dirty=addr.dirty,
                                source_attributes=dict(addr.extra_settings),
                            )
                        )
                        continue

                    error = (
                        "Missing source MAC address."
                        if not raw_mac
                        else f"Invalid source MAC address: {raw_mac!r}."
                    )
                    self.ir.addresses.append(
                        IRAddress(
                            name=addr.name,
                            source_context=addr.source_context,
                            type=AddressType.MAC,
                            parse_error=error,
                            raw_value=raw_mac or "",
                            requires_manual_review=True,
                            audit_note=(
                                "Invalid or missing source MAC address was "
                                "preserved without a replacement value."
                            ),
                            description=addr.comment,
                            source_uuid=addr.uuid,
                            associated_interface=addr.associated_interface,
                            allow_routing=self._fortios_enabled(
                                addr.allow_routing
                            ),
                            source_color=addr.color,
                            source_sub_type=addr.sub_type,
                            source_obj_tag=addr.obj_tag,
                            source_tag_type=addr.tag_type,
                            source_obj_type=addr.obj_type,
                            source_dirty=addr.dirty,
                            source_section="firewall address6" if addr.is_ipv6 else "firewall address",
                            address_family="ipv6" if addr.is_ipv6 else "ipv4",
                            source_type=addr.type,
                            source_list_entries=[entry.name for entry in addr.address_list],
                            source_tagging_entries=self._address_tagging_entries(addr),
                            source_attributes=dict(addr.extra_settings),
                        )
                    )

                    self.ir.audit_entries.append(
                        IRAuditEntry(
                            id=addr.name,
                            category="Address",
                            message=(
                                f"Address '{addr.name}' has an invalid or "
                                "missing source MAC value; no replacement "
                                "address was inferred."
                            ),
                            confidence=(
                                MigrationConfidence.MANUAL
                            ),
                        )
                    )

                    continue

                elif addr.type == "geography":
                    if addr.country:
                        addr_type = AddressType.GEO
                        val = addr.country
                    else:
                        self.ir.addresses.append(
                            self._preserve_source_only_address(
                                addr,
                                reason="FortiGate geography address has no explicit country value.",
                            )
                        )
                        continue

                elif addr.type == "wildcard":
                    if addr.wildcard:
                        addr_type = AddressType.WILDCARD_MASK
                        val = addr.wildcard
                    else:
                        self.ir.addresses.append(
                            self._preserve_source_only_address(
                                addr,
                                reason="FortiGate wildcard address has no explicit wildcard value.",
                            )
                        )
                        continue

                elif addr.type == "dynamic" and addr.sub_type == "ems-tag":
                    explicit_tag = addr.obj_tag or addr.ems_tag_name
                    tag_name = explicit_tag or addr.name
                    used_fallback = explicit_tag is None

                    self.ir.address_groups.append(
                        IRAddressGroup(
                            name=addr.name,
                            source_context=addr.source_context,
                            is_dynamic=True,
                            dynamic_filter=(
                                f"'{tag_name}'"
                            ),
                            tags=[tag_name],
                            description=addr.comment or "FortiClient EMS dynamic address tag",
                            source_uuid=addr.uuid,
                            source_section=self._address_source_section(addr),
                            address_family=self._address_family(addr),
                            associated_interface=(
                                addr.associated_interface
                            ),
                            allow_routing=(
                                self._fortios_enabled(
                                    addr.allow_routing
                                )
                            ),
                            source_color=addr.color,
                            source_sub_type=addr.sub_type,
                            source_obj_tag=addr.obj_tag,
                            source_tag_type=addr.tag_type,
                            source_obj_type=addr.obj_type,
                            source_dirty=addr.dirty,
                            source_attributes=dict(
                                addr.extra_settings
                            ),
                            migration_status=(
                                "PARTIALLY_NORMALIZED" if used_fallback else "NORMALIZED"
                            ),
                            requires_manual_review=used_fallback,
                            audit_note=(
                                "No explicit EMS tag identifier was configured; the object name was retained for review."
                                if used_fallback else None
                            ),
                        )
                    )

                    self.ir.audit_entries.append(
                        IRAuditEntry(
                            id=addr.name,
                            category="Address",
                            message=(
                                f"FortiGate EMS dynamic address '{addr.name}' was normalized "
                                f"to a vendor-neutral dynamic address group using tag '{tag_name}'."
                            ),
                            confidence=(
                                MigrationConfidence.PARTIAL if used_fallback else MigrationConfidence.FULL
                            ),
                        )
                    )

                    continue

                elif addr.type == "dynamic":
                    dynamic_value = addr.filter or addr.obj_tag or addr.sdn or ""
                    self.ir.addresses.append(
                        self._preserve_source_only_address(
                            addr,
                            reason=(
                                f"FortiGate dynamic address sub-type {addr.sub_type!r} "
                                "is source-specific and requires target-specific review."
                            ),
                            original_value=dynamic_value,
                        )
                    )
                    self.ir.audit_entries.append(
                        IRAuditEntry(
                            id=addr.name,
                            category="Address",
                            message=(
                                f"Dynamic address '{addr.name}' uses FortiGate sub-type "
                                f"{addr.sub_type!r}; source semantics were retained without "
                                "converting it to an EMS dynamic address group."
                            ),
                            confidence=MigrationConfidence.MANUAL,
                        )
                    )
                    continue

                elif addr.type == "interface-subnet":
                    self.ir.addresses.append(
                        self._preserve_source_only_address(
                            addr,
                            reason=(
                                "FortiGate interface-subnet depends on source interface addressing "
                                "and cannot be safely converted during extraction."
                            ),
                            original_value=addr.interface or "",
                        )
                    )
                    continue

                elif addr.type == "route-tag":
                    self.ir.addresses.append(
                        self._preserve_source_only_address(
                            addr,
                            reason="FortiGate route-tag semantics require target-specific review.",
                            original_value="" if addr.route_tag is None else str(addr.route_tag),
                        )
                    )
                    continue

            if not val:
                self.ir.addresses.append(
                    self._preserve_source_only_address(
                        addr,
                        reason=(
                            "FortiGate address object has no safely normalizable explicit address "
                            "value. Source object was preserved without inference."
                        ),
                    )
                )
                self.ir.audit_entries.append(
                    IRAuditEntry(
                        id=addr.name,
                        category="Address",
                        message=(
                            f"Address '{addr.name}' has no explicit safely normalizable value. "
                            "The source object was preserved without inferring a replacement subnet."
                        ),
                        confidence=MigrationConfidence.MANUAL,
                    )
                )
                continue

            self.ir.addresses.append(
                self._create_ir_address(
                    name=addr.name,
                    source_context=addr.source_context,
                    addr_type=addr_type,
                    val=val,
                    description=addr.comment,
                    is_ipv6=addr.is_ipv6,
                    is_multicast=(
                        addr.is_multicast
                    ),
                    source_uuid=addr.uuid,
                    associated_interface=(
                        addr.associated_interface
                    ),
                    allow_routing=(
                        self._fortios_enabled(
                            addr.allow_routing
                        )
                    ),
                    source_color=addr.color,
                    source_sub_type=addr.sub_type,
                    source_obj_tag=addr.obj_tag,
                    source_tag_type=addr.tag_type,
                    source_obj_type=addr.obj_type,
                    source_dirty=addr.dirty,
                    source_attributes=dict(
                        addr.extra_settings
                    ),
                    source_section=self._address_source_section(addr),
                    address_family=self._address_family(addr),
                    source_type=addr.type,
                    source_list_entries=[entry.name for entry in addr.address_list],
                    source_tagging_entries=self._address_tagging_entries(addr),
                )
            )

        for fqdn in self.fg.wildcard_fqdns:
            val = fqdn.wildcard_fqdn

            self.ir.addresses.append(
                self._create_ir_address(
                    name=fqdn.name,
                    source_context=fqdn.source_context,
                    addr_type=(
                        AddressType.WILDCARD_FQDN
                    ),
                    val=val,
                    description=fqdn.comment,
                    source_uuid=fqdn.uuid,
                    source_section="firewall wildcard-fqdn custom",
                    address_family="ipv4",
                    source_type="wildcard-fqdn",
                    source_attributes=dict(
                        fqdn.extra_settings
                    ),
                )
            )

        for group in self.fg.address_groups:
            exclusion_enabled = group.exclude == "enable"
            review_reasons = []
            if exclusion_enabled or group.exclude_member:
                review_reasons.append("FortiGate exclusion membership semantics")
            if group.category in {"ztna-ems-tag", "ztna-geo-tag"}:
                review_reasons.append(f"FortiGate ZTNA category '{group.category}'")
            if group.extra_settings:
                review_reasons.append("unmodeled FortiGate address-group settings")
            if group.is_ipv6:
                review_reasons.append("IPv6 address-group target support requires verification")
            partial = bool(review_reasons) or group.type == "folder"
            self.ir.address_groups.append(
                IRAddressGroup(
                    name=group.name,
                    source_context=group.source_context,
                    members=list(group.member),
                    description=group.comment,
                    source_uuid=group.uuid,
                    allow_routing=(
                        self._fortios_enabled(
                            group.allow_routing
                        )
                    ),
                    source_color=group.color,
                    source_category=group.category,
                    source_section="firewall addrgrp6" if group.is_ipv6 else "firewall addrgrp",
                    address_family="ipv6" if group.is_ipv6 else "ipv4",
                    source_group_type=group.type,
                    source_exclude_setting=group.exclude,
                    source_fabric_object_setting=group.fabric_object,
                    exclusion_enabled=exclusion_enabled,
                    exclude_members=list(group.exclude_member),
                    source_tagging_entries=[
                        IRAddressGroupTaggingEntry(
                            name=entry.name, category=entry.category,
                            tags=list(entry.tags), source_attributes=dict(entry.extra_settings),
                        ) for entry in group.tagging
                    ],
                    source_attributes=dict(
                        group.extra_settings
                    ),
                    migration_status="PARTIALLY_NORMALIZED" if partial else "NORMALIZED",
                    requires_manual_review=bool(review_reasons),
                    audit_note="; ".join(review_reasons) or (
                        "FortiGate folder grouping metadata is source-specific" if group.type == "folder" else None
                    ),
                )
            )

    def _propagate_address_group_review(self) -> None:
        """Mark parent groups unsafe when they reference an unsafe nested group."""
        changed = True
        while changed:
            changed = False
            by_family = {(group.address_family, group.name): group for group in self.ir.address_groups}
            for group in self.ir.address_groups:
                unsafe = [name for name in group.members if (child := by_family.get((group.address_family, name))) and child.requires_manual_review]
                if unsafe and not group.requires_manual_review:
                    group.requires_manual_review = True
                    group.migration_status = "PARTIALLY_NORMALIZED"
                    note = f"contains nested address group(s) requiring manual review: {', '.join(unsafe)}"
                    group.audit_note = "; ".join(filter(None, [group.audit_note, note]))
                    changed = True

    def _mark_address_group_family_collisions(self) -> None:
        groups = {}
        for group in self.ir.address_groups:
            if group.source_section in {"firewall addrgrp", "firewall addrgrp6"}:
                groups.setdefault(group.name, []).append(group)
        for name, items in groups.items():
            if {item.address_family for item in items} == {"ipv4", "ipv6"}:
                for item in items:
                    item.requires_manual_review = True
                    item.migration_status = "PARTIALLY_NORMALIZED"
                    item.audit_note = "; ".join(filter(None, [item.audit_note, f"same name '{name}' exists in IPv4 and IPv6 address-group namespaces"]))

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    @staticmethod
    def _clean_port_range(port_str: str) -> str:
        """Return the destination side without rewriting its value."""
        if not port_str:
            return IR_KEYWORD_ANY

        return port_str.partition(":")[0].strip()

    def _parse_port_ranges(
        self,
        port_str: str,
        protocol: ServiceProtocol,
    ) -> List[IRServicePort]:
        if not port_str:
            return [
                IRServicePort(
                    protocol=protocol,
                    port=IR_KEYWORD_ANY,
                )
            ]

        parts = [
            part.strip()
            for part in (
                port_str
                .replace(",", " ")
                .split()
            )
            if part.strip()
        ]

        result = []

        for part in parts:
            destination_port, separator, source_port = (
                part.partition(":")
            )
            result.append(
                IRServicePort(
                    protocol=protocol,
                    port=destination_port.strip(),
                    source_port=(
                        source_port.strip()
                        if separator
                        else None
                    ),
                    raw_source_value=part,
                )
            )

        if result:
            return result

        return [
            IRServicePort(
                protocol=protocol,
                port=IR_KEYWORD_ANY,
            )
        ]

    @staticmethod
    def _service_unmodeled_semantic_settings(
        service: FGService,
    ) -> List[str]:
        """Identify retained service settings without canonical semantics."""
        unmodeled = []
        for key, value in service.extra_settings.items():
            if key != "source_unset_settings":
                unmodeled.append(key)
                continue

            unset_settings = value if isinstance(value, list) else [value]
            for unset_key in unset_settings:
                normalized_key = str(unset_key).replace("-", "_")
                if normalized_key not in FGService.model_fields:
                    unmodeled.append(str(unset_key))

        return list(dict.fromkeys(sorted(unmodeled)))

    def _transform_services(
        self,
    ) -> None:
        for category in self.fg.service_categories:
            cat_review_reasons = []
            if not category.name or len(category.name) > 63:
                cat_review_reasons.append("Service category name is missing or exceeds 63 characters.")
            if category.comment is not None and len(category.comment) > 255:
                cat_review_reasons.append("Service category comment exceeds 255 characters.")
            if category.fabric_object is not None and category.fabric_object not in {"enable", "disable"}:
                cat_review_reasons.append(f"Invalid fabric-object setting '{category.fabric_object}'.")
            if category.extra_settings:
                cat_review_reasons.append(f"Unknown source settings: {', '.join(sorted(category.extra_settings))}")

            is_normalized = not bool(cat_review_reasons)
            self.ir.service_categories.append(
                IRServiceCategory(
                    name=category.name,
                    source_context=category.source_context,
                    description=category.comment,
                    source_fabric_object=category.fabric_object,
                    source_attributes=dict(
                        category.extra_settings
                    ),
                    migration_status="NORMALIZED" if is_normalized else "PARTIALLY_NORMALIZED",
                    requires_manual_review=not is_normalized,
                    review_reasons=cat_review_reasons,
                )
            )

        for service in self.fg.services:
            ports = []
            protocol_name = service.protocol.upper()
            unmodeled_semantics = (
                self._service_unmodeled_semantic_settings(service)
            )

            if service.tcp_portrange:
                ports.extend(
                    self._parse_port_ranges(
                        service.tcp_portrange,
                        ServiceProtocol.TCP,
                    )
                )

            if service.udp_portrange:
                ports.extend(
                    self._parse_port_ranges(
                        service.udp_portrange,
                        ServiceProtocol.UDP,
                    )
                )

            if service.sctp_portrange:
                ports.extend(
                    self._parse_port_ranges(
                        service.sctp_portrange,
                        ServiceProtocol.SCTP,
                    )
                )

            if protocol_name in ["ICMP", "ICMP6"]:
                ports.append(
                    IRServicePort(
                        protocol=(
                            ServiceProtocol.ICMPV6
                            if protocol_name == "ICMP6"
                            else ServiceProtocol.ICMP
                        ),
                        port=IR_KEYWORD_ANY,
                        icmptype=(
                            service.icmptype
                        ),
                        icmpcode=(
                            service.icmpcode
                        ),
                    )
                )

            elif (
                protocol_name == "IP"
                and service.protocol_number is not None
                and service.protocol_number != 0
            ):
                ports.append(
                    IRServicePort(
                        protocol=(
                            ServiceProtocol.IP
                        ),
                        port=str(
                            service.protocol_number
                        ),
                    )
                )

            elif protocol_name == "IP":
                ports.append(
                    IRServicePort(
                        protocol=ServiceProtocol.ANY,
                        port=IR_KEYWORD_ANY,
                    )
                )

            source_proxy = (
                self._fortios_enabled(service.proxy)
                if service.proxy is not None
                else None
            )
            has_exact_zero_destination = any(
                port.port == "0" for port in ports
            )
            has_sctp = any(
                port.protocol == ServiceProtocol.SCTP
                for port in ports
            )
            requires_manual_review = bool(
                source_proxy
                or has_exact_zero_destination
                or has_sctp
                or unmodeled_semantics
            )
            audit_reasons = []

            if source_proxy:
                audit_reasons.append(
                    "FortiGate proxy service semantics require target review"
                )

            if has_exact_zero_destination:
                audit_reasons.append(
                    "FortiGate destination port 0 has non-matching/block-style "
                    "service semantics and must not be broadened to an any-port service"
                )

            if has_sctp:
                audit_reasons.append(
                    "FortiGate SCTP service semantics require target-platform support review"
                )

            if unmodeled_semantics:
                audit_reasons.append(
                    "Unmodeled FortiGate service semantics preserved in source "
                    f"attributes: {', '.join(unmodeled_semantics)}"
                )

            if not ports:
                requires_manual_review = True
                audit_reasons.append(
                    "source protocol has no safe normalized port representation"
                )

            self.ir.services.append(
                IRService(
                    name=service.name,
                    source_context=service.source_context,
                    ports=ports,
                    source_uuid=service.uuid,
                    source_category=service.category,
                    source_protocol_configured=service.source_protocol_configured,
                    source_protocol=service.protocol,
                    source_protocol_number=(
                        service.protocol_number
                    ),
                    source_proxy=source_proxy,
                    source_color=service.color,
                    source_fabric_object=service.fabric_object,
                    source_unmodeled_semantic_settings=unmodeled_semantics,
                    source_attributes=dict(
                        service.extra_settings
                    ),
                    migration_status=(
                        "PARTIALLY_NORMALIZED"
                        if requires_manual_review
                        else "NORMALIZED"
                    ),
                    requires_manual_review=(
                        requires_manual_review
                    ),
                    audit_note=(
                        "; ".join(audit_reasons)
                        if audit_reasons
                        else None
                    ),
                    description=service.comment,
                )
            )

        for group in self.fg.service_groups:
            source_proxy = (
                self._fortios_enabled(group.proxy)
                if group.proxy is not None
                else None
            )
            requires_review = source_proxy is True
            self.ir.service_groups.append(
                IRServiceGroup(
                    name=group.name,
                    source_context=group.source_context,
                    members=group.member,
                    source_uuid=group.uuid,
                    source_color=group.color,
                    source_proxy=source_proxy,
                    source_fabric_object=group.fabric_object,
                    source_attributes=dict(
                        group.extra_settings
                    ),
                    migration_status=(
                        "PARTIALLY_NORMALIZED" if requires_review else "NORMALIZED"
                    ),
                    requires_manual_review=requires_review,
                    audit_note=(
                        "FortiGate proxy service-group semantics require target review."
                        if requires_review else None
                    ),
                    description=group.comment,
                )
            )

        self._propagate_service_group_review()

    def _propagate_service_group_review(self) -> None:
        """Propagate unsafe services, nested groups, and missing references."""
        service_by_name = {
            (item.source_context, item.name): item for item in self.ir.services
        }
        group_by_name = {
            (item.source_context, item.name): item for item in self.ir.service_groups
        }

        changed = True
        while changed:
            changed = False
            for group in self.ir.service_groups:
                unsafe = []
                unresolved = []
                for member in group.members:
                    key = (group.source_context, member)
                    service = service_by_name.get(key)
                    child_group = group_by_name.get(key)
                    if service is not None:
                        if service.requires_manual_review or service.migration_status != "NORMALIZED":
                            unsafe.append(member)
                    elif child_group is not None:
                        if child_group.requires_manual_review or child_group.migration_status != "NORMALIZED":
                            unsafe.append(member)
                    else:
                        unsafe.append(member)
                        unresolved.append(member)

                unsafe = list(dict.fromkeys(unsafe))
                unresolved = list(dict.fromkeys(unresolved))
                notes = []
                if unsafe:
                    notes.append(
                        "contains service/service-group member(s) requiring "
                        f"review: {', '.join(unsafe)}"
                    )
                if unresolved:
                    notes.append(
                        "unresolved service/service-group member reference(s): "
                        f"{', '.join(unresolved)}"
                    )

                prior_note = group.audit_note or ""
                new_notes = [note for note in notes if note not in prior_note]
                if unsafe != group.unsafe_members:
                    group.unsafe_members = unsafe
                    changed = True
                if unsafe and (
                    not group.requires_manual_review
                    or group.migration_status == "NORMALIZED"
                ):
                    group.requires_manual_review = True
                    group.migration_status = "PARTIALLY_NORMALIZED"
                    changed = True
                if new_notes:
                    group.audit_note = "; ".join(
                        filter(None, [group.audit_note, *new_notes])
                    )
                    changed = True

    # ------------------------------------------------------------------
    # Schedules
    # ------------------------------------------------------------------

    def _transform_schedules(
        self,
    ) -> None:
        for schedule in self.fg.schedules:
            sched_review_reasons = []
            if schedule.extra_settings:
                sched_review_reasons.append(
                    f"Unknown source schedule settings: {', '.join(sorted(schedule.extra_settings))}"
                )

            is_normalized = not bool(sched_review_reasons)
            self.ir.schedules.append(
                IRSchedule(
                    name=schedule.name,
                    source_context=schedule.source_context,
                    start=schedule.start,
                    end=schedule.end,
                    days=schedule.day,
                    schedule_type=schedule.type,
                    source_color=schedule.color,
                    expiration_days=schedule.expiration_days,
                    source_fabric_object=schedule.fabric_object,
                    start_utc=schedule.start_utc,
                    end_utc=schedule.end_utc,
                    migration_status="NORMALIZED" if is_normalized else "PARTIALLY_NORMALIZED",
                    requires_manual_review=not is_normalized,
                    review_reasons=sched_review_reasons,
                    source_attributes=dict(schedule.extra_settings),
                )
            )

    def _transform_schedule_groups(self) -> None:
        schedules = {(item.source_context, item.name) for item in self.fg.schedules}
        group_names = {(item.source_context, item.name) for item in self.fg.schedule_groups}
        for group in self.fg.schedule_groups:
            unresolved = [
                member for member in group.member
                if (group.source_context, member) not in schedules
                and (group.source_context, member) not in group_names
            ]
            self.ir.schedule_groups.append(
                IRScheduleGroup(
                    name=group.name,
                    source_context=group.source_context,
                    members=list(group.member),
                    description=group.comments,
                    unresolved_members=unresolved,
                    requires_manual_review=bool(unresolved),
                    source_attributes=dict(group.extra_settings),
                )
            )

    def _transform_ssh_keys(self) -> None:
        """Preserve public SSH key/CA metadata without credential contents."""
        for key in self.fg.ssh_keys:
            self.ir.ssh_keys.append(
                IRSSHKey(
                    name=key.name,
                    key_type=key.key_type,
                    public_key=key.public_key,
                    source_origin=key.source,
                    has_private_key=key.has_private_key,
                    has_password=key.has_password,
                    source_attributes=dict(key.extra_settings),
                )
            )

    def _transform_traffic_shapers(self) -> None:
        for shaper in self.fg.traffic_shapers:
            source_attributes = dict(shaper.extra_settings)
            per_policy = None
            if shaper.per_policy == "enable":
                per_policy = True
            elif shaper.per_policy == "disable":
                per_policy = False
            elif shaper.per_policy is not None:
                source_attributes["per_policy"] = shaper.per_policy

            self.ir.traffic_shapers.append(
                IRTrafficShaper(
                    name=shaper.name,
                    source_context=shaper.source_context,
                    guaranteed_bandwidth=shaper.guaranteed_bandwidth,
                    maximum_bandwidth=shaper.maximum_bandwidth,
                    source_bandwidth_unit=shaper.bandwidth_unit,
                    priority=shaper.priority,
                    per_policy=per_policy,
                    source_attributes=source_attributes,
                )
            )

    def _transform_proxy_settings(self) -> None:
        for proxy in self.fg.proxy_addresses:
            self.ir.proxy_addresses.append(
                IRProxyAddress(
                    name=proxy.name,
                    source_context=proxy.source_context,
                    source_uuid=proxy.uuid,
                    proxy_address_type=proxy.type,
                    host=proxy.host,
                    host_regex=proxy.host_regex,
                    path=proxy.path,
                    query=proxy.query,
                    source_attributes=dict(proxy.extra_settings),
                )
            )

        if self.fg.web_proxy_global is not None:
            self.ir.web_proxy_settings = IRWebProxySettings(
                proxy_fqdn=self.fg.web_proxy_global.proxy_fqdn,
                source_attributes=dict(self.fg.web_proxy_global.extra_settings),
            )

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def _resolve_policy_zones(
        self,
        interfaces: List[str],
        policy_id: int,
        direction: str,
        source_context: str,
    ) -> List[str]:
        zones: List[str] = []
        unresolved: Set[str] = set()

        for interface in interfaces:
            if interface == "any":
                zone = IR_KEYWORD_ANY
            else:
                zone = (
                    self._intf_to_zone.get((source_context, interface))
                    or self.fg_zone_intf_map.get((source_context, interface))
                )
                if zone is None and (source_context, interface) in self._sdwan_zone_names:
                    zone = interface

            if zone:
                if zone not in zones:
                    zones.append(zone)
                continue

            if interface in unresolved:
                continue

            unresolved.add(interface)
            self.ir.audit_entries.append(
                IRAuditEntry(
                    id=(
                        f"policy:{policy_id}:"
                        f"{direction}:{interface}"
                    ),
                    category="Policy Zone Resolution",
                    message=(
                        f"Policy {policy_id} references interface "
                        f"'{interface}' with no explicit canonical "
                        "zone. Source interface preserved; no "
                        "trust/untrust zone inferred."
                    ),
                    confidence=MigrationConfidence.MANUAL,
                )
            )

        return zones

    @staticmethod
    def _policy_value_is_configured(value: object) -> bool:
        return value not in (None, "", "disable", [])

    @staticmethod
    def _get_policy_internet_service_settings(
        policy: FGPolicy,
    ) -> Dict[str, object]:
        """Return configured FortiGate Internet Service source settings."""
        values = {
            "internet-service": policy.internet_service,
            "internet-service-id": policy.extra_settings.get("internet_service_id"),
            "internet-service-custom": policy.internet_service_custom,
            "internet-service-custom-group": policy.internet_service_custom_group,
            "internet-service-group": policy.internet_service_group,
            "internet-service-name": policy.internet_service_name,
            "internet-service-negate": policy.internet_service_negate,
            "internet-service-src": policy.internet_service_src,
            "internet-service-src-custom": policy.internet_service_src_custom,
            "internet-service-src-custom-group": policy.internet_service_src_custom_group,
            "internet-service-src-group": policy.internet_service_src_group,
            "internet-service-src-name": policy.internet_service_src_name,
            "internet-service-src-negate": policy.internet_service_src_negate,
            "internet-service6": policy.internet_service6,
            "internet-service6-custom": policy.internet_service6_custom,
            "internet-service6-custom-group": policy.internet_service6_custom_group,
            "internet-service6-group": policy.internet_service6_group,
            "internet-service6-name": policy.internet_service6_name,
            "internet-service6-negate": policy.internet_service6_negate,
            "internet-service6-src": policy.internet_service6_src,
            "internet-service6-src-custom": policy.internet_service6_src_custom,
            "internet-service6-src-custom-group": policy.internet_service6_src_custom_group,
            "internet-service6-src-group": policy.internet_service6_src_group,
            "internet-service6-src-name": policy.internet_service6_src_name,
            "internet-service6-src-negate": policy.internet_service6_src_negate,
        }
        return {
            key: value
            for key, value in values.items()
            if FGToIRTransformer._policy_value_is_configured(value)
        }

    @staticmethod
    def _policy_effective_match_fields(
        policy: FGPolicy,
    ) -> Tuple[List[str], List[str], List[str], List[str]]:
        """Return safe portable matches plus reasons for inactive source fields."""
        source = list(policy.srcaddr)
        destination = list(policy.dstaddr)
        service = list(policy.service)
        review_reasons: List[str] = []

        def mark_inactive(
            fields: Tuple[str, ...],
            label: str,
        ) -> None:
            configured = [field for field in fields if getattr(policy, field)]
            if not configured:
                return
            review_reasons.append(
                f"FortiOS {label} is enabled; configured {', '.join(configured)} "
                "values are preserved as source evidence but are not effective "
                "ordinary portable match criteria"
            )
            for field in fields:
                if field in configured and field.endswith("_negate"):
                    review_reasons.append(
                        f"FortiOS {label} leaves configured {field} inactive "
                        "with its ordinary address/service selector"
                    )

        if policy.internet_service == "enable":
            destination = []
            service = []
            mark_inactive(
                ("dstaddr", "dstaddr_negate", "service", "service_negate"),
                "Internet Service destination matching",
            )
        if policy.internet_service6 == "enable":
            service = []
            mark_inactive(
                ("dstaddr6", "dstaddr6_negate", "service", "service_negate"),
                "IPv6 Internet Service destination matching",
            )
        if policy.internet_service_src == "enable":
            source = []
            mark_inactive(
                ("srcaddr", "srcaddr_negate"),
                "Internet Service source matching",
            )
        if policy.internet_service6_src == "enable":
            mark_inactive(
                ("srcaddr6", "srcaddr6_negate"),
                "IPv6 Internet Service source matching",
            )

        return source, destination, service, review_reasons

    def _policy_review_reasons(
        self,
        policy: FGPolicy,
        policy_based_contexts: Optional[Set[str]] = None,
    ) -> List[str]:
        """Return ordered, unique reasons a policy needs manual review.

        The helper owns policy review classification.  Parsing, dependency
        resolution, zone resolution, and IR field mapping remain separate so
        this refactor cannot silently change the extracted policy values.
        """
        if policy_based_contexts is None:
            policy_based_contexts = {
                context.vdom
                for context in self.fg.execution_contexts
                if context.ngfw_mode == "policy-based"
            }
        identity_indexes = self._build_identity_dependency_indexes()

        ips_sensors_by_ctx: Dict[str, Set[str]] = {}
        for item in self.fg.ips_sensors:
            ips_sensors_by_ctx.setdefault(item.source_context, set()).add(item.name)

        structured_profiles_by_ctx: Dict[Tuple[str, str], Set[str]] = {}
        for item in self.fg.structured_source_objects:
            if item.name:
                structured_profiles_by_ctx.setdefault(
                    (item.source_context, item.source_path),
                    set(),
                ).add(item.name)

        source_profile_names = {
            "antivirus": structured_profiles_by_ctx.get(
                (policy.source_context, "antivirus profile"),
                set(),
            ),
            "ips": ips_sensors_by_ctx.get(policy.source_context, set()),
            "webfilter": structured_profiles_by_ctx.get(
                (policy.source_context, "webfilter profile"),
                set(),
            ),
            "application": structured_profiles_by_ctx.get(
                (policy.source_context, "application list"),
                set(),
            ),
            "ssl-ssh": structured_profiles_by_ctx.get(
                (policy.source_context, "firewall ssl-ssh-profile"),
                set(),
            ),
            "profile-group": structured_profiles_by_ctx.get(
                (policy.source_context, "firewall profile-group"),
                set(),
            ),
            "protocol-options": structured_profiles_by_ctx.get(
                (policy.source_context, "firewall profile-protocol-options"),
                set(),
            ),
        }

        schedule_keys = {
            (item.source_context, item.name)
            for item in self.fg.schedules
        } | {
            (item.source_context, item.name)
            for item in self.fg.schedule_groups
        }
        schedule_group_keys = {
            (item.source_context, item.name)
            for item in self.fg.schedule_groups
        }
        custom_is_keys = {
            (item.source_context, item.name)
            for item in self.fg.custom_internet_services
            if item.name
        }
        custom_is_group_keys = {
            (item.source_context, item.name)
            for item in self.fg.custom_internet_service_groups
            if item.name
        }

        review_reasons: List[str] = []

        # Execution mode.
        if policy.source_context in policy_based_contexts:
            review_reasons.append(
                "VDOM uses policy-based NGFW mode; conventional firewall policy is not complete without security-policy semantics"
            )

        # Action.
        action_map = {
            "accept": PolicyAction.ALLOW,
            "deny": PolicyAction.DENY,
            "ipsec": PolicyAction.IPSEC,
        }
        if policy.action == "ipsec":
            review_reasons.append("policy-based IPsec action")
        elif policy.action not in action_map:
            review_reasons.append(f"unrecognized action '{policy.action}'")

        # Inspection mode.
        if policy.inspection_mode == "proxy":
            review_reasons.append(
                "FortiGate proxy inspection mode requires target-platform review"
            )
        elif policy.inspection_mode not in (None, "flow"):
            review_reasons.append(
                "Unknown FortiGate inspection mode requires manual review"
            )

        # ZTNA.
        ztna_used = any((
            policy.ztna_status not in (None, "disable"),
            policy.ztna_device_ownership,
            policy.ztna_ems_tag,
            policy.ztna_ems_tag_secondary,
            policy.ztna_geo_tag,
            policy.ztna_policy_redirect,
            policy.ztna_tags_match_logic,
        ))
        if ztna_used:
            review_reasons.append(
                "FortiGate ZTNA policy semantics require target-platform review"
            )

        # NAT semantics.
        nat_controls = {
            "fixedport": policy.fixedport,
            "match-vip": policy.match_vip,
            "match-vip-only": policy.match_vip_only,
            "nat46": policy.nat46,
            "nat64": policy.nat64,
            "natinbound": policy.natinbound,
            "natoutbound": policy.natoutbound,
            "natip": policy.natip,
            "poolname6": policy.poolname6,
        }
        configured_nat_controls = [
            key
            for key, value in nat_controls.items()
            if self._policy_value_is_configured(value)
        ]
        if configured_nat_controls:
            review_reasons.append(
                "FortiGate unsupported NAT behavior is retained in typed source settings: "
                + ", ".join(configured_nat_controls)
            )
        if policy.nat not in ("enable", "disable"):
            review_reasons.append(
                f"Unknown FortiGate NAT setting '{policy.nat}'"
            )
        if policy.ippool not in ("enable", "disable"):
            review_reasons.append(
                f"Unknown FortiGate IP pool setting '{policy.ippool}'"
            )
        if policy.ippool == "enable" and not policy.poolname:
            review_reasons.append("IP pool is enabled without a pool reference")
        if policy.vpntunnel and policy.action != "ipsec":
            review_reasons.append(
                "FortiGate VPN tunnel semantics require target-platform review"
            )

        # Security profile semantics.
        if policy.profile_type == "group" and policy.profile_group:
            review_reasons.append("FortiGate profile group")

        profile_references = [
            ("antivirus", policy.av_profile),
            ("ips", policy.ips_sensor),
            ("webfilter", policy.webfilter_profile),
            ("application", policy.application_list),
            ("ssl-ssh", policy.ssl_ssh_profile),
            ("profile-group", policy.profile_group),
            ("protocol-options", policy.profile_protocol_options),
        ]
        profiles_enforced = (
            policy.utm_status == "enable"
            or policy.profile_type == "group"
        )
        unresolved_security_profiles = [
            f"{profile_type}:{name}"
            for profile_type, name in profile_references
            if profiles_enforced
            and name
            and name not in source_profile_names[profile_type]
        ]
        portable_profile_semantics = any((
            policy.av_profile,
            policy.ips_sensor,
            policy.webfilter_profile,
            policy.application_list,
            policy.profile_group,
        ))
        if profiles_enforced and portable_profile_semantics:
            review_reasons.append(
                "FortiGate security profile semantics require target-specific translation"
            )
        if unresolved_security_profiles:
            review_reasons.append(
                "unresolved security profile reference(s): "
                + ", ".join(unresolved_security_profiles)
            )

        # Other retained source settings and non-portable policy semantics.
        negate_settings = {
            "srcaddr-negate": policy.srcaddr_negate,
            "dstaddr-negate": policy.dstaddr_negate,
            "srcaddr6-negate": policy.srcaddr6_negate,
            "dstaddr6-negate": policy.dstaddr6_negate,
            "service-negate": policy.service_negate,
        }
        review_reasons.extend(
            key
            for key, value in negate_settings.items()
            if self._policy_value_is_configured(value)
        )
        if policy.srcaddr6 or policy.dstaddr6:
            review_reasons.append("IPv6 policy address references")

        if self._get_policy_internet_service_settings(policy):
            review_reasons.append(
                "FortiGate Internet Service match semantics are retained and not merged with ordinary address/service matching"
            )

        for reference in (
            *policy.internet_service_custom,
            *policy.internet_service_src_custom,
            *policy.internet_service6_custom,
            *policy.internet_service6_src_custom,
        ):
            if (policy.source_context, reference) not in custom_is_keys:
                review_reasons.append(
                    f"unresolved custom Internet Service reference '{reference}' in VDOM '{policy.source_context}'"
                )
        for reference in (
            *policy.internet_service_custom_group,
            *policy.internet_service_src_custom_group,
            *policy.internet_service6_custom_group,
            *policy.internet_service6_src_custom_group,
        ):
            if (policy.source_context, reference) not in custom_is_group_keys:
                review_reasons.append(
                    f"unresolved custom Internet Service group reference '{reference}' in VDOM '{policy.source_context}'"
                )

        if (
            policy.schedule is not None
            and policy.schedule != "always"
            and (policy.source_context, policy.schedule) not in schedule_keys
        ):
            review_reasons.append(
                f"unresolved schedule reference '{policy.schedule}' in VDOM '{policy.source_context}'"
            )
        elif (
            policy.schedule is not None
            and (policy.source_context, policy.schedule) in schedule_group_keys
        ):
            review_reasons.append(
                f"schedule group '{policy.schedule}' requires target-specific expansion without widening"
            )

        if policy.groups:
            review_reasons.append(
                "FortiGate user/group identity match requires target-specific identity mapping"
            )
        if policy.users:
            review_reasons.append(
                "FortiGate explicit user identity match requires target-specific identity mapping"
            )
        if policy.identity_based_route:
            review_reasons.append(
                "FortiGate identity-based routing requires target-specific authentication and forwarding translation"
            )
        unresolved_user_groups = [
            name
            for name in dict.fromkeys(policy.groups)
            if name not in identity_indexes["user_groups"]
        ]
        if unresolved_user_groups:
            review_reasons.append(
                "unresolved identity group reference(s): "
                + ", ".join(unresolved_user_groups)
            )
        unresolved_users = [
            name
            for name in dict.fromkeys(policy.users)
            if name not in identity_indexes["local_users"]
        ]
        if unresolved_users:
            review_reasons.append(
                "unresolved identity user reference(s): "
                + ", ".join(unresolved_users)
            )

        unsafe_v4 = {
            (group.source_context, group.name)
            for group in self.ir.address_groups
            if group.address_family == "ipv4" and group.requires_manual_review
        }
        unsafe_v6 = {
            (group.source_context, group.name)
            for group in self.ir.address_groups
            if group.address_family == "ipv6" and group.requires_manual_review
        }
        for name in [*policy.srcaddr, *policy.dstaddr]:
            if (policy.source_context, name) in unsafe_v4:
                review_reasons.append(
                    f"references address group '{name}' requiring manual review"
                )
        for name in [*policy.srcaddr6, *policy.dstaddr6]:
            if (policy.source_context, name) in unsafe_v6:
                review_reasons.append(
                    f"references address group '{name}' requiring manual review"
                )

        # Keep approved cosmetic metadata out of the unknown-setting review.
        semantic_unknowns = [
            str(key)
            for key in policy.extra_settings
            if str(key).replace("-", "_").lower() not in COSMETIC_POLICY_SETTINGS
        ]
        if semantic_unknowns:
            review_reasons.append(
                "Retained unknown traffic-affecting FortiGate policy settings: "
                + ", ".join(semantic_unknowns)
            )

        return list(dict.fromkeys(review_reasons))

    def _get_policy_semantic_review_reasons(
        self,
        policy: FGPolicy,
    ) -> List[str]:
        """Return ordered, unique review reasons for one source policy."""
        return self._policy_review_reasons(policy)

    def _transform_policies(
        self,
    ) -> None:
        identity_indexes = self._build_identity_dependency_indexes()
        ips_sensors_by_ctx: Dict[str, Set[str]] = {}
        for item in self.fg.ips_sensors:
            ips_sensors_by_ctx.setdefault(item.source_context, set()).add(item.name)

        structured_profiles_by_ctx: Dict[Tuple[str, str], Set[str]] = {}
        for item in self.fg.structured_source_objects:
            if item.name:
                structured_profiles_by_ctx.setdefault((item.source_context, item.source_path), set()).add(item.name)

        for policy in self.fg.policies:
            ctx = policy.source_context
            source_profile_names = {
                "antivirus": structured_profiles_by_ctx.get((ctx, "antivirus profile"), set()),
                "ips": ips_sensors_by_ctx.get(ctx, set()),
                "webfilter": structured_profiles_by_ctx.get((ctx, "webfilter profile"), set()),
                "application": structured_profiles_by_ctx.get((ctx, "application list"), set()),
                "ssl-ssh": structured_profiles_by_ctx.get((ctx, "firewall ssl-ssh-profile"), set()),
                "profile-group": structured_profiles_by_ctx.get((ctx, "firewall profile-group"), set()),
                "protocol-options": structured_profiles_by_ctx.get((ctx, "firewall profile-protocol-options"), set()),
            }
            from_zones = self._resolve_policy_zones(
                policy.srcintf,
                policy.id,
                "source",
                policy.source_context,
            )
            to_zones = self._resolve_policy_zones(
                policy.dstintf,
                policy.id,
                "destination",
                policy.source_context,
            )

            action_map = {
                "accept": PolicyAction.ALLOW,
                "deny": PolicyAction.DENY,
                "ipsec": PolicyAction.IPSEC,
            }
            action = action_map.get(policy.action, PolicyAction.DENY)

            review_reasons = self._get_policy_semantic_review_reasons(policy)
            effective_source, effective_destination, effective_service, internet_service_review_reasons = (
                self._policy_effective_match_fields(policy)
            )
            review_reasons.extend(internet_service_review_reasons)
            review_reasons = list(dict.fromkeys(review_reasons))
            internet_service_fields = self._get_policy_internet_service_settings(policy)

            unresolved_user_groups = [
                name for name in policy.groups
                if name not in identity_indexes["user_groups"]
            ]
            unresolved_users = [
                name for name in policy.users
                if name not in identity_indexes["local_users"]
            ]
            if unresolved_user_groups:
                self._add_identity_audit(
                    f"policy:{policy.id}:user-groups",
                    f"Policy {policy.id} contains unresolved user group reference(s): "
                    f"{', '.join(unresolved_user_groups)}. Source values were preserved; "
                    "the rule requires manual review and must not be broadened.",
                )
            if unresolved_users:
                self._add_identity_audit(
                    f"policy:{policy.id}:users",
                    f"Policy {policy.id} contains unresolved user reference(s): "
                    f"{', '.join(unresolved_users)}. Source values were preserved; the "
                    "rule requires manual review and must not be broadened.",
                )

            profile_references = [
                ("antivirus", policy.av_profile),
                ("ips", policy.ips_sensor),
                ("webfilter", policy.webfilter_profile),
                ("application", policy.application_list),
                ("ssl-ssh", policy.ssl_ssh_profile),
                ("profile-group", policy.profile_group),
                ("protocol-options", policy.profile_protocol_options),
            ]
            profiles_enforced = (
                policy.utm_status == "enable"
                or policy.profile_type == "group"
            )
            unresolved_security_profiles = [
                f"{profile_type}:{name}"
                for profile_type, name in profile_references
                if profiles_enforced
                and name
                and name not in source_profile_names[profile_type]
            ]
            portable_profile_semantics = any((
                policy.av_profile,
                policy.ips_sensor,
                policy.webfilter_profile,
                policy.application_list,
                policy.profile_group,
            ))
            security_profile_semantics_review = bool(
                profiles_enforced and portable_profile_semantics
            )
            if unresolved_security_profiles:
                self._add_identity_audit(
                    f"policy:{policy.id}:security-profiles",
                    f"Policy {policy.id} contains unresolved security profile "
                    f"reference(s): {', '.join(unresolved_security_profiles)}. Source "
                    "values were preserved and require manual review.",
                )

            ir_policy = IRPolicy(
                name=(
                    policy.name
                    or f"Rule_{policy.id}"
                ),
                source_rule_id=str(
                    policy.id
                ),
                source_uuid=policy.uuid,
                source_from_interfaces=list(
                    policy.srcintf
                ),
                source_to_interfaces=list(
                    policy.dstintf
                ),
                source_address_references=list(
                    policy.srcaddr
                ),
                destination_address_references=list(
                    policy.dstaddr
                ),
                source_context=policy.source_context,
                source_ipv6_address_references=list(
                    policy.srcaddr6
                ),
                destination_ipv6_address_references=list(
                    policy.dstaddr6
                ),
                source_address_negate_setting=policy.srcaddr_negate,
                destination_address_negate_setting=policy.dstaddr_negate,
                source_ipv6_address_negate_setting=policy.srcaddr6_negate,
                destination_ipv6_address_negate_setting=policy.dstaddr6_negate,
                source_service_references=list(
                    policy.service
                ),
                source_service_negate_setting=policy.service_negate,
                source_action=policy.action,
                source_schedule=policy.schedule,
                source_user_groups=list(
                    policy.groups
                ),
                source_users=list(
                    policy.users
                ),
                unresolved_user_groups=unresolved_user_groups,
                unresolved_users=unresolved_users,
                identity_dependency_review=bool(policy.groups or policy.users),
                source_log_setting=(
                    policy.logtraffic
                ),
                source_log_start_setting=policy.logtraffic_start,
                source_utm_status=(
                    policy.utm_status
                ),
                source_profile_type=policy.profile_type,
                source_profile_group=policy.profile_group,
                source_profile_protocol_options=policy.profile_protocol_options,
                unresolved_security_profiles=unresolved_security_profiles,
                security_profile_semantics_review=security_profile_semantics_review,
                source_internet_service_status=policy.internet_service,
                source_internet_service_settings=internet_service_fields,
                source_vpn_tunnel=policy.vpntunnel,
                source_identity_based_route=policy.identity_based_route,
                source_inspection_mode=(
                    policy.inspection_mode
                ),
                source_ztna_status=(
                    policy.ztna_status
                ),
                source_ztna_ems_tags=list(
                    policy.ztna_ems_tag
                ),
                source_ztna_device_ownership=policy.ztna_device_ownership,
                source_ztna_ems_tags_secondary=list(
                    policy.ztna_ems_tag_secondary
                ),
                source_ztna_geo_tags=list(policy.ztna_geo_tag),
                source_ztna_policy_redirect=policy.ztna_policy_redirect,
                source_ztna_tags_match_logic=policy.ztna_tags_match_logic,
                source_extra_settings=dict(policy.extra_settings),
                nat_enabled=(
                    policy.nat == "enable"
                ),
                nat_pool_enabled=(
                    policy.ippool == "enable"
                ),
                nat_pool_names=list(
                    policy.poolname
                ),
                nat_pool_names6=list(
                    policy.poolname6
                ),
                migration_status=(
                    "PARTIALLY_NORMALIZED"
                    if review_reasons
                    else "NORMALIZED"
                ),
                review_reasons=review_reasons,
                requires_manual_review=bool(review_reasons),
                from_zone=from_zones,
                to_zone=to_zones,
                source=[
                    normalize_to_ir(
                        "fortigate",
                        address,
                    )
                    for address
                    in effective_source
                ],
                destination=[
                    normalize_to_ir(
                        "fortigate",
                        address,
                    )
                    for address
                    in effective_destination
                ],
                service=[
                    normalize_to_ir(
                        "fortigate",
                        service,
                    )
                    for service
                    in effective_service
                ],
                action=action,
                description=policy.comments,
                schedule=policy.schedule,
                log_start=(
                    policy.logtraffic_start == "enable"
                ),
                log_end=(
                    policy.logtraffic
                    in (
                        "all",
                        "utm",
                    )
                ),
                disabled=(
                    policy.status
                    == "disable"
                ),
                internet_service=list(
                    policy.internet_service_name
                ),
                ssl_ssh_profile=(
                    policy.ssl_ssh_profile
                ),
                antivirus=policy.av_profile,
                ips_sensor=policy.ips_sensor,
                webfilter=policy.webfilter_profile,
                application_list=policy.application_list,
            )

            if (
                policy.utm_status == "enable"
                and policy.profile_type != "group"
                and any((
                    policy.av_profile,
                    policy.ips_sensor,
                    policy.webfilter_profile,
                    policy.application_list,
                    policy.ssl_ssh_profile,
                ))
            ):
                active_features = []

                if policy.av_profile:
                    active_features.append(
                        f"AV_{policy.av_profile}"
                    )

                if policy.ips_sensor:
                    active_features.append(
                        f"IPS_{policy.ips_sensor}"
                    )

                if policy.webfilter_profile:
                    active_features.append(
                        f"WF_{policy.webfilter_profile}"
                    )

                if policy.application_list:
                    active_features.append(
                        f"APP_{policy.application_list}"
                    )

                group_name = (
                    "SPG_" + "_".join(active_features)
                    if active_features
                    else f"SPG_SSL_{policy.ssl_ssh_profile}"
                )

                group_name = re.sub(
                    r"[^a-zA-Z0-9_-]",
                    "_",
                    group_name,
                )[:63]

                ir_policy.security_profile_group = (
                    group_name
                )
                if not any(
                    (group.source_context, group.name) == (policy.source_context, group_name)
                    for group
                    in self.ir.security_profile_groups
                ):
                    self.ir.security_profile_groups.append(
                        IRSecurityProfileGroup(
                            name=group_name,
                            source_context=policy.source_context,
                            antivirus=(
                                policy.av_profile
                            ),
                            vulnerability=(
                                policy.ips_sensor
                            ),
                            anti_spyware=None,
                            url_filtering=(
                                policy.webfilter_profile
                            ),
                            file_blocking=None,
                            wildfire=None,
                            ssl_decryption=(
                                policy.ssl_ssh_profile
                            ),
                            description=(
                                "Auto-generated profile "
                                "group for FortiGate UTM "
                                f"({', '.join(active_features)})"
                            ),
                            source_profile_references={
                                key: value
                                for key, value in {
                                    "antivirus": policy.av_profile,
                                    "ips": policy.ips_sensor,
                                    "webfilter": policy.webfilter_profile,
                                    "application": policy.application_list,
                                    "ssl_ssh": policy.ssl_ssh_profile,
                                }.items()
                                if value
                            },
                        )
                    )

                self.ir.audit_entries.append(
                    IRAuditEntry(
                        id=str(
                            policy.id
                        ),
                        category="Policy",
                        message=(
                            "FortiGate UTM profile references were correlated into "
                            f"Security Profile Group '{group_name}' for inventory. "
                            "Source profile definitions remain source-specific and "
                            "require target-specific semantic translation."
                        ),
                        confidence=(
                            MigrationConfidence.MANUAL
                        ),
                    )
                )

            self.ir.policies.append(
                ir_policy
            )

    # ------------------------------------------------------------------
    # IP pools
    # ------------------------------------------------------------------

    @staticmethod
    def _fortios_enabled(
        value: Optional[str],
    ) -> Optional[bool]:
        if value is None:
            return None

        return value == "enable"

    @staticmethod
    def _fortios_explicit_flag(
        value: Optional[str],
    ) -> Optional[bool]:
        """Normalize only explicit FortiOS enable/disable values."""
        if value == "enable":
            return True
        if value == "disable":
            return False
        return None

    @staticmethod
    def _effective_source_rule_enabled(rule) -> Optional[bool]:
        """Resolve explicit status and verified source-only family defaults."""
        if rule.status == "enable":
            return True
        if rule.status == "disable":
            return False
        if rule.status is None:
            return SOURCE_ONLY_DEFAULT_ENABLED.get(rule.family)
        return None

    @staticmethod
    def _source_rule_effective_action(rule) -> Optional[str]:
        """Resolve only verified FortiOS source-only action semantics."""
        explicit_action = rule.settings.get("action")
        if explicit_action is not None:
            allowed_actions = SOURCE_ONLY_ALLOWED_ACTIONS.get(rule.family)
            if (
                isinstance(explicit_action, str)
                and allowed_actions is not None
                and explicit_action in allowed_actions
            ):
                return explicit_action
            return None
        return SOURCE_ONLY_DEFAULT_ACTION.get(rule.family)

    @staticmethod
    def _source_rule_to_ir(
        rule,
        review_reason: str,
        additional_review_reasons: Optional[List[str]] = None,
    ) -> IRFortiGateSourceRule:
        source_attributes = dict(rule.settings)
        if rule.nested_configs:
            source_attributes["nested_configs"] = [
                node.model_dump() for node in rule.nested_configs
            ]
        review_reasons = list(dict.fromkeys([
            review_reason,
            *(additional_review_reasons or []),
        ]))
        return IRFortiGateSourceRule(
            family=rule.family,
            source_id=str(rule.id) if rule.id is not None else None,
            name=rule.name,
            source_order=rule.source_order,
            source_context=rule.source_context,
            enabled=FGToIRTransformer._effective_source_rule_enabled(rule),
            effective_action=FGToIRTransformer._source_rule_effective_action(rule),
            source_attributes=source_attributes,
            review_reasons=review_reasons,
        )

    @staticmethod
    def _local_in_semantic_review_reasons(rule) -> List[str]:
        if rule.family == "local-in-policy-ipv4":
            internet_service_field = "internet_service_src"
            label = "Internet Service"
            source_field = "srcaddr"
            negate_field = "srcaddr_negate"
        elif rule.family == "local-in-policy-ipv6":
            internet_service_field = "internet_service6_src"
            label = "IPv6 Internet Service"
            source_field = "srcaddr"
            negate_field = "srcaddr_negate"
        else:
            return []

        if rule.settings.get(internet_service_field) != "enable":
            return []

        reasons = []
        if rule.settings.get(source_field):
            reasons.append(
                f"FortiOS {label} source matching is enabled; configured "
                f"{source_field} values are preserved as source evidence but "
                "are not effective ordinary source match criteria."
            )
        if negate_field in rule.settings:
            reasons.append(
                f"FortiOS {label} source matching leaves configured "
                f"{negate_field} inactive with the ordinary source address selector."
            )
        return reasons

    def _transform_source_only_rule_families(self) -> None:
        for rule in self.fg.security_policies:
            self.ir.security_policies.append(self._source_rule_to_ir(
                rule, "FortiGate policy-based NGFW security-policy semantics require manual migration"
            ))
        for rule in self.fg.policy_routes:
            self.ir.policy_routes.append(self._source_rule_to_ir(
                rule, "FortiGate policy routing is not a static route"
            ))
        for rule in self.fg.local_in_policies:
            self.ir.local_in_policies.append(self._source_rule_to_ir(
                rule,
                "FortiGate local-in policy protects control-plane traffic",
                self._local_in_semantic_review_reasons(rule),
            ))
        for rule in self.fg.proxy_policies:
            self.ir.proxy_policies.append(self._source_rule_to_ir(
                rule, "FortiGate explicit proxy policy is not transit firewall policy"
            ))
        for rule in self.fg.shaping_policies:
            self.ir.shaping_policies.append(self._source_rule_to_ir(
                rule, "FortiGate shaping match semantics are source-specific"
            ))
        for rule in self.fg.dhcp6_servers:
            self.ir.dhcp6_servers.append(self._source_rule_to_ir(
                rule, "DHCPv6 is retained separately from IPv4 DHCP"
            ))
        for rule in self.fg.source_only_rules:
            self.ir.source_only_rules.append(self._source_rule_to_ir(
                rule, f"FortiGate {rule.family} semantics are source-only"
            ))
        for rule in self.fg.custom_internet_services:
            self.ir.custom_internet_services.append(self._source_rule_to_ir(
                rule, "Custom Internet Service definitions require target-specific translation"
            ))
        for rule in self.fg.custom_internet_service_groups:
            self.ir.custom_internet_service_groups.append(self._source_rule_to_ir(
                rule, "Custom Internet Service group semantics require target-specific translation"
            ))

        for rule in self.fg.central_snat_rules:
            attributes = rule.model_dump(exclude={"source_context", "id"})
            unknown = bool(rule.extra_settings)
            self.ir.central_snat_rules.append(
                IRFortiGateSourceRule(
                    family="central-snat-map",
                    source_id=str(rule.id),
                    source_order=rule.id,
                    source_context=rule.source_context,
                    enabled=rule.status != "disable",
                    source_attributes=attributes,
                    migration_status="PARTIALLY_NORMALIZED",
                    requires_manual_review=True,
                    review_reasons=[
                        "Central SNAT requires target-specific ordered NAT translation"
                        + ("; unknown settings retained" if unknown else "")
                    ],
                )
            )

    def _transform_ip_pools(
        self,
    ) -> None:
        for pool in self.fg.ip_pools:
            review_reasons = []
            if pool.exclude_ip:
                review_reasons.append("IP pool exclusions require exact target-specific handling")
            if pool.permit_any_host == "enable":
                review_reasons.append("permit-any-host enables full-cone behavior")
            if pool.type == "fixed-port-range":
                review_reasons.append("fixed-port-range pool semantics")
            if pool.type == "port-block-allocation":
                review_reasons.append("port-block-allocation pool semantics")
            cgn_values = (
                pool.cgn_block_size,
                pool.cgn_client_startip,
                pool.cgn_client_endip,
                pool.cgn_client_ipv6shift,
                pool.cgn_fixedalloc,
                pool.cgn_overload,
                pool.cgn_port_start,
                pool.cgn_port_end,
                pool.cgn_spa,
            )
            if any(value is not None for value in cgn_values):
                review_reasons.append("carrier-grade NAT fields are configured")
            if pool.nat64 == "enable":
                review_reasons.append("NAT64 pool semantics")

            self.ir.ip_pools.append(
                IRIPPool(
                    name=pool.name,
                    source_context=pool.source_context,
                    address_family="ipv4",
                    pool_type=pool.type,
                    start_ip=pool.startip,
                    end_ip=pool.endip,
                    source_start_ip=(
                        pool.source_startip
                    ),
                    source_end_ip=(
                        pool.source_endip
                    ),
                    source_prefix6=(
                        pool.source_prefix6
                    ),
                    start_port=pool.startport,
                    end_port=pool.endport,
                    associated_interface=(
                        pool.associated_interface
                    ),
                    arp_reply=(
                        self._fortios_enabled(
                            pool.arp_reply
                        )
                    ),
                    arp_interface=pool.arp_intf,
                    permit_any_host=(
                        self._fortios_enabled(
                            pool.permit_any_host
                        )
                    ),
                    excluded_ips=list(
                        pool.exclude_ip
                    ),
                    block_size=pool.block_size,
                    blocks_per_user=(
                        pool.num_blocks_per_user
                    ),
                    pba_timeout=pool.pba_timeout,
                    pba_interim_log=(
                        pool.pba_interim_log
                    ),
                    ports_per_user=(
                        pool.port_per_user
                    ),
                    privileged_port_use_pba=(
                        self._fortios_enabled(
                            pool.privileged_port_use_pba
                        )
                    ),
                    nat64=(
                        self._fortios_enabled(
                            pool.nat64
                        )
                    ),
                    add_nat64_route=(
                        self._fortios_enabled(
                            pool.add_nat64_route
                        )
                    ),
                    client_prefix_length=(
                        pool.client_prefix_length
                    ),
                    include_subnet_broadcast=(
                        self._fortios_enabled(
                            pool.subnet_broadcast_in_ippool
                        )
                    ),
                    tcp_session_quota=(
                        pool.tcp_session_quota
                    ),
                    udp_session_quota=(
                        pool.udp_session_quota
                    ),
                    icmp_session_quota=(
                        pool.icmp_session_quota
                    ),
                    cgn_block_size=pool.cgn_block_size,
                    cgn_client_start_ip=pool.cgn_client_startip,
                    cgn_client_end_ip=pool.cgn_client_endip,
                    cgn_client_ipv6_shift=pool.cgn_client_ipv6shift,
                    cgn_fixed_allocation=self._fortios_explicit_flag(pool.cgn_fixedalloc),
                    cgn_overload=self._fortios_explicit_flag(pool.cgn_overload),
                    cgn_port_start=pool.cgn_port_start,
                    cgn_port_end=pool.cgn_port_end,
                    cgn_spa=self._fortios_explicit_flag(pool.cgn_spa),
                    utilization_alarm_clear=pool.utilization_alarm_clear,
                    utilization_alarm_raise=pool.utilization_alarm_raise,
                    migration_status=(
                        "PARTIALLY_NORMALIZED" if review_reasons else "NORMALIZED"
                    ),
                    requires_manual_review=bool(review_reasons),
                    audit_note="; ".join(review_reasons) or None,
                    source_attributes=dict(pool.extra_settings),
                    description=pool.comments,
                )
            )

        for pool in self.fg.ip_pools6:
            self.ir.ip_pools.append(
                IRIPPool(
                    name=pool.name,
                    source_context=pool.source_context,
                    address_family="ipv6",
                    start_ip=pool.startip,
                    end_ip=pool.endip,
                    nat46=self._fortios_explicit_flag(pool.nat46),
                    add_nat46_route=self._fortios_explicit_flag(pool.add_nat46_route),
                    migration_status="EXTRACT_ONLY",
                    requires_manual_review=True,
                    audit_note="IPv6 IP pools are retained as extraction-only source inventory",
                    source_attributes=dict(pool.extra_settings),
                    description=pool.comments,
                )
            )

    # ------------------------------------------------------------------
    # Virtual IPs
    # ------------------------------------------------------------------

    def _transform_virtual_ips(
        self,
    ) -> None:
        monitor_keys = {
            (rule.source_context, rule.name)
            for rule in self.fg.source_only_rules
            if rule.family == "load-balance-monitor" and rule.name
        }
        def transform_real_server(server) -> IRVirtualIPRealServer:
            review_reasons = []
            if server.type == "address":
                review_reasons.append("address-object real-server backend")
            if server.healthcheck:
                review_reasons.append("real-server healthcheck")
            if server.monitor:
                review_reasons.append("real-server monitor")
            if server.client_ip:
                review_reasons.append("real-server client-IP restriction")
            if server.http_host or server.translate_host or server.max_connections is not None:
                review_reasons.append("advanced real-server HTTP/connection semantics")

            return IRVirtualIPRealServer(
                id=server.id,
                address_type=server.type,
                ip_address=server.ip,
                address_reference=(
                    server.address if server.type == "address" else None
                ),
                port=server.port,
                status=server.status,
                weight=server.weight,
                holddown_interval=server.holddown_interval,
                healthcheck=server.healthcheck,
                http_host=server.http_host,
                translate_host=server.translate_host,
                max_connections=server.max_connections,
                monitors=list(server.monitor),
                client_ip=server.client_ip,
                migration_status=(
                    "PARTIALLY_NORMALIZED" if review_reasons else "NORMALIZED"
                ),
                requires_manual_review=bool(review_reasons),
                audit_note="; ".join(review_reasons) or None,
                source_attributes=dict(server.extra_settings),
            )

        for vip in self.fg.vips:
            real_servers = [transform_real_server(server) for server in vip.realservers]
            review_reasons = []
            if vip.type != "static-nat":
                review_reasons.append(f"advanced VIP type '{vip.type}'")
            if vip.nat46 == "enable":
                review_reasons.append("NAT46 VIP semantics")
            if vip.portmapping_type == "m-to-n":
                review_reasons.append("m-to-n port mapping")
            if vip.nat_source_vip == "enable":
                review_reasons.append("nat-source-vip semantics")
            if vip.src_filter:
                review_reasons.append("VIP source filters")
            if vip.srcintf_filter:
                review_reasons.append("VIP source-interface filters")
            if vip.service:
                review_reasons.append("VIP service restrictions")
            if vip.ipv6_mappedip or vip.ipv6_mappedport:
                review_reasons.append("IPv6 mapped destination fields")
            if vip.nat44 not in (None, "enable"):
                review_reasons.append("nonstandard NAT44 setting")
            if vip.realservers or vip.ldb_method or vip.server_type or vip.persistence or vip.monitor:
                review_reasons.append("VIP load-balancing semantics")
            unresolved_monitors = [
                name for name in vip.monitor
                if (vip.source_context, name) not in monitor_keys
            ]
            if unresolved_monitors:
                review_reasons.append(
                    "unresolved VIP monitor reference(s): " + ", ".join(unresolved_monitors)
                )
            if any(server.requires_manual_review for server in real_servers):
                review_reasons.append("advanced real-server semantics")

            self.ir.virtual_ips.append(
                IRVirtualIP(
                    name=vip.name,
                    source_context=vip.source_context,
                    address_family="ipv4",
                    source_id=vip.id,
                    source_uuid=vip.uuid,
                    vip_type=vip.type,
                    enabled=(
                        vip.status != "disable"
                    ),
                    external_ip=vip.extip,
                    external_addresses=list(
                        vip.extaddr
                    ),
                    external_interface=(
                        vip.extintf
                    ),
                    mapped_ips=list(
                        vip.mappedip
                    ),
                    mapped_address=(
                        vip.mapped_addr
                    ),
                    port_forward=(
                        vip.portforward
                        == "enable"
                    ),
                    protocol=vip.protocol,
                    external_port=vip.extport,
                    mapped_port=vip.mappedport,
                    port_mapping_type=(
                        vip.portmapping_type
                    ),
                    arp_reply=(
                        self._fortios_enabled(
                            vip.arp_reply
                        )
                    ),
                    gratuitous_arp_interval=(
                        vip.gratuitous_arp_interval
                    ),
                    nat_source_vip=(
                        self._fortios_enabled(
                            vip.nat_source_vip
                        )
                    ),
                    nat44=self._fortios_explicit_flag(vip.nat44),
                    nat46=self._fortios_explicit_flag(vip.nat46),
                    add_nat46_route=self._fortios_explicit_flag(vip.add_nat46_route),
                    ipv6_mapped_ip=vip.ipv6_mappedip,
                    ipv6_mapped_port=vip.ipv6_mappedport,
                    source_filters=list(
                        vip.src_filter
                    ),
                    source_interface_filters=list(
                        vip.srcintf_filter
                    ),
                    services=list(
                        vip.service
                    ),
                    load_balance_method=(
                        vip.ldb_method
                    ),
                    server_type=(
                        vip.server_type
                    ),
                    persistence=(
                        vip.persistence
                    ),
                    http_redirect=(
                        self._fortios_enabled(
                            vip.http_redirect
                        )
                    ),
                    monitors=list(
                        vip.monitor
                    ),
                    max_embryonic_connections=(
                        vip.max_embryonic_connections
                    ),
                    real_servers=real_servers,
                    color=vip.color,
                    description=vip.comment,
                    extra_settings=dict(
                        vip.extra_settings
                    ),
                    migration_status=(
                        "PARTIALLY_NORMALIZED" if review_reasons else "NORMALIZED"
                    ),
                    requires_manual_review=bool(review_reasons),
                    audit_note="; ".join(review_reasons) or None,
                )
            )

        for vip in self.fg.vips6:
            self.ir.virtual_ips.append(
                IRVirtualIP(
                    name=vip.name,
                    address_family="ipv6",
                    source_id=vip.id,
                    source_uuid=vip.uuid,
                    vip_type=vip.type,
                    enabled=vip.status != "disable",
                    external_ip=vip.extip,
                    mapped_ips=list(vip.mappedip),
                    port_forward=vip.portforward == "enable",
                    protocol=vip.protocol,
                    external_port=vip.extport,
                    mapped_port=vip.mappedport,
                    nat_source_vip=self._fortios_explicit_flag(vip.nat_source_vip),
                    nat64=self._fortios_explicit_flag(vip.nat64),
                    nat66=self._fortios_explicit_flag(vip.nat66),
                    add_nat64_route=self._fortios_explicit_flag(vip.add_nat64_route),
                    ndp_reply=self._fortios_explicit_flag(vip.ndp_reply),
                    ipv4_mapped_ip=vip.ipv4_mappedip,
                    ipv4_mapped_port=vip.ipv4_mappedport,
                    embedded_ipv4_address=vip.embedded_ipv4_address,
                    load_balance_method=vip.ldb_method,
                    server_type=vip.server_type,
                    persistence=vip.persistence,
                    monitors=list(vip.monitor),
                    source_filters=list(vip.src_filter),
                    real_servers=[transform_real_server(server) for server in vip.realservers],
                    color=vip.color,
                    description=vip.comment,
                    extra_settings=dict(vip.extra_settings),
                    migration_status="EXTRACT_ONLY",
                    requires_manual_review=True,
                    audit_note="IPv6 VIPs are retained as extraction-only source inventory",
                )
            )

    def _transform_vip_groups(self) -> None:
        for group in self.fg.vip_groups:
            self.ir.virtual_ip_groups.append(
                IRVirtualIPGroup(
                    name=group.name,
                    source_context=group.source_context,
                    source_uuid=group.uuid,
                    interface=group.interface,
                    members=list(group.member),
                    source_color=group.color,
                    description=group.comments or group.comment,
                    source_attributes=dict(group.extra_settings),
                )
            )

        for group in self.fg.vip_groups6:
            self.ir.virtual_ip_groups.append(
                IRVirtualIPGroup(
                    name=group.name,
                    source_context=group.source_context,
                    address_family="ipv6",
                    source_uuid=group.uuid,
                    members=list(group.member),
                    source_color=group.color,
                    description=group.comments,
                    migration_status="EXTRACT_ONLY",
                    requires_manual_review=True,
                    audit_note="IPv6 VIP groups are retained as extraction-only source inventory",
                    source_attributes=dict(group.extra_settings),
                )
            )

    # ------------------------------------------------------------------
    # NAT
    # ------------------------------------------------------------------

    def _transform_nat(
        self,
    ) -> None:
        """
        Correlate policy match semantics with referenced NAT resources.
        """

        central_nat_contexts = {
            context.vdom for context in self.fg.execution_contexts
            if context.central_nat == "enable"
        }

        pools_by_name = {
            (pool.source_context, pool.name): pool
            for pool in self.ir.ip_pools
            if pool.address_family == "ipv4"
        }

        vips_by_name = {
            (vip.source_context, vip.name): vip
            for vip in self.fg.vips
        }

        ir_vips_by_name = {
            (vip.source_context, vip.name): vip
            for vip in self.ir.virtual_ips
            if vip.address_family == "ipv4"
        }

        vip_groups_by_name = {
            (group.source_context, group.name): group
            for group in self.fg.vip_groups
        }

        def add_reason(reasons: List[str], reason: str) -> None:
            if reason not in reasons:
                reasons.append(reason)

        def audit(
            policy_id: int,
            message: str,
            confidence=(
                MigrationConfidence.PARTIAL
            ),
        ):
            self.ir.audit_entries.append(
                IRAuditEntry(
                    id=(
                        f"nat-policy-{policy_id}"
                    ),
                    category="NAT",
                    message=message,
                    confidence=confidence,
                )
            )

        for policy_index, (
            policy,
            ir_policy,
        ) in enumerate(
            zip(
                self.fg.policies,
                self.ir.policies,
            ),
            1,
        ):
            if policy.source_context in central_nat_contexts:
                self.ir.audit_entries.append(
                    IRAuditEntry(
                        id=f"central-nat-policy-{policy.id}",
                        category="NAT",
                        message=(
                            f"Policy {policy.id} is in VDOM '{policy.source_context}' where central NAT is enabled; "
                            "no policy-derived NAT rule was emitted. central-snat-map remains authoritative source data."
                        ),
                        confidence=MigrationConfidence.MANUAL,
                    )
                )
                continue
            nat_review_reasons: List[str] = []
            vip_matches = []
            ordinary_destinations = []

            for destination in policy.dstaddr:
                destination_key = (policy.source_context, destination)
                if destination_key in vips_by_name:
                    vip_matches.append(
                        (
                            vips_by_name[destination_key],
                            None,
                        )
                    )
                    continue

                vip_group = (
                    vip_groups_by_name.get(
                        destination_key
                    )
                )

                if vip_group is None:
                    ordinary_destinations.append(
                        normalize_to_ir(
                            "fortigate",
                            destination,
                        )
                    )
                    continue

                for member in vip_group.member:
                    vip = vips_by_name.get(
                        (policy.source_context, member)
                    )

                    if vip is None:
                        audit(
                            policy.id,
                            (
                                f"Policy {policy.id} VIP "
                                f"group '{vip_group.name}' "
                                "references missing VIP "
                                f"'{member}'."
                            ),
                            MigrationConfidence.MANUAL,
                        )
                        continue

                    vip_matches.append(
                        (
                            vip,
                            vip_group.name,
                        )
                    )

            snat_enabled = (
                policy.nat == "enable"
            )

            source_mode = None
            pool_references = []
            pool_type = None
            translated_sources = []
            source_pool_excluded_ips = []
            source_pool_permit_any_host = None
            source_pool_original_start_ip = []
            source_pool_original_end_ip = []
            source_requires_review = (
                not ir_policy.from_zone
                or not ir_policy.to_zone
            )

            if source_requires_review:
                add_reason(nat_review_reasons, "unresolved canonical NAT zones")

            if ir_policy.requires_manual_review:
                source_requires_review = True
                add_reason(
                    nat_review_reasons,
                    "source policy semantics require manual review",
                )

            policy_nat_controls = (
                ("fixedport", policy.fixedport),
                ("nat46", policy.nat46),
                ("nat64", policy.nat64),
                ("natinbound", policy.natinbound),
                ("natoutbound", policy.natoutbound),
                ("natip", policy.natip),
                ("match-vip", policy.match_vip),
                ("match-vip-only", policy.match_vip_only),
            )
            for control, value in policy_nat_controls:
                if value is not None and value != "disable":
                    source_requires_review = True
                    add_reason(
                        nat_review_reasons,
                        f"policy NAT control '{control}' is configured as '{value}'",
                    )

            if source_requires_review and (
                snat_enabled or vip_matches
            ):
                audit(
                    policy.id,
                    (
                        f"Policy {policy.id} NAT match has unresolved canonical zones "
                        "or source policy semantics requiring manual review; "
                        "source evidence was preserved."
                    ),
                    MigrationConfidence.MANUAL,
                )

            if (
                snat_enabled
                and policy.ippool
                == "enable"
            ):
                source_mode = (
                    NATTranslationMode.POOL
                )

                pool_references = list(
                    policy.poolname
                )

                resolved_pool_types = []

                if not pool_references:
                    source_requires_review = True
                    add_reason(nat_review_reasons, "IP pool is enabled without a pool reference")

                    audit(
                        policy.id,
                        (
                            f"Policy {policy.id} enables "
                            "an IP pool but has no pool "
                            "reference; interface NAT "
                            "was not substituted."
                        ),
                        MigrationConfidence.MANUAL,
                    )

                for pool_name in pool_references:
                    pool = pools_by_name.get(
                        (policy.source_context, pool_name)
                    )

                    if pool is None:
                        source_requires_review = True
                        add_reason(
                            nat_review_reasons,
                            f"referenced IP pool '{pool_name}' is missing",
                        )

                        audit(
                            policy.id,
                            (
                                f"Policy {policy.id} "
                                "references missing IP "
                                f"pool '{pool_name}'; "
                                "the unresolved name "
                                "was preserved."
                            ),
                            MigrationConfidence.MANUAL,
                        )
                        continue

                    resolved_pool_types.append(
                        pool.pool_type
                        or "overload"
                    )

                    if pool.start_ip:
                        source_pool_original_start_ip.append(pool.start_ip)
                    if pool.end_ip:
                        source_pool_original_end_ip.append(pool.end_ip)
                    for excluded_ip in pool.excluded_ips:
                        if excluded_ip not in source_pool_excluded_ips:
                            source_pool_excluded_ips.append(excluded_ip)
                    source_pool_permit_any_host = (
                        bool(source_pool_permit_any_host)
                        or bool(pool.permit_any_host)
                    )

                    if pool.requires_manual_review:
                        source_requires_review = True
                        add_reason(
                            nat_review_reasons,
                            pool.audit_note or f"IP pool '{pool.name}' requires manual review",
                        )

                    if pool.pool_type == "one-to-one" and (
                        pool.source_start_ip or pool.source_end_ip
                    ):
                        source_requires_review = True
                        add_reason(
                            nat_review_reasons,
                            f"one-to-one pool '{pool.name}' has explicit source-range semantics",
                        )

                    if (
                        pool.start_ip
                        and pool.end_ip
                    ):
                        if (
                            pool.start_ip
                            == pool.end_ip
                        ):
                            translated_sources.append(
                                pool.start_ip
                            )
                        else:
                            translated_sources.append(
                                f"{pool.start_ip}-"
                                f"{pool.end_ip}"
                            )

                    elif pool.start_ip:
                        translated_sources.append(
                            pool.start_ip
                        )

                    else:
                        source_requires_review = True
                        add_reason(
                            nat_review_reasons,
                            f"IP pool '{pool.name}' has no translated address range",
                        )

                        audit(
                            policy.id,
                            (
                                f"Policy {policy.id} "
                                f"IP pool '{pool.name}' "
                                "has no translated "
                                "address range."
                            ),
                            MigrationConfidence.MANUAL,
                        )

                    if (
                        pool.pool_type
                        not in (
                            None,
                            "overload",
                            "one-to-one",
                        )
                        or pool.nat64
                    ):
                        source_requires_review = True
                        add_reason(
                            nat_review_reasons,
                            f"advanced IP pool '{pool.name}' type '{pool.pool_type}'",
                        )

                        audit(
                            policy.id,
                            (
                                f"Policy {policy.id} "
                                "uses advanced IP pool "
                                f"'{pool.name}' type "
                                f"'{pool.pool_type}' that "
                                "requires target-specific "
                                "review."
                            ),
                        )

                if resolved_pool_types:
                    if (
                        len(
                            set(
                                resolved_pool_types
                            )
                        )
                        == 1
                    ):
                        pool_type = (
                            resolved_pool_types[0]
                        )
                    else:
                        pool_type = "mixed"

                    if (
                        pool_type == "one-to-one"
                        and (
                            len(
                                translated_sources
                            )
                            != 1
                            or "-"
                            in translated_sources[0]
                        )
                    ):
                        source_requires_review = True
                        add_reason(
                            nat_review_reasons,
                            "one-to-one pool cannot be represented as one proven static source mapping",
                        )

                        audit(
                            policy.id,
                            (
                                f"Policy {policy.id} "
                                "one-to-one pool "
                                "correlation was preserved "
                                "but cannot be rendered as "
                                "one static source "
                                "translation without review."
                            ),
                        )

            elif snat_enabled:
                source_mode = (
                    NATTranslationMode.INTERFACE_ADDRESS
                )

                (
                    translated_source,
                    requires_review,
                    resolution_reason,
                ) = (
                    self._resolve_interface_snat_address(
                        policy.dstintf,
                        policy.source_context,
                    )
                )

                if translated_source:
                    translated_sources.append(
                        translated_source
                    )

                if requires_review:
                    source_requires_review = True
                    add_reason(
                        nat_review_reasons,
                        f"interface-address SNAT is unresolved: {resolution_reason}",
                    )

                    audit(
                        policy.id,
                        (
                            f"Policy {policy.id} "
                            "interface-address SNAT "
                            "could not be resolved: "
                            f"{resolution_reason}"
                        ),
                        MigrationConfidence.MANUAL,
                    )

            if (
                policy.internet_service
                == "enable"
            ):
                source_requires_review = True
                add_reason(
                    nat_review_reasons,
                    "Internet Service match semantics require target-specific review",
                )

                audit(
                    policy.id,
                    (
                        f"Policy {policy.id} NAT "
                        "match uses FortiGate "
                        "Internet Service references; "
                        "they were preserved but "
                        "require target-specific review."
                    ),
                )

            if (
                snat_enabled
                and (
                    not policy.srcaddr
                    or not policy.dstaddr
                    or not policy.service
                )
            ):
                source_requires_review = True
                add_reason(nat_review_reasons, "ordinary NAT match fields are incomplete")

                audit(
                    policy.id,
                    (
                        f"Policy {policy.id} has "
                        "incomplete ordinary NAT match "
                        "fields; missing values were "
                        "not replaced with 'any'."
                    ),
                    MigrationConfidence.MANUAL,
                )

            if (
                vip_matches
                and (
                    not policy.srcaddr
                    or not policy.service
                )
            ):
                source_requires_review = True
                add_reason(nat_review_reasons, "DNAT match fields are incomplete")

                audit(
                    policy.id,
                    (
                        f"Policy {policy.id} has "
                        "incomplete DNAT match fields; "
                        "missing values were not "
                        "replaced with 'any'."
                    ),
                    MigrationConfidence.MANUAL,
                )

            common = dict(
                source_context=policy.source_context,
                source_policy_reference=str(
                    policy.id
                ),
                source_policy_uuid=policy.uuid,
                source_policy_name=policy.name,
                sequence=policy_index,
                enabled=(
                    policy.status
                    != "disable"
                ),
                source_from_interfaces=list(
                    policy.srcintf
                ),
                source_to_interfaces=list(
                    policy.dstintf
                ),
                from_zone=list(
                    ir_policy.from_zone
                ),
                source=list(
                    ir_policy.source
                ),
                services=list(
                    ir_policy.service
                ),
                internet_services=list(
                    policy.internet_service_name
                ),
                source_translation_mode=(
                    source_mode
                ),
                source_pool_references=(
                    pool_references
                ),
                source_pool_type=pool_type,
                source_pool_excluded_ips=source_pool_excluded_ips,
                source_pool_permit_any_host=source_pool_permit_any_host,
                source_pool_original_start_ip=source_pool_original_start_ip,
                source_pool_original_end_ip=source_pool_original_end_ip,
                translated_sources=(
                    translated_sources
                ),
                source_policy_fixed_port=policy.fixedport,
                source_policy_nat46=policy.nat46,
                source_policy_nat64=policy.nat64,
                source_policy_nat_inbound=policy.natinbound,
                source_policy_nat_outbound=policy.natoutbound,
                source_policy_nat_ip=policy.natip,
                source_policy_match_vip=policy.match_vip,
                source_policy_match_vip_only=policy.match_vip_only,
                migration_status=(
                    "PARTIALLY_NORMALIZED" if source_requires_review else "NORMALIZED"
                ),
                review_reasons=list(nat_review_reasons),
                requires_manual_review=(
                    source_requires_review
                ),
                description=policy.comments,
            )

            for (
                vip,
                vip_group_name,
            ) in vip_matches:
                ir_vip = ir_vips_by_name[(policy.source_context, vip.name)]
                external_destinations = (
                    [vip.extip]
                    if vip.extip
                    else list(
                        vip.extaddr
                    )
                )

                translated_destinations = list(
                    vip.mappedip
                )

                if (
                    not translated_destinations
                    and vip.mapped_addr
                ):
                    translated_destinations = [
                        vip.mapped_addr
                    ]

                vip_requires_review = (
                    source_requires_review
                    or ir_vip.requires_manual_review
                )
                vip_review_reasons = list(nat_review_reasons)
                if ir_vip.requires_manual_review:
                    add_reason(
                        vip_review_reasons,
                        ir_vip.audit_note or f"VIP '{vip.name}' requires manual review",
                    )

                vip_enabled = vip.status != "disable"
                if not vip_enabled:
                    vip_requires_review = True
                    add_reason(vip_review_reasons, f"VIP '{vip.name}' is disabled")

                if vip.src_filter:
                    vip_requires_review = True
                    add_reason(vip_review_reasons, f"VIP '{vip.name}' has source filters")
                if vip.srcintf_filter:
                    vip_requires_review = True
                    add_reason(vip_review_reasons, f"VIP '{vip.name}' has interface filters")
                if vip.service:
                    vip_requires_review = True
                    add_reason(vip_review_reasons, f"VIP '{vip.name}' has service restrictions")

                if vip_group_name:
                    group = vip_groups_by_name[(policy.source_context, vip_group_name)]
                    if (
                        group.interface
                        and group.interface != "any"
                        and vip.extintf
                        and vip.extintf != "any"
                        and group.interface != vip.extintf
                    ):
                        vip_requires_review = True
                        add_reason(
                            vip_review_reasons,
                            f"VIP group interface '{group.interface}' conflicts with member VIP interface '{vip.extintf}'",
                        )

                if (
                    not external_destinations
                    or not translated_destinations
                ):
                    vip_requires_review = True
                    add_reason(vip_review_reasons, f"VIP '{vip.name}' has incomplete translation addresses")

                    audit(
                        policy.id,
                        (
                            f"Policy {policy.id} "
                            f"references VIP '{vip.name}' "
                            "without complete external "
                            "and mapped addresses."
                        ),
                        MigrationConfidence.MANUAL,
                    )

                if (
                    len(
                        translated_destinations
                    )
                    > 1
                ):
                    vip_requires_review = True
                    add_reason(vip_review_reasons, f"VIP '{vip.name}' has multiple mapped destinations")

                    audit(
                        policy.id,
                        (
                            f"Policy {policy.id} VIP "
                            f"'{vip.name}' has multiple "
                            "mapped destinations; all "
                            "were preserved."
                        ),
                    )

                translated_port = None
                original_port = None

                if (
                    vip.portforward == "enable"
                    and vip.extport
                ):
                    original_port = (
                        self._clean_port_range(
                            vip.extport
                        )
                    )

                    translated_port = (
                        self._clean_port_range(
                            vip.mappedport
                            or vip.extport
                        )
                    )

                    protocol = (
                        vip.protocol
                        or "tcp"
                    ).lower()

                    if protocol in (
                        "tcp",
                        "udp",
                    ):
                        service_name = (
                            "svc_nat_"
                            f"{protocol}_"
                            f"{original_port}"
                        )

                        if not any(
                            (service.source_context, service.name)
                            == (policy.source_context, service_name)
                            for service
                            in self.ir.services
                        ):
                            self.ir.services.append(
                                IRService(
                                    name=service_name,
                                    source_context=policy.source_context,
                                    ports=[
                                        IRServicePort(
                                            protocol=(
                                                ServiceProtocol.UDP
                                                if protocol
                                                == "udp"
                                                else ServiceProtocol.TCP
                                            ),
                                            port=(
                                                original_port
                                            ),
                                        )
                                    ],
                                    description=(
                                        "Generated from VIP "
                                        f"{vip.name} "
                                        "pre-NAT port"
                                    ),
                                )
                            )

                    else:
                        vip_requires_review = True
                        add_reason(
                            vip_review_reasons,
                            f"VIP '{vip.name}' uses unsupported protocol '{protocol}'",
                        )

                        audit(
                            policy.id,
                            (
                                f"Policy {policy.id} VIP "
                                f"'{vip.name}' uses "
                                "unsupported port-forward "
                                f"protocol '{protocol}'."
                            ),
                            MigrationConfidence.MANUAL,
                        )

                if vip.extintf == "any":
                    nat_to_zone = [
                        IR_KEYWORD_ANY
                    ]

                elif (
                    (policy.source_context, vip.extintf)
                    in self._intf_to_zone
                ):
                    nat_to_zone = [
                        self._intf_to_zone[
                            (policy.source_context, vip.extintf)
                        ]
                    ]

                else:
                    nat_to_zone = []
                    vip_requires_review = True
                    add_reason(
                        vip_review_reasons,
                        f"VIP '{vip.name}' external interface '{vip.extintf}' is unresolved",
                    )

                    audit(
                        policy.id,
                        (
                            f"Policy {policy.id} VIP "
                            f"'{vip.name}' references "
                            "unresolved external "
                            f"interface '{vip.extintf}'."
                        ),
                        MigrationConfidence.MANUAL,
                    )

                nat_type = (
                    NATType.TWICE
                    if snat_enabled
                    else NATType.DESTINATION
                )

                prefix = (
                    "TWICE"
                    if nat_type
                    == NATType.TWICE
                    else "DNAT"
                )

                self.ir.nat_rules.append(
                    IRNATRule(
                        name=(
                            f"{prefix}-P"
                            f"{policy.id}-"
                            f"{vip.name}"
                        ),
                        type=nat_type,
                        enabled=(common["enabled"] and vip_enabled),
                        to_zone=nat_to_zone,
                        destination=(
                            external_destinations
                        ),
                        translated_destinations=(
                            translated_destinations
                        ),
                        destination_protocol=(
                            vip.protocol
                        ),
                        original_destination_port=(
                            original_port
                        ),
                        translated_port=(
                            translated_port
                        ),
                        source_vip_reference=(
                            vip.name
                        ),
                        source_vip_group_reference=(
                            vip_group_name
                        ),
                        source_vip_type=vip.type,
                        source_vip_enabled=vip_enabled,
                        source_vip_nat_source_vip=(vip.nat_source_vip == "enable"),
                        source_vip_filters=list(vip.src_filter),
                        source_vip_interface_filters=list(vip.srcintf_filter),
                        source_vip_services=list(vip.service),
                        source_vip_port_mapping_type=vip.portmapping_type,
                        migration_status=(
                            "PARTIALLY_NORMALIZED" if vip_requires_review else "NORMALIZED"
                        ),
                        review_reasons=vip_review_reasons,
                        requires_manual_review=(
                            vip_requires_review
                        ),
                        **{
                            key: value
                            for key, value
                            in common.items()
                            if key
                            not in {
                                "enabled",
                                "migration_status",
                                "review_reasons",
                                "requires_manual_review",
                            }
                        },
                    )
                )

            if (
                snat_enabled
                and (
                    not vip_matches
                    or ordinary_destinations
                )
            ):
                suffix = (
                    "-ordinary"
                    if vip_matches
                    else ""
                )

                self.ir.nat_rules.append(
                    IRNATRule(
                        name=(
                            f"SNAT-P"
                            f"{policy.id}"
                            f"{suffix}"
                        ),
                        type=NATType.SOURCE,
                        to_zone=list(
                            ir_policy.to_zone
                        ),
                        destination=(
                            ordinary_destinations
                            if vip_matches
                            else list(
                                ir_policy.destination
                            )
                        ),
                        **common,
                    )
                )

    def _resolve_interface_snat_address(
        self,
        destination_interfaces: List[str],
        source_context: str,
    ) -> Tuple[
        Optional[str],
        bool,
        Optional[str],
    ]:
        """
        Resolve a statically knowable FortiGate egress-interface
        primary IP.
        """

        if not destination_interfaces:
            return (
                None,
                True,
                (
                    "no destination interface was "
                    "configured, so the egress "
                    "interface cannot be selected."
                ),
            )

        if len(
            destination_interfaces
        ) > 1:
            return (
                None,
                True,
                (
                    "multiple possible outgoing "
                    "interfaces; the translation "
                    "address depends on the "
                    "routing/session path."
                ),
            )

        interface_name = (
            destination_interfaces[0]
        )

        if interface_name.lower() in (
            "any",
            IR_KEYWORD_ANY.lower(),
        ):
            return (
                None,
                True,
                (
                    "destination interface 'any' "
                    "does not identify an egress "
                    "interface."
                ),
            )

        if (source_context, interface_name) in self._sdwan_zone_names:
            return (
                None,
                True,
                (
                    "the interface-address "
                    "translation uses the "
                    "runtime-selected SD-WAN "
                    "member interface address."
                ),
            )

        interface = (
            self._interface_by_name.get(
                (source_context, interface_name)
            )
        )

        if interface is None:
            return (
                None,
                True,
                (
                    f"egress interface "
                    f"'{interface_name}' was not "
                    "found in the source "
                    "configuration."
                ),
            )

        mode = (
            interface.mode
            or "static"
        ).lower()

        if mode != "static":
            return (
                None,
                True,
                (
                    f"{mode} dynamic interface "
                    f"address for '{interface_name}' "
                    "cannot be resolved from static "
                    "configuration."
                ),
            )

        primary_ip = (
            interface.ip.split()[0]
            if interface.ip
            else None
        )

        try:
            parsed_ip = (
                ip_address(
                    primary_ip
                )
                if primary_ip
                else None
            )
        except ValueError:
            parsed_ip = None

        if (
            parsed_ip is None
            or parsed_ip.is_unspecified
        ):
            return (
                None,
                True,
                (
                    f"egress interface "
                    f"'{interface_name}' has no "
                    "usable static primary IP."
                ),
            )

        return (
            str(parsed_ip),
            False,
            None,
        )

    # ------------------------------------------------------------------
    # VPN
    # ------------------------------------------------------------------

    def _transform_vpn(
        self,
    ) -> None:
        phase1_names = {
            (phase1.source_context, phase1.name)
            for phase1 in self.fg.phase1_interfaces
        }
        user_group_names = {item.name for item in self.ir.user_groups}

        for phase1 in self.fg.phase1_interfaces:
            source_attributes = dict(phase1.extra_settings)
            source_flags = {
                "net_device": phase1.net_device,
                "mode_cfg": phase1.mode_cfg,
                "eap": phase1.eap,
            }
            for field_name, value in source_flags.items():
                if value is not None and value not in {"enable", "disable"}:
                    source_attributes[field_name] = value

            if phase1.remote_gw is not None:
                peer_address = phase1.remote_gw
            elif phase1.type == "dynamic":
                peer_address = "dynamic"
            else:
                peer_address = None

            if phase1.ike_version == "1":
                ike_version = "v1"
            elif phase1.ike_version == "2":
                ike_version = "v2"
            else:
                ike_version = None
                if phase1.ike_version is not None:
                    source_attributes["ike_version"] = phase1.ike_version

            self.ir.vpn_tunnels.append(
                IRVPNTunnel(
                    name=phase1.name,
                    source_context=phase1.source_context,
                    peer_address=peer_address,
                    local_interface=(
                        phase1.interface
                    ),
                    ike_version=ike_version,
                    has_psk=phase1.has_psk,
                    source_local_gateway=phase1.local_gw,
                    source_type=phase1.type,
                    source_mode=phase1.mode,
                    source_peer_type=phase1.peertype,
                    source_net_device=self._fortios_explicit_flag(
                        phase1.net_device
                    ),
                    source_proposals=list(phase1.proposal),
                    source_mode_config=self._fortios_explicit_flag(
                        phase1.mode_cfg
                    ),
                    source_eap=self._fortios_explicit_flag(phase1.eap),
                    source_eap_identity=phase1.eap_identity,
                    source_auth_user_group=phase1.authusrgrp,
                    unresolved_auth_user_groups=(
                        [phase1.authusrgrp]
                        if phase1.authusrgrp
                        and phase1.authusrgrp not in user_group_names
                        else []
                    ),
                    source_client_ip_start=phase1.ipv4_start_ip,
                    source_client_ip_end=phase1.ipv4_end_ip,
                    source_dns_mode=phase1.dns_mode,
                    source_split_include=list(
                        phase1.ipv4_split_include
                    ),
                    source_dpd_retry_interval=(
                        phase1.dpd_retryinterval
                    ),
                    migration_status="PARTIALLY_NORMALIZED",
                    requires_manual_review=True,
                    source_attributes=source_attributes,
                    description=phase1.comments,
                )
            )

            if phase1.authusrgrp and phase1.authusrgrp not in user_group_names:
                self._add_identity_audit(
                    f"identity:vpn:{phase1.name}:auth-user-group",
                    f"IPsec VPN Phase 1 '{phase1.name}' references unresolved "
                    f"authentication user group '{phase1.authusrgrp}'. The source "
                    "reference was preserved and requires manual review.",
                )

            if phase1.has_psk:
                audit_message = (
                    "IPsec VPN mapped. Pre-Shared Key (PSK) is "
                    "configured but intentionally redacted; retrieve the "
                    "usable PSK securely from the source environment and "
                    "set the equivalent target IKE gateway credential."
                )
            else:
                audit_message = (
                    "IPsec VPN Phase 1 source semantics were partially "
                    "normalized and require target-specific migration review."
                )

            self.ir.audit_entries.append(
                IRAuditEntry(
                    id=phase1.name,
                    category="VPN",
                    message=audit_message,
                    confidence=(
                        MigrationConfidence.PARTIAL
                    ),
                )
            )

        for phase2 in self.fg.phase2_interfaces:
            missing_phase1 = (
                phase2.source_context, phase2.phase1name
            ) not in phase1_names
            self.ir.vpn_phase2.append(
                IRVPNPhase2(
                    name=phase2.name,
                    source_context=phase2.source_context,
                    phase1_name=phase2.phase1name,
                    proposals=list(phase2.proposal),
                    source_address_type=phase2.src_addr_type,
                    destination_address_type=phase2.dst_addr_type,
                    source_names=list(phase2.src_name),
                    destination_names=list(phase2.dst_name),
                    source_subnet=phase2.src_subnet,
                    destination_subnet=phase2.dst_subnet,
                    auto_negotiate=self._fortios_enabled(
                        phase2.auto_negotiate
                    ),
                    dh_groups=list(phase2.dhgrp),
                    keepalive=self._fortios_enabled(
                        phase2.keepalive
                    ),
                    description=phase2.comments,
                    requires_manual_review=True,
                    source_attributes=dict(phase2.extra_settings),
                )
            )

            if missing_phase1:
                self.ir.audit_entries.append(
                    IRAuditEntry(
                        id=f"vpn-phase2:{phase2.name}:phase1",
                        category="VPN",
                        message=(
                            f"IPsec Phase 2 '{phase2.name}' references "
                            f"missing Phase 1 '{phase2.phase1name}'. The "
                            "source reference was preserved and requires "
                            "manual review."
                        ),
                        confidence=MigrationConfidence.MANUAL,
                    )
                )

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    def _transform_routes(
        self,
    ) -> None:
        for route in self.fg.static_routes:
            review_reasons = []
            parse_error = None
            dst_cidr = None
            src_cidr = None

            if route.dstaddr is not None:
                review_reasons.append(
                    "FortiGate destination object/group reference requires manual review."
                )
            else:
                default_destination = (
                    "::/0"
                    if route.address_family == "ipv6"
                    else "0.0.0.0 0.0.0.0"
                )
                dst_raw = route.dst if route.dst is not None else default_destination
                normalizer = (
                    normalize_ipv6_network
                    if route.address_family == "ipv6"
                    else normalize_ipv4_network
                )
                try:
                    dst_cidr = normalizer(dst_raw)
                except ValueError as exc:
                    parse_error = str(exc)
                    review_reasons.append(parse_error)
                    self.ir.audit_entries.append(
                        IRAuditEntry(
                            id=f"route:{route.id}:destination",
                            category="Route Network Normalization",
                            message=(
                                f"Route {route.id} destination {dst_raw!r} "
                                f"failed normalization: {exc}. No replacement "
                                "prefix was inferred."
                            ),
                            confidence=MigrationConfidence.MANUAL,
                        )
                    )

            if route.src is not None:
                try:
                    src_cidr = normalize_ipv4_network(route.src)
                except ValueError as exc:
                    src_parse_error = str(exc)
                    if parse_error is None:
                        parse_error = src_parse_error
                    review_reasons.append(src_parse_error)
                    self.ir.audit_entries.append(
                        IRAuditEntry(
                            id=f"route:{route.id}:source_prefix",
                            category="Route Network Normalization",
                            message=(
                                f"Route {route.id} source prefix {route.src!r} "
                                f"failed normalization: {exc}. No replacement "
                                "prefix was inferred."
                            ),
                            confidence=MigrationConfidence.MANUAL,
                        )
                    )
                    src_cidr = route.src
                else:
                    src_cidr = src_cidr

            if route.preferred_source is not None:
                review_reasons.append(
                    "Static route preferred-source requires target-specific validation."
                )

            source_attributes = {
                **dict(route.extra_settings),
            }
            if route.blackhole not in {"enable", "disable"}:
                source_attributes["blackhole"] = route.blackhole
            if route.status is not None and route.status not in {"enable", "disable"}:
                source_attributes["status"] = route.status

            if route.extra_settings:
                review_reasons.append("Unknown source route settings are retained.")

            requires_review = bool(review_reasons)

            if source_attributes:
                self.ir.audit_entries.append(
                    IRAuditEntry(
                        id=f"route:{route.id}:source-semantics",
                        category="Route Semantics",
                        message=(
                            f"Route {route.id} retains unmodeled or invalid "
                            "source settings and requires manual review: "
                            f"{', '.join(sorted(source_attributes))}."
                        ),
                        confidence=MigrationConfidence.MANUAL,
                    )
                )

            self.ir.routes.append(
                IRRoute(
                    name=(
                        f"route_{route.id}"
                    ),
                    source_context=route.source_context,
                    address_family=route.address_family,
                    destination=dst_cidr,
                    source_destination=(
                        route.dst
                        if route.dst is not None
                        else (
                            None
                            if route.dstaddr is not None
                            else default_destination
                        )
                    ),
                    source_destination_reference=route.dstaddr,
                    source_prefix=src_cidr,
                    source_preferred_source=route.preferred_source,
                    source_route_id=route.id,
                    interface=route.device,
                    next_hop=route.gateway,
                    administrative_distance=route.distance,
                    metric=None,
                    priority=route.priority,
                    weight=route.weight,
                    blackhole=route.blackhole == "enable",
                    enabled=(
                        {"enable": True, "disable": False}.get(route.status)
                    ),
                    source_explicit_fields=sorted(route.source_explicit_fields),
                    sdwan_zone=(
                        route.sdwan_zone[0]
                        if len(route.sdwan_zone) == 1
                        else None
                    ),
                    sdwan_zones=list(route.sdwan_zone),
                    dynamic_gateway=route.dynamic_gateway,
                    link_monitor_exempt=route.link_monitor_exempt,
                    bfd=route.bfd,
                    vrf=route.vrf,
                    route_tag=route.tag,
                    internet_service=route.internet_service,
                    internet_service_custom=route.internet_service_custom,
                    description=route.comment,
                    migration_status=(
                        "PARTIALLY_NORMALIZED"
                        if requires_review
                        else "NORMALIZED"
                    ),
                    review_reasons=review_reasons,
                    parse_error=parse_error,
                    requires_manual_review=requires_review,
                    source_attributes=source_attributes,
                )
            )


def extract_nat_and_security(
    policy_data: dict,
    vip_inventory: Dict[str, dict],
    service_inventory: Optional[
        Dict[
            str,
            "IRServiceObject",
        ]
    ] = None,
) -> Tuple[
    "IRSecurityRule",
    List["IRNatRule"],
    List["IRServiceObject"],
]:
    """
    Deprecated compatibility helper for the legacy
    fwmigrate.core.models NAT schema.

    Production FortiGate correlation is implemented by
    FGToIRTransformer._transform_nat and emits
    fwmigrate.ir.core.IRNATRule objects.
    """

    from fwmigrate.core.models import (
        IRSecurityRule,
        IRNatRule,
        IRNatType,
        IRServiceObject,
        ServiceProtocol,
    )

    if service_inventory is None:
        service_inventory = {}

    base_services = list(
        policy_data.get(
            "service",
            ["any"],
        )
    )

    if not base_services:
        base_services = [
            "any"
        ]

    ir_sec_rule = IRSecurityRule(
        name=policy_data.get(
            "name",
            "unnamed_policy",
        ),
        from_zones=list(
            policy_data.get(
                "srcintf",
                ["any"],
            )
        ),
        to_zones=list(
            policy_data.get(
                "dstintf",
                ["any"],
            )
        ),
        sources=list(
            policy_data.get(
                "srcaddr",
                ["any"],
            )
        ),
        destinations=list(
            policy_data.get(
                "dstaddr",
                ["any"],
            )
        ),
        services=base_services,
        action=policy_data.get(
            "action",
            "deny",
        ),
        description=policy_data.get(
            "comments"
        ),
    )

    ir_nat_rules: List[
        IRNatRule
    ] = []

    generated_services: List[
        IRServiceObject
    ] = []

    mapped_post_nat_zones: List[
        str
    ] = []

    mapped_vip_services: List[
        str
    ] = []

    # Policy-level source NAT.
    if (
        policy_data.get("nat")
        == "enable"
    ):
        snat_rule = IRNatRule(
            name=(
                f"SNAT_"
                f"{ir_sec_rule.name}"
            ),
            nat_type=(
                IRNatType.SNAT_DIPP
            ),
            from_zones=list(
                ir_sec_rule.from_zones
            ),
            to_zones=list(
                ir_sec_rule.to_zones
            ),
            sources=list(
                ir_sec_rule.sources
            ),
            destinations=list(
                ir_sec_rule.destinations
            ),
            service=(
                base_services[0]
                if base_services
                else "any"
            ),
            translated_sources=(
                policy_data.get(
                    "poolname",
                    ["interface-address"],
                )
            ),
            description=(
                "SNAT for policy "
                f"{ir_sec_rule.name}"
            ),
        )

        ir_nat_rules.append(
            snat_rule
        )

    # Destination NAT / VIP correlation.
    for destination in (
        ir_sec_rule.destinations
    ):
        if destination not in vip_inventory:
            continue

        vip = vip_inventory[
            destination
        ]

        is_portforward = (
            vip.get(
                "portforward"
            )
            == "enable"
            or "extport" in vip
        )

        service_name = "any"

        if (
            is_portforward
            and vip.get("extport")
        ):
            raw_proto = (
                vip.get(
                    "protocol",
                    "tcp",
                ).lower()
            )

            protocol = (
                ServiceProtocol.UDP
                if raw_proto == "udp"
                else ServiceProtocol.TCP
            )

            ext_port = str(
                vip["extport"]
            ).strip()

            service_name = (
                f"svc_{protocol.value}_"
                f"{ext_port.replace('-', '_').replace(':', '_')}"
            )

            mapped_vip_services.append(
                service_name
            )

            if (
                service_name
                not in service_inventory
                and not any(
                    item.name
                    == service_name
                    for item
                    in generated_services
                )
            ):
                service_object = (
                    IRServiceObject(
                        name=service_name,
                        protocol=protocol,
                        port=ext_port,
                        description=(
                            "Auto-generated Service "
                            f"for VIP {destination} "
                            f"({protocol.value.upper()}/"
                            f"{ext_port})"
                        ),
                    )
                )

                generated_services.append(
                    service_object
                )

                service_inventory[
                    service_name
                ] = service_object

        ext_port_str = str(
            vip.get(
                "extport",
                "",
            )
        )

        mapped_port_str = str(
            vip.get(
                "mappedport",
                ext_port_str,
            )
        )

        dnat_rule = IRNatRule(
            name=(
                f"DNAT_{destination}"
            ),
            nat_type=(
                IRNatType.DNAT_STATIC
            ),
            from_zones=list(
                ir_sec_rule.from_zones
            ),
            to_zones=list(
                ir_sec_rule.from_zones
            ),
            sources=list(
                ir_sec_rule.sources
            ),
            destinations=[
                vip["extip"]
            ],
            service=service_name,
            translated_destinations=[
                vip["mappedip"]
            ],
            translated_port=(
                mapped_port_str
                if is_portforward
                else None
            ),
            description=(
                (
                    f"DNAT VIP {destination} "
                    f"({ext_port_str} -> "
                    f"{mapped_port_str})"
                )
                if is_portforward
                else (
                    f"DNAT VIP "
                    f"{destination}"
                )
            ),
        )

        ir_nat_rules.append(
            dnat_rule
        )

        # Legacy bi-directional source NAT behaviour.
        if (
            vip.get("extintf")
            == "any"
            and not is_portforward
        ):
            bi_snat_rule = IRNatRule(
                name=(
                    "SNAT_Outbound_"
                    f"{destination}"
                ),
                nat_type=(
                    IRNatType.SNAT_STATIC
                ),
                from_zones=[
                    vip.get(
                        "mapped_interface",
                        "trust",
                    )
                ],
                to_zones=list(
                    ir_sec_rule.from_zones
                ),
                sources=[
                    vip["mappedip"]
                ],
                destinations=[
                    "any"
                ],
                service="any",
                translated_sources=[
                    vip["extip"]
                ],
                description=(
                    "Bi-directional outbound "
                    f"SNAT for VIP {destination}"
                ),
            )

            ir_nat_rules.append(
                bi_snat_rule
            )

        if vip.get(
            "mapped_interface"
        ):
            mapped_post_nat_zones.append(
                vip[
                    "mapped_interface"
                ]
            )

    if mapped_post_nat_zones:
        ir_sec_rule.to_zones = list(
            dict.fromkeys(
                mapped_post_nat_zones
            )
        )

    if mapped_vip_services:
        ir_sec_rule.services = list(
            dict.fromkeys(
                mapped_vip_services
            )
        )
    else:
        cleaned_services = [
            (
                "any"
                if service.upper()
                in [
                    "ALL",
                    "ANY",
                ]
                else service
            )
            for service
            in base_services
        ]

        ir_sec_rule.services = list(
            dict.fromkeys(
                cleaned_services
            )
        )

    return (
        ir_sec_rule,
        ir_nat_rules,
        generated_services,
    )
