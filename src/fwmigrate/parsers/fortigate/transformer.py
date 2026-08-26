from ipaddress import ip_address
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from pydantic import ValidationError

from fwmigrate.parsers.fortigate.model import (
    FGConfig,
    FGInterface,
    FGFCTEMS,
    FGSystemGlobal,
)
from fwmigrate.ir.core import (
    IRConfig,
    IRMetadata,
    IRZone,
    IRInterface,
    IRAddress,
    AddressType,
    IRAddressGroup,
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
    IRZTNAProvider,
    IRSessionHelper,
    IRSessionTTLOverride,
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
    IRUserLDAP,
    IRFSSOProvider,
    IRFSSOADGroup,
    IRUserSAML,
    IRLocalUser,
    IRUserGroup,
    IRUserGroupMatch,
    IRSSLVPNPortal,
    IRSSLVPNHostCheck,
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
)
from fwmigrate.parsers.fortigate.session_helper_defaults import (
    classify_session_helper,
    protocol_number_to_name,
)
from fwmigrate.parsers.fortigate.net_utils import (
    normalize_ipv4_network,
    normalize_ipv4_prefix,
)
from fwmigrate.parsers.vendor_maps import normalize_to_ir
from fwmigrate.core.constants import IR_KEYWORD_ANY


def _normalize_interface_ip(value: Optional[str]) -> Optional[str]:
    """Normalize a FortiOS interface address without repairing invalid input."""
    if not value:
        return None

    normalized = normalize_ipv4_prefix(value)

    # 0.0.0.0/0 means no usable configured IP.
    if normalized == "0.0.0.0/0":
        return None

    return normalized


class FGToIRTransformer:
    def __init__(
        self,
        fg_config: FGConfig,
        zone_mapping: Optional[Dict[str, str]] = None,
    ):
        self.fg = fg_config

        self.ir = IRConfig(
            metadata=IRMetadata(
                hostname=(
                    fg_config.system_global.hostname
                    if fg_config.system_global
                    else "fortigate"
                ),
                source_vendor="fortigate",
            )
        )

        self.zone_mapping = zone_mapping or {}

        self._intf_to_zone: Dict[str, str] = {}

        self._interface_by_name = {
            interface.name: interface
            for interface in self.fg.interfaces
        }

        self._sdwan_zone_names: Set[str] = set()

        if self.fg.sdwan:
            self._sdwan_zone_names.update(
                zone.name
                for zone in self.fg.sdwan.zones
            )

            self._sdwan_zone_names.update(
                member.zone
                for member in self.fg.sdwan.members
            )

        # Map FortiGate system-zone members to their zone.
        self.fg_zone_intf_map: Dict[str, str] = {}

        for system_zone in self.fg.system_zones:
            for member_intf in system_zone.interface:
                self.fg_zone_intf_map[
                    member_intf
                ] = system_zone.name

            self.fg_zone_intf_map[
                system_zone.name
            ] = system_zone.name

            self._intf_to_zone[
                system_zone.name
            ] = system_zone.name

    def transform(self) -> IRConfig:
        self._transform_system_settings()
        self._transform_interfaces_and_zones()

        # Operational / traffic-behaviour settings.
        self._transform_dhcp_servers()

        self._transform_addresses()
        self._transform_services()

        # ALG / session behaviour.
        self._transform_session_helpers()
        self._transform_session_ttl_overrides()

        self._transform_schedules()
        self._transform_traffic_shapers()
        self._transform_proxy_settings()
        self._transform_ips_sensors()
        self._transform_policies()

        self._transform_ip_pools()
        self._transform_virtual_ips()
        self._transform_vip_groups()
        self._transform_nat()

        self._transform_vpn()
        self._transform_certificates()
        self._transform_ssh_keys()
        self._transform_routes()
        self._transform_sdwan()

        self._transform_internet_services()
        self._transform_ztna_providers()
        self._transform_identity()
        self._transform_ssl_vpn()
        self._transform_dos_policies()
        self._transform_firewall_sniffers()
        self._transform_authentication_inventory()

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
            self.ir.dns_settings = IRDNSSettings(
                primary=self.fg.dns.primary,
                secondary=self.fg.dns.secondary,
                source_attributes=dict(self.fg.dns.extra_settings),
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
        if self.fg.sdwan is None:
            return
        self.ir.sdwan = IRSDWAN(
            status=self.fg.sdwan.status,
            load_balance_mode=self.fg.sdwan.load_balance_mode,
            zones=[
                IRSDWANZone(
                    name=zone.name,
                    source_attributes=dict(zone.extra_settings),
                )
                for zone in self.fg.sdwan.zones
            ],
            members=[
                IRSDWANMember(
                    source_id=member.id,
                    interface=member.interface,
                    zone=member.zone,
                    gateway=member.gateway,
                    weight=member.weight,
                    priority=member.priority,
                    source_attributes=dict(member.extra_settings),
                )
                for member in self.fg.sdwan.members
            ],
            health_checks=[
                IRSDWANHealthCheck(
                    name=check.name,
                    server=check.server,
                    member_ids=list(check.members),
                    interval=check.interval,
                    sla=[
                        IRSDWANSLA(
                            source_id=sla.id,
                            source_attributes=dict(sla.extra_settings),
                        )
                        for sla in check.sla
                    ],
                    source_attributes=dict(check.extra_settings),
                )
                for check in self.fg.sdwan.health_checks
            ],
            rules=[
                IRSDWANRule(
                    source_id=rule.id,
                    name=rule.name,
                    mode=rule.mode,
                    source_addresses=list(rule.src),
                    destination_addresses=list(rule.dst),
                    health_check=rule.health_check,
                    priority_member_ids=list(rule.priority_members),
                    internet_service=rule.internet_service,
                    internet_service_names=list(rule.internet_service_name),
                    internet_service_app_ctrl=list(rule.internet_service_app_ctrl),
                    use_shortcut_sla=rule.use_shortcut_sla,
                    source_attributes=dict(rule.extra_settings),
                )
                for rule in self.fg.sdwan.services
            ],
            source_attributes=dict(self.fg.sdwan.extra_settings),
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
                        id=f"fsso-adgrp:{item.name}:provider",
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

        ad_group_names = {item.name for item in self.fg.ad_groups}
        for item in self.fg.user_groups:
            if item.group_type != "fsso-service":
                continue
            for member in item.member:
                if member not in ad_group_names:
                    self.ir.audit_entries.append(
                        IRAuditEntry(
                            id=f"user-group:{item.name}:fsso-adgrp:{member}",
                            category="Identity",
                            message=(
                                f"User group '{item.name}' references missing "
                                f"FSSO AD group '{member}'."
                            ),
                            confidence=MigrationConfidence.MANUAL,
                        )
                    )

    def _transform_ssl_vpn(self) -> None:
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
                source_interfaces=list(settings.source_interface),
                source_addresses=list(settings.source_address),
                tunnel_ip_pools=list(settings.tunnel_ip_pools),
                default_portal=settings.default_portal,
                authentication_rules=[
                    IRSSLVPNAuthenticationRule(
                        source_id=rule.id,
                        groups=list(rule.groups),
                        portal=rule.portal,
                        source_attributes=dict(rule.extra_settings),
                    )
                    for rule in settings.authentication_rules
                ],
                source_attributes=dict(settings.extra_settings),
            )

    def _transform_dos_policies(self) -> None:
        self.ir.dos_policies.extend(
            IRDoSPolicy(
                source_id=policy.id,
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

    # ------------------------------------------------------------------
    # Interfaces / zones
    # ------------------------------------------------------------------

    def _get_zone_for_intf(
        self,
        intf: FGInterface,
    ) -> Optional[str]:
        if intf.name in self.zone_mapping:
            return self.zone_mapping[intf.name]

        if intf.name in self.fg_zone_intf_map:
            return self.fg_zone_intf_map[intf.name]

        # If part of SD-WAN, use the source SD-WAN zone.
        if self.fg.sdwan:
            for member in self.fg.sdwan.members:
                if member.interface == intf.name:
                    return member.zone

        return None

    def _transform_interfaces_and_zones(
        self,
    ) -> None:
        zones_map: Dict[str, IRZone] = {}

        # Preserve explicitly configured FortiGate system zones.
        for system_zone in self.fg.system_zones:
            if system_zone.name not in zones_map:
                zones_map[
                    system_zone.name
                ] = IRZone(
                    name=system_zone.name,
                    interfaces=list(
                        system_zone.interface
                    ),
                )

        for intf in self.fg.interfaces:
            zone_name = self._get_zone_for_intf(
                intf
            )

            if zone_name is not None:
                self._intf_to_zone[
                    intf.name
                ] = zone_name

                if zone_name not in zones_map:
                    zones_map[
                        zone_name
                    ] = IRZone(
                        name=zone_name
                    )

                if (
                    intf.name
                    not in zones_map[
                        zone_name
                    ].interfaces
                ):
                    zones_map[
                        zone_name
                    ].interfaces.append(
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

            self.ir.interfaces.append(
                IRInterface(
                    name=intf.name,
                    zone=zone_name,
                    ip=ip_cidr,
                    remote_ip=remote_ip_cidr,
                    description=intf.description,
                    parent=intf.interface,
                    tag=intf.vlanid,
                    alias=intf.alias,
                    status=(
                        intf.status != "down"
                    ),
                    vlanid=intf.vlanid,
                    pppoe_mode=(
                        intf.mode
                        if intf.mode == "pppoe"
                        else None
                    ),
                    pppoe_username=intf.username,
                    source_vdom=intf.vdom,
                    interface_type=intf.type,
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
                    requires_manual_review=bool(parse_errors),
                    parse_errors=parse_errors,
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
        associated_interface=None,
        allow_routing=None,
        source_color=None,
        source_sub_type=None,
        source_obj_tag=None,
        source_tag_type=None,
        source_obj_type=None,
        source_dirty=None,
        source_attributes=None,
    ):
        kwargs = {
            "name": name,
            "type": addr_type,
            "description": description,
            "is_ipv6": is_ipv6,
            "is_multicast": is_multicast,
            "source_uuid": source_uuid,
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

    def _transform_addresses(
        self,
    ) -> None:
        tunnel_routes = {}

        for route in self.fg.static_routes:
            dst_raw = (
                route.dst
                or "0.0.0.0 0.0.0.0"
            )

            if (
                route.device
                and dst_raw
                and dst_raw
                != "0.0.0.0 0.0.0.0"
            ):
                try:
                    tunnel_routes[route.device] = normalize_ipv4_network(dst_raw)
                except ValueError:
                    continue

        local_subnets = []

        import ipaddress

        for intf in self.fg.interfaces:
            if (
                intf.role in [
                    "lan",
                    "trust",
                ]
                and intf.ip
            ):
                try:
                    cidr_str = normalize_ipv4_prefix(intf.ip)
                    network = ipaddress.ip_network(
                        cidr_str,
                        strict=False,
                    )
                    local_subnets.append(
                        str(network)
                    )
                except ValueError:
                    continue

        if not local_subnets:
            for intf in self.fg.interfaces:
                if (
                    self._get_zone_for_intf(
                        intf
                    )
                    == "trust"
                    and intf.ip
                ):
                    try:
                        cidr_str = normalize_ipv4_prefix(intf.ip)
                        network = (
                            ipaddress.ip_network(
                                cidr_str,
                                strict=False,
                            )
                        )
                        local_subnets.append(
                            str(network)
                        )
                    except ValueError:
                        continue

        skip_addresses = {
            "all",
            "none",
            "FABRIC_DEVICE",
            "FIREWALL_AUTH_PORTAL_ADDRESS",
        }

        for addr in self.fg.addresses:
            if (
                addr.name in {"all", "none"}
                and addr.is_ipv6
            ):
                section_name = (
                    "firewall multicast-address6"
                    if addr.is_multicast
                    else "firewall address6"
                )
                self.ir.audit_entries.append(
                    IRAuditEntry(
                        id=f"{section_name}:{addr.name}",
                        category=section_name,
                        message=(
                            f"Source object '{addr.name}' was retained as "
                            "source-audit inventory and withheld from ordinary "
                            "IR addresses to avoid collision with a built-in "
                            f"keyword (IPv6={addr.is_ipv6}, "
                            f"multicast={addr.is_multicast}, "
                            f"value={addr.ip6 or ''}, "
                            f"source_uuid={addr.uuid or ''})."
                        ),
                        confidence=MigrationConfidence.MANUAL,
                    )
                )
                continue

            if addr.name in skip_addresses:
                continue

            addr_type = AddressType.NETWORK
            val = ""

            # Attempt to resolve empty VPN helper objects.
            if (
                not addr.subnet
                and addr.type
                not in [
                    "fqdn",
                    "mac",
                    "geography",
                    "dynamic",
                ]
            ):
                if "remote_subnet" in addr.name:
                    tunnel_name = (
                        addr.name.split(
                            "_remote_subnet"
                        )[0]
                    )

                    if tunnel_name in tunnel_routes:
                        val = tunnel_routes[
                            tunnel_name
                        ]

                        self.ir.audit_entries.append(
                            IRAuditEntry(
                                id=addr.name,
                                category="Address",
                                message=(
                                    "Inferred empty VPN remote "
                                    f"subnet '{addr.name}' from "
                                    "route pointing to "
                                    f"'{tunnel_name}'."
                                ),
                                confidence=MigrationConfidence.PARTIAL,
                            )
                        )

                elif "local_subnet" in addr.name:
                    if local_subnets:
                        val = local_subnets[0]

                        self.ir.audit_entries.append(
                            IRAuditEntry(
                                id=addr.name,
                                category="Address",
                                message=(
                                    "Inferred empty VPN local "
                                    f"subnet '{addr.name}' from "
                                    "primary local interface."
                                ),
                                confidence=MigrationConfidence.PARTIAL,
                            )
                        )

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
                        val = (
                            f"{addr.start_ip}/32"
                        )
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
                                type=AddressType.MAC,
                                mac=raw_mac,
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
                    addr_type = (
                        AddressType.GEO
                    )
                    val = addr.country or ""

                elif addr.type == "dynamic":
                    tag_name = (
                        addr.obj_tag
                        or addr.ems_tag_name
                        or addr.name
                    )

                    self.ir.address_groups.append(
                        IRAddressGroup(
                            name=addr.name,
                            is_dynamic=True,
                            dynamic_filter=(
                                f"'{tag_name}'"
                            ),
                            tags=[tag_name],
                            description=(
                                addr.comment
                                or (
                                    "Migrated FortiClient "
                                    "EMS Dynamic Tag: "
                                    f"{tag_name}"
                                )
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
                        )
                    )

                    self.ir.audit_entries.append(
                        IRAuditEntry(
                            id=addr.name,
                            category="Address",
                            message=(
                                "Dynamic/EMS Tag "
                                f"'{addr.name}' automatically "
                                "converted to Target Dynamic "
                                "Address Group (DAG) with "
                                f"filter '{tag_name}'."
                            ),
                            confidence=(
                                MigrationConfidence.FULL
                            ),
                        )
                    )

                    continue

            if not val and addr_type != AddressType.GEO:
                continue

            self.ir.addresses.append(
                self._create_ir_address(
                    name=addr.name,
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
                )
            )

        for fqdn in self.fg.wildcard_fqdns:
            val = fqdn.wildcard_fqdn

            self.ir.addresses.append(
                self._create_ir_address(
                    name=fqdn.name,
                    addr_type=(
                        AddressType.WILDCARD_FQDN
                    ),
                    val=val,
                    description=fqdn.comment,
                    source_uuid=fqdn.uuid,
                    source_attributes=dict(
                        fqdn.extra_settings
                    ),
                )
            )

        for group in self.fg.address_groups:
            self.ir.address_groups.append(
                IRAddressGroup(
                    name=group.name,
                    members=group.member,
                    description=group.comment,
                    source_uuid=group.uuid,
                    allow_routing=(
                        self._fortios_enabled(
                            group.allow_routing
                        )
                    ),
                    source_color=group.color,
                    source_category=group.category,
                    source_attributes=dict(
                        group.extra_settings
                    ),
                )
            )

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

    def _transform_services(
        self,
    ) -> None:
        for category in self.fg.service_categories:
            self.ir.service_categories.append(
                IRServiceCategory(
                    name=category.name,
                    description=category.comment,
                    source_attributes=dict(
                        category.extra_settings
                    ),
                )
            )

        for service in self.fg.services:
            ports = []
            protocol_name = service.protocol.upper()

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
                and service.protocol_number
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
                        protocol=(
                            ServiceProtocol.ANY
                            if service.name.upper() == "ALL"
                            else ServiceProtocol.IP
                        ),
                        port=IR_KEYWORD_ANY,
                    )
                )

            source_proxy = (
                self._fortios_enabled(service.proxy)
                if service.proxy is not None
                else None
            )
            zero_port_values = {
                port.port
                for port in ports
                if port.port == "0"
                or port.port.startswith("0-")
            }
            requires_manual_review = bool(
                source_proxy or zero_port_values
            )
            audit_reasons = []

            if source_proxy:
                audit_reasons.append(
                    "FortiGate proxy service semantics require target review"
                )

            if zero_port_values:
                audit_reasons.append(
                    "target support for source port-zero semantics must be verified"
                )

            if not ports:
                requires_manual_review = True
                audit_reasons.append(
                    "source protocol has no safe normalized port representation"
                )

            self.ir.services.append(
                IRService(
                    name=service.name,
                    ports=ports,
                    source_uuid=service.uuid,
                    source_category=service.category,
                    source_protocol=service.protocol,
                    source_protocol_number=(
                        service.protocol_number
                    ),
                    source_proxy=source_proxy,
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
            self.ir.service_groups.append(
                IRServiceGroup(
                    name=group.name,
                    members=group.member,
                    source_uuid=group.uuid,
                    source_attributes=dict(
                        group.extra_settings
                    ),
                    description=group.comment,
                )
            )

    # ------------------------------------------------------------------
    # Schedules
    # ------------------------------------------------------------------

    def _transform_schedules(
        self,
    ) -> None:
        for schedule in self.fg.schedules:
            self.ir.schedules.append(
                IRSchedule(
                    name=schedule.name,
                    start=schedule.start,
                    end=schedule.end,
                    days=schedule.day,
                    schedule_type=schedule.type,
                    source_color=schedule.color,
                    expiration_days=schedule.expiration_days,
                    source_attributes=dict(schedule.extra_settings),
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
    ) -> List[str]:
        zones: List[str] = []
        unresolved: Set[str] = set()

        for interface in interfaces:
            if interface == "any":
                zone = IR_KEYWORD_ANY
            else:
                zone = (
                    self._intf_to_zone.get(interface)
                    or self.fg_zone_intf_map.get(interface)
                )
                if zone is None and interface in self._sdwan_zone_names:
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

    def _transform_policies(
        self,
    ) -> None:
        for policy in self.fg.policies:
            from_zones = self._resolve_policy_zones(
                policy.srcintf,
                policy.id,
                "source",
            )
            to_zones = self._resolve_policy_zones(
                policy.dstintf,
                policy.id,
                "destination",
            )

            action = PolicyAction.DENY

            if policy.action == "accept":
                action = PolicyAction.ALLOW

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
                source_service_references=list(
                    policy.service
                ),
                source_action=policy.action,
                source_schedule=policy.schedule,
                source_user_groups=list(
                    policy.groups
                ),
                source_users=list(
                    policy.users
                ),
                source_log_setting=(
                    policy.logtraffic
                ),
                source_inspection_mode=(
                    policy.inspection_mode
                ),
                source_ztna_status=(
                    policy.ztna_status
                ),
                source_ztna_ems_tags=list(
                    policy.ztna_ems_tag
                ),
                source_extra_settings=dict(
                    policy.extra_settings
                ),
                nat_enabled=(
                    policy.nat == "enable"
                ),
                nat_pool_enabled=(
                    policy.ippool == "enable"
                ),
                nat_pool_names=list(
                    policy.poolname
                ),
                from_zone=from_zones,
                to_zone=to_zones,
                source=[
                    normalize_to_ir(
                        "fortigate",
                        address,
                    )
                    for address
                    in policy.srcaddr
                ],
                destination=[
                    normalize_to_ir(
                        "fortigate",
                        address,
                    )
                    for address
                    in policy.dstaddr
                ],
                service=[
                    normalize_to_ir(
                        "fortigate",
                        service,
                    )
                    for service
                    in policy.service
                ],
                action=action,
                description=policy.comments,
                schedule=(
                    policy.schedule
                    if (
                        policy.schedule
                        and policy.schedule
                        != "always"
                    )
                    else None
                ),
                log_start=(
                    policy.logtraffic
                    in (
                        "all",
                        "utm",
                    )
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
            )

            if policy.utm_status == "enable":
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
                    "SPG_"
                    + "_".join(
                        active_features
                    )
                    if active_features
                    else "Migrated_Profiles"
                )

                group_name = re.sub(
                    r"[^a-zA-Z0-9_-]",
                    "_",
                    group_name,
                )[:63]

                ir_policy.security_profile_group = (
                    group_name
                )
                ir_policy.antivirus = (
                    policy.av_profile
                )
                ir_policy.ips_sensor = (
                    policy.ips_sensor
                )
                ir_policy.webfilter = (
                    policy.webfilter_profile
                )
                ir_policy.application_list = (
                    policy.application_list
                )
                ir_policy.ssl_ssh_profile = (
                    policy.ssl_ssh_profile
                )

                if not any(
                    group.name == group_name
                    for group
                    in self.ir.security_profile_groups
                ):
                    self.ir.security_profile_groups.append(
                        IRSecurityProfileGroup(
                            name=group_name,
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
                                f"({', '.join(active_features) if active_features else 'General'})"
                            ),
                        )
                    )

                self.ir.audit_entries.append(
                    IRAuditEntry(
                        id=str(
                            policy.id
                        ),
                        category="Policy",
                        message=(
                            "UTM profiles mapped to "
                            "Security Profile Group "
                            f"'{group_name}'."
                        ),
                        confidence=(
                            MigrationConfidence.FULL
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

    def _transform_ip_pools(
        self,
    ) -> None:
        for pool in self.fg.ip_pools:
            self.ir.ip_pools.append(
                IRIPPool(
                    name=pool.name,
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
                    description=pool.comments,
                )
            )

    # ------------------------------------------------------------------
    # Virtual IPs
    # ------------------------------------------------------------------

    def _transform_virtual_ips(
        self,
    ) -> None:
        for vip in self.fg.vips:
            self.ir.virtual_ips.append(
                IRVirtualIP(
                    name=vip.name,
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
                    real_servers=[
                        IRVirtualIPRealServer(
                            id=server.id,
                            address=server.ip,
                            port=server.port,
                            status=server.status,
                            weight=server.weight,
                            holddown_interval=(
                                server.holddown_interval
                            ),
                        )
                        for server
                        in vip.realservers
                    ],
                    color=vip.color,
                    description=vip.comment,
                    extra_settings=dict(
                        vip.extra_settings
                    ),
                )
            )

    def _transform_vip_groups(self) -> None:
        for group in self.fg.vip_groups:
            self.ir.virtual_ip_groups.append(
                IRVirtualIPGroup(
                    name=group.name,
                    source_uuid=group.uuid,
                    interface=group.interface,
                    members=list(group.member),
                    source_color=group.color,
                    description=group.comment,
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

        pools_by_name = {
            pool.name: pool
            for pool in self.ir.ip_pools
        }

        vips_by_name = {
            vip.name: vip
            for vip in self.fg.vips
        }

        vip_groups_by_name = {
            group.name: group
            for group in self.fg.vip_groups
        }

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
            vip_matches = []
            ordinary_destinations = []

            for destination in policy.dstaddr:
                if destination in vips_by_name:
                    vip_matches.append(
                        (
                            vips_by_name[
                                destination
                            ],
                            None,
                        )
                    )
                    continue

                vip_group = (
                    vip_groups_by_name.get(
                        destination
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
                        member
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
            source_requires_review = (
                not ir_policy.from_zone
                or not ir_policy.to_zone
            )

            if source_requires_review and (
                snat_enabled or vip_matches
            ):
                audit(
                    policy.id,
                    (
                        f"Policy {policy.id} NAT match has unresolved "
                        "canonical zones; source interface references "
                        "were preserved and the NAT rule requires "
                        "manual review."
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
                        pool_name
                    )

                    if pool is None:
                        source_requires_review = True

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
                        policy.dstintf
                    )
                )

                if translated_source:
                    translated_sources.append(
                        translated_source
                    )

                if requires_review:
                    source_requires_review = True

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
                translated_sources=(
                    translated_sources
                ),
                requires_manual_review=(
                    source_requires_review
                ),
                description=policy.comments,
            )

            for (
                vip,
                vip_group_name,
            ) in vip_matches:
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
                )

                if (
                    not external_destinations
                    or not translated_destinations
                ):
                    vip_requires_review = True

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
                            service.name
                            == service_name
                            for service
                            in self.ir.services
                        ):
                            self.ir.services.append(
                                IRService(
                                    name=service_name,
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
                    vip.extintf
                    in self._intf_to_zone
                ):
                    nat_to_zone = [
                        self._intf_to_zone[
                            vip.extintf
                        ]
                    ]

                else:
                    nat_to_zone = []
                    vip_requires_review = True

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
                        requires_manual_review=(
                            vip_requires_review
                        ),
                        **{
                            key: value
                            for key, value
                            in common.items()
                            if key
                            != "requires_manual_review"
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

        if (
            interface_name
            in self._sdwan_zone_names
        ):
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
                interface_name
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
            phase1.name
            for phase1 in self.fg.phase1_interfaces
        }

        for phase1 in self.fg.phase1_interfaces:
            self.ir.vpn_tunnels.append(
                IRVPNTunnel(
                    name=phase1.name,
                    peer_address=(
                        phase1.remote_gw
                        or "dynamic"
                    ),
                    local_interface=(
                        phase1.interface
                    ),
                    ike_version=(
                        "v1"
                        if phase1.ike_version
                        == "1"
                        else "v2"
                    ),
                    psk=phase1.psksecret,
                    has_psk=phase1.has_psk,
                    description=phase1.comments,
                )
            )

            self.ir.audit_entries.append(
                IRAuditEntry(
                    id=phase1.name,
                    category="VPN",
                    message=(
                        "IPsec VPN mapped. "
                        "Pre-Shared Key (PSK) is "
                        "encrypted in the backup "
                        "configuration; retrieve the "
                        "usable PSK securely from the "
                        "source environment and set "
                        "the equivalent target IKE "
                        "gateway credential."
                    ),
                    confidence=(
                        MigrationConfidence.PARTIAL
                    ),
                )
            )

        for phase2 in self.fg.phase2_interfaces:
            missing_phase1 = phase2.phase1name not in phase1_names
            requires_review = missing_phase1 or bool(
                phase2.extra_settings
            )

            self.ir.vpn_phase2.append(
                IRVPNPhase2(
                    name=phase2.name,
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
                    requires_manual_review=requires_review,
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
            dst_raw = (
                route.dst
                or "0.0.0.0 0.0.0.0"
            )

            try:
                dst_cidr = normalize_ipv4_network(dst_raw)
                parse_error = None
            except ValueError as exc:
                dst_cidr = None
                parse_error = str(exc)
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

            source_attributes = dict(route.extra_settings)
            if route.blackhole not in {"enable", "disable"}:
                source_attributes["blackhole"] = route.blackhole
            if route.status is not None and route.status not in {"enable", "disable"}:
                source_attributes["status"] = route.status

            requires_review = parse_error is not None or bool(source_attributes)

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
                    destination=dst_cidr,
                    source_destination=dst_raw,
                    source_route_id=route.id,
                    interface=route.device,
                    next_hop=route.gateway,
                    administrative_distance=route.distance,
                    metric=None,
                    priority=route.priority,
                    blackhole=route.blackhole == "enable",
                    enabled=(
                        route.status != "disable"
                        if route.status is not None
                        else None
                    ),
                    sdwan_zone=route.sdwan_zone,
                    description=route.comment,
                    migration_status=(
                        "PARTIALLY_NORMALIZED"
                        if requires_review
                        else "NORMALIZED"
                    ),
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
