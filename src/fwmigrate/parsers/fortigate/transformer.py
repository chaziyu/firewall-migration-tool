from ipaddress import ip_address
import re
from typing import Dict, List, Optional, Set, Tuple

from pydantic import ValidationError

from fwmigrate.parsers.fortigate.model import (
    FGConfig,
    FGInterface,
    FGFCTEMS,
)
from fwmigrate.ir.core import (
    IRConfig,
    IRMetadata,
    IRZone,
    IRInterface,
    IRAddress,
    AddressType,
    IRAddressGroup,
    IRService,
    IRServicePort,
    ServiceProtocol,
    IRServiceGroup,
    IRSchedule,
    IRPolicy,
    PolicyAction,
    IRIPPool,
    IRVirtualIP,
    IRVirtualIPRealServer,
    IRNATRule,
    NATType,
    NATTranslationMode,
    IRVPNTunnel,
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
)
from fwmigrate.parsers.fortigate.session_helper_defaults import (
    classify_session_helper,
    protocol_number_to_name,
)
from fwmigrate.parsers.vendor_maps import normalize_to_ir
from fwmigrate.core.constants import IR_KEYWORD_ANY
from fwmigrate.core.stubs import create_unsupported_stub


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
        self._transform_interfaces_and_zones()

        # Operational / traffic-behaviour settings.
        self._transform_dhcp_servers()

        self._transform_addresses()
        self._transform_services()

        # ALG / session behaviour.
        self._transform_session_helpers()
        self._transform_session_ttl_overrides()

        self._transform_schedules()
        self._transform_policies()

        self._transform_ip_pools()
        self._transform_virtual_ips()
        self._transform_nat()

        self._transform_vpn()
        self._transform_routes()

        self._transform_internet_services()
        self._transform_ztna_providers()

        return self.ir

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

    # ------------------------------------------------------------------
    # Interfaces / zones
    # ------------------------------------------------------------------

    def _get_zone_for_intf(
        self,
        intf: FGInterface,
    ) -> str:
        if intf.name in self.zone_mapping:
            return self.zone_mapping[intf.name]

        if intf.name in self.fg_zone_intf_map:
            return self.fg_zone_intf_map[intf.name]

        # If part of SD-WAN, use the source SD-WAN zone.
        if self.fg.sdwan:
            for member in self.fg.sdwan.members:
                if member.interface == intf.name:
                    return member.zone

        if intf.role != "undefined":
            role_map = {
                "wan": "untrust",
                "lan": "trust",
                "dmz": "dmz",
            }
            return role_map.get(
                intf.role,
                intf.role,
            )

        text = (
            f"{intf.name} "
            f"{intf.alias or ''} "
            f"{intf.description or ''}"
        ).lower()

        if any(
            keyword in text
            for keyword in [
                "lan",
                "internal",
                "inside",
                "trust",
                "polycom",
                "user",
                "corp",
                "server",
                "mgmt",
                "local",
            ]
        ):
            return "trust"

        if "dmz" in text:
            return "dmz"

        if any(
            keyword in text
            for keyword in [
                "wan",
                "internet",
                "outside",
                "untrust",
                "pppoe",
                "isp",
                "unifi",
            ]
        ):
            return "untrust"

        if intf.name.lower().startswith("internal"):
            return "trust"

        if (
            intf.name.lower().startswith("wan")
            or intf.name.lower().startswith("port")
        ):
            return "untrust"

        return (
            "trust"
            if "internal" in intf.name.lower()
            else "untrust"
        )

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

            # FortiOS:
            #
            #   10.0.0.1 255.255.255.0
            #
            # IR:
            #
            #   10.0.0.1/24
            ip_cidr = None

            if intf.ip:
                parts = intf.ip.split()

                if len(parts) == 2:
                    ip_value, mask = parts

                    try:
                        bits = sum(
                            bin(int(octet)).count("1")
                            for octet in mask.split(".")
                        )
                        cidr = f"/{bits}"
                    except Exception:
                        cidr = "/32"

                    # 0.0.0.0/0 means no usable configured IP.
                    if (
                        ip_value == "0.0.0.0"
                        and cidr == "/0"
                    ):
                        ip_cidr = None
                    else:
                        ip_cidr = (
                            f"{ip_value}{cidr}"
                        )

            self.ir.interfaces.append(
                IRInterface(
                    name=intf.name,
                    zone=zone_name,
                    ip=ip_cidr,
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
                tunnel_routes[
                    route.device
                ] = self._mask_to_cidr_str(
                    dst_raw
                )

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
                cidr_str = (
                    self._mask_to_cidr_str(
                        intf.ip
                    )
                )

                try:
                    network = ipaddress.ip_network(
                        cidr_str,
                        strict=False,
                    )
                    local_subnets.append(
                        str(network)
                    )
                except Exception:
                    local_subnets.append(
                        cidr_str
                    )

        if not local_subnets:
            for intf in self.fg.interfaces:
                if (
                    self._get_zone_for_intf(
                        intf
                    )
                    == "trust"
                    and intf.ip
                ):
                    cidr_str = (
                        self._mask_to_cidr_str(
                            intf.ip
                        )
                    )

                    try:
                        network = (
                            ipaddress.ip_network(
                                cidr_str,
                                strict=False,
                            )
                        )
                        local_subnets.append(
                            str(network)
                        )
                    except Exception:
                        local_subnets.append(
                            cidr_str
                        )

        skip_addresses = {
            "all",
            "none",
            "FABRIC_DEVICE",
            "FIREWALL_AUTH_PORTAL_ADDRESS",
            "EIGRP",
            "OSPF",
            "SSLVPN_TUNNEL_IPv6_ADDR1",
        }

        for addr in self.fg.addresses:
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
                                confidence=(
                                    MigrationConfidence.FULL
                                ),
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
                                confidence=(
                                    MigrationConfidence.FULL
                                ),
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
                    parts = addr.subnet.split()

                    if len(parts) == 2:
                        ip_value, mask = parts

                        try:
                            bits = sum(
                                bin(
                                    int(octet)
                                ).count("1")
                                for octet
                                in mask.split(".")
                            )
                            val = (
                                f"{ip_value}/{bits}"
                            )
                        except Exception:
                            val = (
                                f"{ip_value}/32"
                            )

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

                    if (
                        val.startswith("*")
                        and not val.startswith("*.")
                    ):
                        normalized = (
                            "*." + val[1:]
                        )

                        self.ir.audit_entries.append(
                            IRAuditEntry(
                                id=addr.name,
                                category="Address",
                                message=(
                                    f"Wildcard FQDN '{val}' "
                                    "normalized to PAN-OS "
                                    f"format '{normalized}'. "
                                    "Apex domain matching "
                                    "behavior may differ."
                                ),
                                confidence=(
                                    MigrationConfidence.PARTIAL
                                ),
                            )
                        )

                        val = normalized

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
                        or "00:00:00:00:00:00"
                    )

                    stub_obj = (
                        create_unsupported_stub(
                            name=addr.name,
                            original_type="mac",
                            original_value=raw_mac,
                            description=addr.comment,
                        )
                    )

                    self.ir.addresses.append(
                        stub_obj.model_copy(
                            update={
                                "source_uuid": addr.uuid,
                                "associated_interface": addr.associated_interface,
                                "allow_routing": self._fortios_enabled(
                                    addr.allow_routing
                                ),
                                "source_color": addr.color,
                                "source_sub_type": addr.sub_type,
                                "source_obj_tag": addr.obj_tag,
                                "source_tag_type": addr.tag_type,
                                "source_obj_type": addr.obj_type,
                                "source_dirty": addr.dirty,
                                "source_attributes": dict(
                                    addr.extra_settings
                                ),
                            }
                        )
                    )

                    self.ir.audit_entries.append(
                        IRAuditEntry(
                            id=addr.name,
                            category="Address",
                            message=(
                                stub_obj.audit_note
                                or (
                                    "Unsupported MAC object "
                                    f"'{addr.name}' converted "
                                    "to RFC 5737 stub"
                                )
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

            if (
                val.startswith("*")
                and not val.startswith("*.")
            ):
                normalized = (
                    "*." + val[1:]
                )

                self.ir.audit_entries.append(
                    IRAuditEntry(
                        id=fqdn.name,
                        category="Address",
                        message=(
                            f"Wildcard FQDN '{val}' "
                            "normalized to PAN-OS format "
                            f"'{normalized}'. Apex domain "
                            "matching behavior may differ."
                        ),
                        confidence=(
                            MigrationConfidence.PARTIAL
                        ),
                    )
                )

                val = normalized

            self.ir.addresses.append(
                self._create_ir_address(
                    name=fqdn.name,
                    addr_type=(
                        AddressType.WILDCARD_FQDN
                    ),
                    val=val,
                    description=fqdn.comment,
                )
            )

        for group in self.fg.address_groups:
            self.ir.address_groups.append(
                IRAddressGroup(
                    name=group.name,
                    members=group.member,
                    description=group.comment,
                )
            )

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    def _clean_port_range(
        self,
        port_str: str,
    ) -> str:
        """
        Extract destination port from FortiGate
        destination:source port syntax.
        """

        if not port_str:
            return IR_KEYWORD_ANY

        if ":" in port_str:
            destination_port = (
                port_str.split(
                    ":",
                    1,
                )[0].strip()
            )
        else:
            destination_port = (
                port_str.strip()
            )

        if destination_port in {
            "0-65535",
            "0-65335",
            "0",
        }:
            return "1-65535"

        return destination_port

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
            result.append(
                IRServicePort(
                    protocol=protocol,
                    port=(
                        self._clean_port_range(
                            part
                        )
                    ),
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
        for service in self.fg.services:
            ports = []

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

            if service.protocol in [
                "ICMP",
                "ICMP6",
            ]:
                ports.append(
                    IRServicePort(
                        protocol=(
                            ServiceProtocol.ICMP
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
                service.protocol == "IP"
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

            if not ports:
                ports.append(
                    IRServicePort(
                        protocol=(
                            ServiceProtocol.TCP
                        ),
                        port=IR_KEYWORD_ANY,
                    )
                )

            self.ir.services.append(
                IRService(
                    name=service.name,
                    ports=ports,
                    description=service.comment,
                )
            )

        for group in self.fg.service_groups:
            self.ir.service_groups.append(
                IRServiceGroup(
                    name=group.name,
                    members=group.member,
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
                )
            )

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def _transform_policies(
        self,
    ) -> None:
        for policy in self.fg.policies:
            from_zones = list(
                dict.fromkeys(
                    self._intf_to_zone.get(
                        intf,
                        "untrust",
                    )
                    for intf in policy.srcintf
                    if intf != "any"
                )
            )

            to_zones = list(
                dict.fromkeys(
                    self._intf_to_zone.get(
                        intf,
                        "untrust",
                    )
                    for intf in policy.dstintf
                    if intf != "any"
                )
            )

            if (
                "any" in policy.srcintf
                or not from_zones
            ):
                from_zones = [
                    IR_KEYWORD_ANY
                ]

            if (
                "any" in policy.dstintf
                or not to_zones
            ):
                to_zones = [
                    IR_KEYWORD_ANY
                ]

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
                    or "default"
                )
                ir_policy.ips_sensor = (
                    policy.ips_sensor
                    or "default"
                )
                ir_policy.webfilter = (
                    policy.webfilter_profile
                    or "default"
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
                                or "default"
                            ),
                            vulnerability=(
                                policy.ips_sensor
                                or "default"
                            ),
                            anti_spyware="default",
                            url_filtering=(
                                policy.webfilter_profile
                                or "default"
                            ),
                            file_blocking=(
                                "basic-file-blocking"
                            ),
                            wildfire="default",
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
            source_requires_review = False

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

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    def _mask_to_cidr_str(
        self,
        ip_mask_str: str,
    ) -> str:
        """
        Convert FortiGate 'IP MASK' notation to CIDR.
        """

        parts = ip_mask_str.split()

        if len(parts) == 2:
            ip_value, mask = parts

            try:
                bits = sum(
                    bin(
                        int(octet)
                    ).count("1")
                    for octet
                    in mask.split(".")
                )

                return (
                    f"{ip_value}/{bits}"
                )

            except Exception:
                return (
                    f"{ip_value}/0"
                )

        if "/" in ip_mask_str:
            return ip_mask_str

        return (
            f"{ip_mask_str}/32"
        )

    def _transform_routes(
        self,
    ) -> None:
        for route in self.fg.static_routes:
            dst_raw = (
                route.dst
                or "0.0.0.0 0.0.0.0"
            )

            dst_cidr = (
                self._mask_to_cidr_str(
                    dst_raw
                )
            )

            self.ir.routes.append(
                IRRoute(
                    name=(
                        f"route_{route.id}"
                    ),
                    destination=dst_cidr,
                    interface=route.device,
                    next_hop=route.gateway,
                    metric=route.distance,
                    description=route.comment,
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
