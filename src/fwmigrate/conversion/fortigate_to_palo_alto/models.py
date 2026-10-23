"""Pair-specific FortiGate to Palo Alto migration-plan models."""

from dataclasses import dataclass, field
from enum import StrEnum


class PANMigrationStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    PARTIAL = "PARTIAL"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class MigrationSourceRef:
    source_vdom: str | None = None
    source_kind: str | None = None
    source_name: str | None = None
    source_policy_id: int | None = None


@dataclass(frozen=True, slots=True)
class MigrationIssue:
    code: str
    message: str
    status: PANMigrationStatus = PANMigrationStatus.MANUAL_REVIEW
    source: MigrationSourceRef = field(default_factory=MigrationSourceRef)


@dataclass(frozen=True, slots=True)
class PlannedPANItem:
    source_vdom: str | None = None
    source_kind: str | None = None
    source_object_type: str | None = None
    source_name: str | None = None
    source_policy_id: int | None = None
    target_vsys: str | None = None
    target_name: str | None = None
    status: PANMigrationStatus = PANMigrationStatus.MANUAL_REVIEW
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedAddress(PlannedPANItem):
    address_type: str | None = None
    value: str | None = None
    source_interface: str | None = None
    description: str | None = None


@dataclass(frozen=True, slots=True)
class PlannedAddressGroup(PlannedPANItem):
    members: tuple[str, ...] = ()
    description: str | None = None


@dataclass(frozen=True, slots=True)
class PlannedService(PlannedPANItem):
    protocol: str | None = None
    destination_port: str | None = None
    source_port: str | None = None
    description: str | None = None


@dataclass(frozen=True, slots=True)
class PlannedServiceGroup(PlannedPANItem):
    members: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedSchedule(PlannedPANItem):
    schedule_type: str | None = None
    weekly: tuple[tuple[str, str, str], ...] = ()
    daily: tuple[tuple[str, str], ...] = ()
    non_recurring: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedManagementProfile(PlannedPANItem):
    protocols: tuple[str, ...] = ()
    permitted_ips: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedInterface(PlannedPANItem):
    management_profile: str | None = None
    interface_family: str | None = None
    parent: str | None = None
    tag: int | None = None
    ipv4_addresses: tuple[str, ...] = ()
    virtual_router: str | None = None

    aggregate_members: tuple[str, ...] = ()
    lacp_mode: str | None = None


@dataclass(frozen=True, slots=True)
class PlannedZone(PlannedPANItem):
    interfaces: tuple[str, ...] = ()
    source_contributors: tuple[MigrationSourceRef, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedStaticRoute(PlannedPANItem):
    destination: str | None = None
    nexthop_type: str | None = None
    nexthop: str | None = None
    admin_distance: int | None = None
    priority: int | None = None
    interface: str | None = None
    virtual_router: str | None = None
    disabled: bool = False
    description: str | None = None


@dataclass(frozen=True, slots=True)
class PlannedDHCPServer(PlannedPANItem):
    interface: str | None = None
    mode: str | None = None
    lease_type: str | None = None
    lease_timeout: int | None = None
    gateway: str | None = None
    subnet_mask: str | None = None
    dns_primary: str | None = None
    dns_secondary: str | None = None
    ip_pools: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedSecurityRule(PlannedPANItem):
    profile_group: str | None = None
    from_zones: tuple[str, ...] = ()
    to_zones: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    applications: tuple[str, ...] = ()
    schedule: str | None = None
    action: str | None = None
    negate_source: bool = False
    negate_destination: bool = False
    disabled: bool = False
    description: str | None = None
    log_start: str | None = None
    log_end: str | None = None
    source_users: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedNATRule(PlannedPANItem):
    source_translation_type: str | None = None
    translated_addresses: tuple[str, ...] = ()
    source_interface_address: bool = False
    destination_translated_address: str | None = None
    destination_translated_port: str | None = None
    from_zones: tuple[str, ...] = ()
    to_zones: tuple[str, ...] = ()
    source_addresses: tuple[str, ...] = ()
    destination_addresses: tuple[str, ...] = ()
    service: str | None = None
    to_interface: str | None = None
    translation_interface: str | None = None

    @property
    def source_translation(self) -> str | None:
        if self.source_interface_address:
            return "dynamic-ip-and-port:interface-address"
        if self.source_translation_type and self.translated_addresses:
            return f"{self.source_translation_type}:{self.translated_addresses[0]}"
        return None

    @property
    def destination_translation(self) -> str | None:
        return f"static-ip:{self.destination_translated_address}" if self.destination_translated_address else None


@dataclass(frozen=True, slots=True)
class PlannedIKECryptoProfile(PlannedPANItem):
    encryption: str | None = None
    authentication: str | None = None
    dh_group: str | None = None
    lifetime_seconds: int | None = None
    dh_groups: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedIPsecCryptoProfile(PlannedPANItem):
    encryption: str | None = None
    authentication: str | None = None
    dh_group: str | None = None
    lifetime_seconds: int | None = None
    phase1_name: str | None = None


@dataclass(frozen=True, slots=True)
class PlannedIKEGateway(PlannedPANItem):
    interface: str | None = None
    local_address: str | None = None
    peer_address: str | None = None
    ike_version: str | None = None
    crypto_profile: str | None = None
    authentication_method: str | None = None


@dataclass(frozen=True, slots=True)
class PlannedVPNProxyID:
    source_name: str
    local: str | None = None
    remote: str | None = None
    protocol: str | None = None
    local_port: str | None = None
    remote_port: str | None = None
    crypto_profile: str | None = None


@dataclass(frozen=True, slots=True)
class PlannedIPsecTunnel(PlannedPANItem):
    interface: str | None = None
    ike_gateway: str | None = None
    proxy_ids: tuple[PlannedVPNProxyID, ...] = ()


@dataclass(frozen=True, slots=True)
class PANMigrationPlan:
    addresses: tuple[PlannedAddress, ...] = ()
    address_groups: tuple[PlannedAddressGroup, ...] = ()
    services: tuple[PlannedService, ...] = ()
    service_groups: tuple[PlannedServiceGroup, ...] = ()
    schedules: tuple[PlannedSchedule, ...] = ()
    interfaces: tuple[PlannedInterface, ...] = ()
    zones: tuple[PlannedZone, ...] = ()
    static_routes: tuple[PlannedStaticRoute, ...] = ()
    dhcp_servers: tuple[PlannedDHCPServer, ...] = ()
    security_rules: tuple[PlannedSecurityRule, ...] = ()
    nat_rules: tuple[PlannedNATRule, ...] = ()
    issues: tuple[MigrationIssue, ...] = field(default_factory=tuple)
    ike_crypto_profiles: tuple[PlannedIKECryptoProfile, ...] = ()
    ipsec_crypto_profiles: tuple[PlannedIPsecCryptoProfile, ...] = ()
    ike_gateways: tuple[PlannedIKEGateway, ...] = ()
    ipsec_tunnels: tuple[PlannedIPsecTunnel, ...] = ()
    management_profiles: tuple[PlannedManagementProfile, ...] = ()
    target_zone_references: tuple[tuple[str, str], ...] = ()
