from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from fwmigrate.capabilities.schema import CapabilityStatus
from fwmigrate.ir.enums import ServiceProtocol
from fwmigrate.ir.service import IRService, IRServiceGroup, IRServicePort


@dataclass(frozen=True)
class ServiceCapabilityResult:
    status: CapabilityStatus
    reasons: tuple[str, ...] = ()

    @property
    def reason(self) -> str | None:
        return "; ".join(self.reasons) or None

    @property
    def supported(self) -> bool:
        return self.status == CapabilityStatus.SUPPORTED

    @property
    def requires_lowering(self) -> bool:
        return self.status == CapabilityStatus.PARTIAL

    @property
    def requires_manual_review(self) -> bool:
        return self.status in {
            CapabilityStatus.UNSUPPORTED,
            CapabilityStatus.MANUAL_REVIEW,
        }


@dataclass(frozen=True)
class ServiceCapabilities:
    supports_sctp: bool = False
    supports_icmp: bool = False
    supports_icmp6: bool = False
    supports_ip_protocol_number: bool = False
    supports_source_ports: bool = False
    supports_destination_port_ranges: bool = False
    supports_nested_groups: bool = False

    def evaluate_service(self, service: IRService) -> ServiceCapabilityResult:
        if (
            service.requires_manual_review
            or service.migration_status != "NORMALIZED"
            or service.source_unmodeled_semantic_settings
        ):
            return ServiceCapabilityResult(
                CapabilityStatus.MANUAL_REVIEW,
                (f"service '{service.name}' requires manual review",),
            )

        manual_review: list[str] = []
        unsupported: list[str] = []
        lowering: list[str] = []
        for port in service.ports:
            protocol = _protocol(port)
            if protocol == ServiceProtocol.SCTP and not self.supports_sctp:
                unsupported.append("SCTP")
            elif protocol == ServiceProtocol.ICMP and not self.supports_icmp:
                unsupported.append("ICMP")
            elif protocol == ServiceProtocol.ICMPV6 and not self.supports_icmp6:
                unsupported.append("ICMP6")
            elif protocol == ServiceProtocol.IP:
                if service.source_protocol_number is None:
                    manual_review.append("arbitrary IP protocol without a protocol number")
                elif not self.supports_ip_protocol_number:
                    unsupported.append("arbitrary IP protocol numbers")

            if port.source_port and not self.supports_source_ports:
                unsupported.append("source-port constraints")
            if _is_port_range(port.port) and not self.supports_destination_port_ranges:
                lowering.append("destination-port ranges")

        if manual_review:
            return ServiceCapabilityResult(
                CapabilityStatus.MANUAL_REVIEW,
                tuple(dict.fromkeys(manual_review)),
            )
        if unsupported:
            return ServiceCapabilityResult(
                CapabilityStatus.UNSUPPORTED,
                tuple(dict.fromkeys(unsupported)),
            )
        if lowering:
            return ServiceCapabilityResult(
                CapabilityStatus.PARTIAL,
                tuple(dict.fromkeys(lowering)),
            )
        return ServiceCapabilityResult(CapabilityStatus.SUPPORTED)

    def evaluate_group(
        self,
        group: IRServiceGroup,
        groups: Iterable[IRServiceGroup] = (),
    ) -> ServiceCapabilityResult:
        if (
            group.requires_manual_review
            or group.migration_status != "NORMALIZED"
            or group.unsafe_members
        ):
            return ServiceCapabilityResult(
                CapabilityStatus.MANUAL_REVIEW,
                (f"service group '{group.name}' requires manual review",),
            )
        if not self.supports_nested_groups:
            nested_names = {
                item.name
                for item in groups
                if item.source_context == group.source_context
            }
            if any(member in nested_names for member in group.members):
                return ServiceCapabilityResult(
                    CapabilityStatus.PARTIAL,
                    ("nested service groups",),
                )
        return ServiceCapabilityResult(CapabilityStatus.SUPPORTED)

    def evaluate(
        self,
        item: IRService | IRServiceGroup,
        groups: Iterable[IRServiceGroup] = (),
    ) -> ServiceCapabilityResult:
        if isinstance(item, IRService):
            return self.evaluate_service(item)
        if isinstance(item, IRServiceGroup):
            return self.evaluate_group(item, groups)
        raise TypeError(
            f"Expected canonical IR service or service group, got {type(item).__name__}"
        )


def _protocol(port: IRServicePort) -> ServiceProtocol:
    try:
        return ServiceProtocol(port.protocol)
    except ValueError:
        return ServiceProtocol.IP


def _is_port_range(port: str) -> bool:
    value = str(port).strip().lower()
    if value in {"", "any", "1-65535", "0-65535"}:
        return False
    start, separator, end = value.partition("-")
    return bool(separator and start.isdigit() and end.isdigit() and start != end)


_TARGET_SERVICE_CAPABILITIES = {
    "palo_alto": ServiceCapabilities(
        supports_icmp=True,
        supports_destination_port_ranges=True,
        supports_nested_groups=True,
    ),
    "fortigate": ServiceCapabilities(
        supports_sctp=True,
        supports_icmp=True,
        supports_icmp6=True,
        supports_ip_protocol_number=True,
        supports_source_ports=True,
        supports_destination_port_ranges=True,
        supports_nested_groups=True,
    ),
    "cisco_asa": ServiceCapabilities(
        supports_destination_port_ranges=True,
        supports_nested_groups=False,
    ),
    "checkpoint": ServiceCapabilities(
        supports_destination_port_ranges=True,
        supports_nested_groups=False,
    ),
    "juniper_srx": ServiceCapabilities(
        supports_icmp=True,
        supports_icmp6=True,
        supports_destination_port_ranges=True,
        supports_nested_groups=True,
    ),
}


def service_capabilities(target_vendor: str) -> ServiceCapabilities:
    return _TARGET_SERVICE_CAPABILITIES.get(target_vendor, ServiceCapabilities())


__all__ = [
    "ServiceCapabilities",
    "ServiceCapabilityResult",
    "service_capabilities",
]
