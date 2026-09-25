from __future__ import annotations

from dataclasses import dataclass, field

from ..model.service import FGService
from ..model.source import FGConfig


@dataclass(frozen=True, slots=True)
class NormalizedService:
    name: str
    vdom: str

    protocol: str

    # Destination port/range.
    port: str | None = None

    # FortiGate can optionally constrain source ports.
    source_port: str | None = None

    protocol_number: int | None = None

    icmp_type: int | None = None
    icmp_code: int | None = None

    comment: str | None = None

    source_name: str | None = None

    generated: bool = False


@dataclass(frozen=True, slots=True)
class NormalizedServiceGroup:
    name: str
    vdom: str

    members: tuple[str, ...]

    comment: str | None = None

    generated: bool = False


@dataclass(frozen=True, slots=True)
class ServiceTransformIssue:
    vdom: str
    service: str
    message: str


@dataclass(slots=True)
class ServiceTransformResult:
    services: list[
        NormalizedService
    ] = field(default_factory=list)

    groups: list[
        NormalizedServiceGroup
    ] = field(default_factory=list)

    issues: list[
        ServiceTransformIssue
    ] = field(default_factory=list)


def transform_services(
    config: FGConfig,
) -> ServiceTransformResult:
    result = ServiceTransformResult()

    reserved_names: dict[
        str,
        set[str],
    ] = {}

    for service in config.services:
        reserved_names.setdefault(
            service.vdom,
            set(),
        ).add(
            service.name
        )

    for group in config.service_groups:
        reserved_names.setdefault(
            group.vdom,
            set(),
        ).add(
            group.name
        )

    # --------------------------------------------------------------
    # Custom services
    # --------------------------------------------------------------

    for service in config.services:
        normalized = _expand_service(
            service,
            result.issues,
        )

        # One canonical entry: retain original name.
        if len(normalized) == 1:
            item = normalized[0]

            result.services.append(
                NormalizedService(
                    name=service.name,
                    vdom=service.vdom,
                    protocol=item.protocol,
                    generated=False,
                    port=item.port,
                    source_port=item.source_port,
                    protocol_number=(
                        item.protocol_number
                    ),
                    icmp_type=item.icmp_type,
                    icmp_code=item.icmp_code,
                    comment=service.comment,
                    source_name=service.name,
                )
            )

            continue

        # Multiple protocol/port combinations:
        #
        # original service name becomes generated group.
        members: list[str] = []

        for index, item in enumerate(
            normalized,
            start=1,
        ):
            child_name = _generated_name(
                service.name,
                index=index,
                reserved=reserved_names[
                    service.vdom
                ],
            )

            members.append(
                child_name
            )

            result.services.append(
                NormalizedService(
                    name=child_name,
                    vdom=service.vdom,
                    protocol=item.protocol,
                    generated=True,
                    port=item.port,
                    source_port=item.source_port,
                    protocol_number=(
                        item.protocol_number
                    ),
                    icmp_type=item.icmp_type,
                    icmp_code=item.icmp_code,
                    comment=service.comment,
                    source_name=service.name,
                )
            )

        result.groups.append(
            NormalizedServiceGroup(
                name=service.name,
                vdom=service.vdom,
                members=tuple(members),
                comment=service.comment,
                generated=True,
            )
        )

    # --------------------------------------------------------------
    # Existing FortiGate service groups
    # --------------------------------------------------------------

    for group in config.service_groups:
        result.groups.append(
            NormalizedServiceGroup(
                name=group.name,
                vdom=group.vdom,
                members=tuple(
                    group.members
                ),
                comment=group.comment,
                generated=False,
            )
        )

    return result


def _expand_service(
    service: FGService,
    issues: list[ServiceTransformIssue],
) -> list[NormalizedService]:
    result: list[NormalizedService] = []

    selector = (service.protocol or "").strip().upper()
    if selector:
        active_fields = {
            "TCP": "tcp_portrange",
            "UDP": "udp_portrange",
            "SCTP": "sctp_portrange",
        }
        active_protocols = set(selector.split("/"))
        if selector == "TCP/UDP/SCTP":
            active_protocols = set(active_fields)
        allowed = {
            active_fields[name]
            for name in active_protocols
            if name in active_fields
        }
        if selector == "IP":
            allowed.add("protocol_number")
        elif selector in {"ICMP", "ICMP6"}:
            allowed.update({"icmptype", "icmpcode"})
        for field_name in (
            "protocol_number",
            "tcp_portrange",
            "udp_portrange",
            "sctp_portrange",
            "icmptype",
            "icmpcode",
        ):
            if getattr(service, field_name) is not None and field_name not in allowed:
                issues.append(
                    ServiceTransformIssue(
                        vdom=service.vdom,
                        service=service.name,
                        message=(
                            f"{field_name.replace('_', '-')} is configured but "
                            f"inactive for protocol {selector}."
                        ),
                    )
                )

        if selector == "IP":
            return [NormalizedService(
                name="", vdom=service.vdom, protocol="ip",
                protocol_number=service.protocol_number, source_name=service.name,
            )]
        if selector in {"ICMP", "ICMP6"}:
            return [NormalizedService(
                name="", vdom=service.vdom, protocol=selector.lower(),
                icmp_type=service.icmptype, icmp_code=service.icmpcode,
                source_name=service.name,
            )]

        selected_ports = [
            (name.lower(), getattr(service, field_name))
            for name, field_name in active_fields.items()
            if name in active_protocols
        ]
    else:
        selected_ports = [
            ("tcp", service.tcp_portrange),
            ("udp", service.udp_portrange),
            ("sctp", service.sctp_portrange),
        ]

    for protocol, raw_ports in selected_ports:
        for token in _port_tokens(
            raw_ports
        ):
            port, source_port = (
                _parse_port_token(token)
            )

            result.append(
                NormalizedService(
                    name="",
                    vdom=service.vdom,
                    protocol=protocol,
                    port=port,
                    source_port=source_port,
                    source_name=service.name,
                )
            )

    if result:
        return result

    protocol = (service.protocol or "").strip()

    if not selector and service.protocol_number is not None:
        return [
            NormalizedService(
                name="",
                vdom=service.vdom,
                protocol="ip",
                protocol_number=(
                    service.protocol_number
                ),
                source_name=service.name,
            )
        ]

    if not selector and protocol.upper() in {
        "ICMP",
        "ICMP6",
    }:
        return [
            NormalizedService(
                name="",
                vdom=service.vdom,
                protocol=protocol.lower(),
                icmp_type=service.icmptype,
                icmp_code=service.icmpcode,
                source_name=service.name,
            )
        ]

    protocols = [
        value.strip().lower()
        for value in protocol.split("/")
        if value.strip()
    ]

    if not protocols:
        protocols = [
            "unknown"
        ]

    return [
        NormalizedService(
            name="",
            vdom=service.vdom,
            protocol=value,
            source_name=service.name,
        )
        for value in protocols
    ]


def _port_tokens(
    raw: str | None,
) -> list[str]:
    if not raw:
        return []

    return [
        token
        for token in raw.replace(
            ",",
            " ",
        ).split()
        if token
    ]


def _parse_port_token(
    token: str,
) -> tuple[
    str,
    str | None,
]:
    """
    FortiGate port syntax may contain:

        443
        8000-8080
        443:1024-65535

    Keep destination and source constraints separate.
    """

    if ":" not in token:
        return (
            token,
            None,
        )

    destination, source = token.split(
        ":",
        1,
    )

    return (
        destination,
        source or None,
    )


def _generated_name(
    source_name: str,
    *,
    index: int,
    reserved: set[str],
) -> str:
    base = (
        f"{source_name}-{index}"
    )

    candidate = base
    suffix = 2

    while candidate in reserved:
        candidate = (
            f"{base}-{suffix}"
        )
        suffix += 1

    reserved.add(candidate)

    return candidate
