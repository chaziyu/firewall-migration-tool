from __future__ import annotations

from typing import List, Optional, Tuple

from fwmigrate.parsers.cisco_asa.acl_parser import parse_port_spec
from fwmigrate.parsers.cisco_asa.model import CiscoServicePort


SUPPORTED_PROTOCOLS = {"tcp", "udp", "sctp", "tcp-udp", "icmp", "icmp6", "icmpv6", "ip"}


def parse_service_clause(tokens: List[str]) -> Tuple[List[CiscoServicePort], Optional[str]]:
    """Parse tokens after ``service``/``service-object`` without guessing defaults."""
    if not tokens:
        return [], "Missing service protocol"
    protocol = tokens[0].lower()
    if protocol not in SUPPORTED_PROTOCOLS:
        return [], f"Unknown service protocol '{protocol}'"
    protocols = ["tcp", "udp"] if protocol == "tcp-udp" else ["icmp6" if protocol == "icmpv6" else protocol]
    index = 1
    source = destination = None
    icmp_type = None
    icmp_code = None
    while index < len(tokens):
        selector = tokens[index].lower()
        if selector in {"source", "destination"}:
            spec, next_index = parse_port_spec(tokens, index + 1)
            if spec is None or not spec.values:
                return [], f"Malformed {selector} port expression"
            if selector == "source":
                source = spec
            else:
                destination = spec
            index = next_index
        elif protocol in {"icmp", "icmp6", "icmpv6"} and icmp_type is None:
            icmp_type = tokens[index]
            if index + 1 < len(tokens) and tokens[index + 1].isdigit():
                icmp_code = int(tokens[index + 1])
                index += 2
            else:
                index += 1
        else:
            return [], f"Unmodeled service token '{tokens[index]}'"
    return [
        CiscoServicePort(
            protocol=item,
            source=source,
            destination=destination,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            raw=" ".join(tokens),
        )
        for item in protocols
    ], None
