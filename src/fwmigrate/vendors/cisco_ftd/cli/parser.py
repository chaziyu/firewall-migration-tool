from __future__ import annotations

import re
import ipaddress
from typing import Dict, Optional

from ..model import (
    CiscoFTDConfig, CiscoFTDInterface, CiscoFTDIPv6Address,
    CiscoFTDManagementSetting, CiscoFTDStaticRoute,
)


FTD_TEXT_GENERATION_BLOCK_REASON = (
    "FTD text input does not contain an authoritative managed NAT/policy representation"
)


class CiscoFTDParser:
    """Independent FTD management-source parser; never routes through ASA parsing."""

    def __init__(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        self.content = content
        self.zone_mapping = zone_mapping or {}
        self.config = CiscoFTDConfig()

    def _parse_interface_block(self, lines: list[str], index: int) -> int:
        line = lines[index].strip()
        match = re.fullmatch(r"interface\s+(\S+)", line, re.I)
        if not match:
            return index + 1
        record = CiscoFTDInterface(
            name=match.group(1),
            raw_lines=[line],
            source_attributes={"raw_header": line, "source_line_number": index + 1},
        )
        index += 1
        while index < len(lines) and lines[index][:1].isspace() and not lines[index].strip().startswith(("!", ":", "#")):
            child = lines[index].strip()
            record.raw_lines.append(child)
            parts = child.split()
            lower_parts = [part.lower() for part in parts]
            lower = child.lower()
            if lower == "management-only":
                record.management_only = True
                record.explicit_fields.append("management_only")
            elif lower == "no management-only":
                record.management_only = False
                record.explicit_fields.append("management_only")
            elif len(parts) == 2 and lower_parts[0] == "nameif":
                record.nameif = parts[1]
                record.explicit_fields.append("nameif")
            elif len(parts) == 2 and lower_parts[0] == "security-level" and parts[1].isdigit():
                record.security_level = int(parts[1])
                record.explicit_fields.append("security_level")
            elif len(parts) >= 4 and lower_parts[:2] == ["ip", "address"]:
                record.ip, record.mask = parts[2], parts[3]
                record.explicit_fields.extend(("ip", "mask"))
                if "standby" in lower_parts:
                    pos = lower_parts.index("standby")
                    record.standby_ip = parts[pos + 1] if pos + 1 < len(parts) else None
                    record.explicit_fields.append("standby_ip")
            elif len(parts) >= 3 and lower_parts[:2] == ["ipv6", "address"]:
                value = parts[2]
                try:
                    address = ipaddress.IPv6Interface(value)
                    options = {part.lower() for part in parts[3:]}
                    standby = None
                    if "standby" in options:
                        position = lower_parts.index("standby")
                        standby = parts[position + 1] if position + 1 < len(parts) else None
                    record.ipv6_addresses.append(CiscoFTDIPv6Address(
                        address=str(address.ip), prefix_length=address.network.prefixlen,
                        standby=standby, eui64=True if "eui-64" in options else None,
                        link_local=True if "link-local" in options else None, raw=child,
                    ))
                    record.explicit_fields.append("ipv6_addresses")
                except ValueError:
                    record.source_attributes.setdefault("invalid_ipv6_addresses", []).append(child)
                    self.config.unsupported_evidence.append({
                        "source_path": "ftd-cli/interfaces",
                        "source_name": record.name,
                        "reason": "Invalid IPv6 interface address",
                    })
            elif len(parts) >= 2 and lower_parts[0] == "vlan" and parts[1].isdigit():
                record.vlan_id = int(parts[1])
                record.explicit_fields.append("vlan_id")
            elif lower_parts[:1] == ["channel-group"] and len(parts) >= 2 and parts[1].isdigit():
                record.etherchannel_id = int(parts[1])
                if len(parts) >= 4 and lower_parts[2] == "mode":
                    record.etherchannel_mode = parts[3]
                    record.explicit_fields.append("etherchannel_mode")
                record.explicit_fields.append("etherchannel_id")
            elif len(parts) == 2 and lower_parts[0] == "bridge-group" and parts[1].isdigit():
                record.bridge_group = int(parts[1])
                record.explicit_fields.append("bridge_group")
            elif len(parts) == 2 and lower_parts[0] == "mtu" and parts[1].isdigit():
                record.mtu = int(parts[1])
                record.explicit_fields.append("mtu")
            elif lower.startswith("description "):
                record.description = child.split(maxsplit=1)[1]
                record.explicit_fields.append("description")
            elif lower == "shutdown":
                record.shutdown = True
                record.explicit_fields.append("shutdown")
            elif lower == "no shutdown":
                record.shutdown = False
                record.explicit_fields.append("shutdown")
            else:
                record.source_attributes.setdefault("unmodeled_lines", []).append(child)
                self.config.unsupported_evidence.append({
                    "source_path": "ftd-cli/interfaces",
                    "source_name": record.name,
                    "reason": "Unsupported FTD interface command is source-preserved",
                })
            index += 1
        if record.nameif and record.nameif.lower() == "diagnostic":
            self.config.diagnostic_interface = record.name
        record.explicit_fields = list(dict.fromkeys(record.explicit_fields))
        self.config.interfaces.append(record)
        return index

    def _parse_static_route(self, line: str, line_number: int) -> None:
        parts = line.split()
        ipv6 = parts[0].lower() == "ipv6"
        offset = 1 if ipv6 else 0
        if len(parts) < offset + 4:
            self.config.static_routes.append(CiscoFTDStaticRoute(
                name=f"route_{line_number}", address_family="ipv6" if ipv6 else "ipv4", raw_line=line,
                source_attributes={"source_line_number": line_number},
            ))
            self.config.unsupported_evidence.append({
                "source_path": "ftd-cli/routes",
                "source_name": f"route_{line_number}",
                "reason": "Malformed FTD static route",
            })
            return
        interface = parts[offset + 1]
        destination = parts[offset + 2]
        mask_or_gateway = parts[offset + 3]
        mask = None if ipv6 else mask_or_gateway
        gateway_index = offset + 4 if not ipv6 else offset + 3
        gateway = parts[gateway_index] if gateway_index < len(parts) else None
        distance_index = gateway_index + 1
        distance = int(parts[distance_index]) if distance_index < len(parts) and parts[distance_index].isdigit() else None
        self.config.static_routes.append(CiscoFTDStaticRoute(
            name=f"route_{line_number}", interface=interface, destination=destination,
            mask=mask, gateway=gateway, address_family="ipv6" if ipv6 else "ipv4",
            administrative_distance=distance, raw_line=line,
            source_attributes={"source_line_number": line_number},
        ))

    def parse_raw(self) -> CiscoFTDConfig:
        self.config = CiscoFTDConfig()
        self.config.input_source_type = "ftd-text-evidence"
        self.config.source_plane = "ftd-cli"
        self.config.source_metadata = {"authoritative": "device CLI/text evidence"}
        lines = self.content.splitlines()
        index = 0
        while index < len(lines):
            raw = lines[index]
            line = raw.strip()
            if not line or line.startswith(("!", ":", "#")):
                index += 1
                continue
            if not raw[:1].isspace() and re.fullmatch(r"interface\s+\S+", line, re.I):
                index = self._parse_interface_block(lines, index)
                continue

            if re.match(r"^(?:ipv6\s+)?route(?:\s+|$)", line, re.I):
                self._parse_static_route(raw, index + 1)
                index += 1
                continue

            parts = line.split()
            lower_parts = [part.lower() for part in parts]
            if re.fullmatch(r"no\s+management-interface\s+convergence", line, re.I):
                self.config.cmi_enabled = False
                self.config.management_settings.append(CiscoFTDManagementSetting(
                    name="no", setting="management-interface convergence", values=[], raw_lines=[line],
                    source_attributes={"source_line_number": index + 1, "raw_command": line, "negated": True},
                ))
                index += 1
                continue
            if parts[0].lower() == "no":
                self.config.management_settings.append(CiscoFTDManagementSetting(
                    name="no", setting="no", values=parts[1:], raw_lines=[line],
                    source_attributes={"source_line_number": index + 1, "raw_command": line, "negated": True},
                ))
                index += 1
                continue
            if re.fullmatch(r"show\s+management-interface\s+convergence", line, re.I):
                self.config.cmi_enabled = True
            elif len(parts) >= 7 and lower_parts[:4] == ["configure", "network", "ipv4", "manual"]:
                self.config.management_ipv4, self.config.management_netmask, self.config.management_gateway = parts[4:7]
            elif len(parts) >= 3 and lower_parts[:2] == ["management", "gateway"]:
                self.config.management_gateway = parts[2]
            elif len(parts) >= 3 and lower_parts[0] == "management" and lower_parts[1] in {"dns", "dns-server"}:
                self.config.management_dns_servers.extend(parts[2:])
            elif len(parts) >= 3 and lower_parts[:2] == ["configure", "ssh-access-list"]:
                self.config.ssh_access_list.append(" ".join(parts[2:]))
            elif len(parts) >= 3 and lower_parts[:2] == ["nameif", "diagnostic"]:
                # Retain the repository's earlier management-source form for
                # compatibility; official LINA interface blocks are preferred.
                self.config.diagnostic_interface = parts[2]
            if lower_parts[0] in {"configure", "management", "show-network-style", "show"}:
                self.config.management_settings.append(CiscoFTDManagementSetting(
                    name=parts[0], setting=" ".join(parts[:2]), values=parts[2:],
                    raw_lines=[line], source_attributes={"source_line_number": index + 1, "raw_command": line},
                ))
            index += 1
        return self.config

    @staticmethod
    def _ipv4_interface(address: Optional[str], mask: Optional[str]) -> tuple[Optional[str], Optional[str]]:
        if not address or not mask:
            return None, None
        try:
            return str(ipaddress.IPv4Interface(f"{address}/{mask}")), None
        except ValueError:
            return None, f"Invalid management IPv4 address/netmask: {address} {mask}"
