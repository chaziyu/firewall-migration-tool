from __future__ import annotations

import ipaddress
import re
from typing import Optional

from fwmigrate.ir.core import IRConfig, IRInterface, IRMetadata, IRRoute
from fwmigrate.ir.enums import IRRouteNextHopType
from fwmigrate.parsers.cisco_ftd.model import (
    CiscoFTDConfig, CiscoFTDInterface, CiscoFTDIPv6Address,
    CiscoFTDManagementSetting, CiscoFTDStaticRoute,
)


class CiscoFTDParser:
    """Independent FTD management-source parser; never routes through ASA parsing."""

    def __init__(self, content: str):
        self.content = content
        self.config = CiscoFTDConfig()

    def _parse_interface_block(self, lines: list[str], index: int) -> int:
        line = lines[index].strip()
        match = re.fullmatch(r"interface\s+(\S+)", line, re.I)
        if not match:
            return index + 1
        record = CiscoFTDInterface(
            name=match.group(1),
            interface_type=self._interface_type(match.group(1)),
            parent_interface=match.group(1).rsplit(".", 1)[0] if "." in match.group(1) else None,
            vlan_id=int(match.group(1).rsplit(".", 1)[1]) if "." in match.group(1) and match.group(1).rsplit(".", 1)[1].isdigit() else None,
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
            elif lower == "no management-only":
                record.management_only = False
            elif len(parts) == 2 and lower_parts[0] == "nameif":
                record.nameif = parts[1]
            elif len(parts) == 2 and lower_parts[0] == "security-level" and parts[1].isdigit():
                record.security_level = int(parts[1])
            elif len(parts) >= 4 and lower_parts[:2] == ["ip", "address"]:
                record.ip, record.mask = parts[2], parts[3]
                if "standby" in lower_parts:
                    pos = lower_parts.index("standby")
                    record.standby_ip = parts[pos + 1] if pos + 1 < len(parts) else None
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
                        standby=standby, eui64="eui-64" in options,
                        link_local="link-local" in options, raw=child,
                    ))
                except ValueError:
                    record.source_attributes.setdefault("invalid_ipv6_addresses", []).append(child)
                    record.requires_manual_review = True
                    record.review_reasons.append("Invalid IPv6 interface address")
            elif len(parts) >= 2 and lower_parts[0] == "vlan" and parts[1].isdigit():
                record.vlan_id = int(parts[1])
            elif lower_parts[:1] == ["channel-group"] and len(parts) >= 2 and parts[1].isdigit():
                record.etherchannel_id = int(parts[1])
                record.etherchannel_mode = parts[3] if len(parts) >= 4 and lower_parts[2] == "mode" else None
                record.interface_type = "etherchannel-member"
            elif len(parts) == 2 and lower_parts[0] == "bridge-group" and parts[1].isdigit():
                record.bridge_group = int(parts[1])
            elif len(parts) == 2 and lower_parts[0] == "mtu" and parts[1].isdigit():
                record.mtu = int(parts[1])
            elif lower.startswith("description "):
                record.description = child.split(maxsplit=1)[1]
            elif lower == "shutdown":
                record.shutdown = True
            elif lower == "no shutdown":
                record.shutdown = False
            else:
                record.source_attributes.setdefault("unmodeled_lines", []).append(child)
                record.migration_status = "PARTIALLY_NORMALIZED"
                record.requires_manual_review = True
                record.review_reasons.append("Unsupported FTD interface command is source-preserved")
            index += 1
        if record.nameif and record.nameif.lower() == "diagnostic":
            self.config.diagnostic_interface = record.name
        self.config.interfaces.append(record)
        return index

    @staticmethod
    def _interface_type(name: str) -> str:
        lowered = name.lower()
        if lowered.startswith("bvi"):
            return "bvi"
        if lowered.startswith("port-channel") or lowered.startswith("etherchannel"):
            return "etherchannel"
        if "." in name:
            return "subinterface"
        if lowered.startswith("management"):
            return "management"
        return "physical"

    def _parse_static_route(self, line: str, line_number: int) -> None:
        parts = line.split()
        ipv6 = parts[0].lower() == "ipv6"
        offset = 1 if ipv6 else 0
        if len(parts) < offset + 4:
            self.config.static_routes.append(CiscoFTDStaticRoute(
                name=f"route_{line_number}", raw_line=line,
                migration_status="PARSE_ERROR", requires_manual_review=True,
                review_reasons=["Malformed FTD static route"],
            ))
            return
        interface = parts[offset + 1]
        destination = parts[offset + 2]
        mask_or_gateway = parts[offset + 3]
        mask = None if ipv6 else mask_or_gateway
        gateway_index = offset + 4 if not ipv6 else offset + 3
        gateway = parts[gateway_index] if gateway_index < len(parts) else None
        distance_index = gateway_index + 1
        distance = int(parts[distance_index]) if distance_index < len(parts) and parts[distance_index].isdigit() else None
        errors: list[str] = []
        try:
            if ipv6:
                destination = str(ipaddress.IPv6Network(destination, strict=False))
            else:
                destination = str(ipaddress.IPv4Network(f"{destination}/{mask}", strict=False))
        except ValueError:
            errors.append("Invalid FTD static route destination")
        if gateway:
            try:
                ipaddress.ip_address(gateway)
            except ValueError:
                errors.append("Invalid FTD static route next hop")
        self.config.static_routes.append(CiscoFTDStaticRoute(
            name=f"route_{line_number}", interface=interface, destination=destination,
            mask=mask, gateway=gateway, address_family="ipv6" if ipv6 else "ipv4",
            administrative_distance=distance, raw_line=line,
            migration_status="PARSE_ERROR" if errors else "NORMALIZED",
            requires_manual_review=bool(errors), review_reasons=errors,
        ))

    def parse_raw(self) -> CiscoFTDConfig:
        self.config = CiscoFTDConfig()
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

            if re.match(r"^(?:ipv6\s+)?route\s+", line, re.I):
                self._parse_static_route(line, index + 1)
                index += 1
                continue

            parts = line.split()
            lower_parts = [part.lower() for part in parts]
            if re.fullmatch(r"no\s+management-interface\s+convergence", line, re.I):
                self.config.cmi_enabled = False
                self.config.management_settings.append(CiscoFTDManagementSetting(
                    name="no", setting="management-interface convergence", values=[], raw_lines=[line],
                    source_attributes={"raw_command": line, "negated": True},
                ))
                index += 1
                continue
            if parts[0].lower() == "no":
                self.config.management_settings.append(CiscoFTDManagementSetting(
                    name="no", setting="no", values=parts[1:], raw_lines=[line],
                    source_attributes={"raw_command": line, "negated": True},
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
                    raw_lines=[line], source_attributes={"raw_command": line},
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

    def parse(self) -> IRConfig:
        cfg = self.parse_raw()
        interfaces: list[IRInterface] = []
        interface_names = {item.name for item in cfg.interfaces}
        interface_names.update(item.nameif for item in cfg.interfaces if item.nameif)
        for item in cfg.interfaces:
            ip_value, parse_error = self._ipv4_interface(item.ip, item.mask)
            interfaces.append(IRInterface(
                name=item.name,
                zone=None,
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
                source_attributes={
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
        )
