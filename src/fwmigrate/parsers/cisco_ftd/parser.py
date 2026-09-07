from __future__ import annotations

import ipaddress
import re
from typing import Optional

from fwmigrate.ir.core import IRConfig, IRInterface, IRMetadata
from fwmigrate.parsers.cisco_ftd.model import CiscoFTDConfig, CiscoFTDInterface, CiscoFTDManagementSetting


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
                record.ipv6_addresses.append(" ".join(parts[2:]))
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
            index += 1
        if record.nameif and record.nameif.lower() == "diagnostic":
            self.config.diagnostic_interface = record.name
        self.config.interfaces.append(record)
        return index

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
                ipv6_source_settings={"addresses": list(item.ipv6_addresses)},
                migration_status=item.migration_status,
                requires_manual_review=item.requires_manual_review or bool(parse_error),
                parse_errors=[parse_error] if parse_error else [],
                source_attributes={
                    **item.source_attributes,
                    "nameif": item.nameif,
                    "management_only": item.management_only,
                    "security_level": item.security_level,
                    "standby_ip": item.standby_ip,
                    "raw_lines": item.raw_lines,
                    "ftd_policy_zone_not_inferred": True,
                },
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
        )
