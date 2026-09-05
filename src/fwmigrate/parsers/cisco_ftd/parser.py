from __future__ import annotations

import re
from typing import Optional
from fwmigrate.ir.core import IRConfig, IRMetadata
from fwmigrate.parsers.cisco_ftd.model import CiscoFTDConfig, CiscoFTDManagementSetting


class CiscoFTDParser:
    """Small, independent FTD source foundation; it never routes through ASA parsing."""

    def __init__(self, content: str):
        self.content = content
        self.config = CiscoFTDConfig()

    def parse_raw(self) -> CiscoFTDConfig:
        for raw in self.content.splitlines():
            line = raw.strip()
            if not line or line.startswith(("!", ":", "#")):
                continue
            parts = line.split()
            if parts[0].lower() == "no" and re.match(r"^no\s+management-interface\s+convergence$", line, re.IGNORECASE):
                self.config.cmi_enabled = False
                self.config.management_settings.append(CiscoFTDManagementSetting(
                    name="no", setting="no", values=parts[1:], raw_lines=[line],
                    source_attributes={"raw_command": line, "negated": True},
                ))
                continue
            if parts[0].lower() == "no":
                self.config.management_settings.append(CiscoFTDManagementSetting(
                    name="no", setting="no", values=parts[1:], raw_lines=[line],
                    source_attributes={"raw_command": line, "negated": True},
                ))
                continue
            if re.match(r"^show\s+management-interface\s+convergence$", line, re.IGNORECASE):
                self.config.cmi_enabled = True
            elif re.match(r"^no\s+management-interface\s+convergence$", line, re.IGNORECASE):
                self.config.cmi_enabled = False
            elif len(parts) >= 7 and [item.lower() for item in parts[:4]] == ["configure", "network", "ipv4", "manual"]:
                self.config.management_ipv4, self.config.management_netmask, self.config.management_gateway = parts[4:7]
            elif len(parts) >= 3 and parts[0].lower() == "management" and parts[1].lower() == "gateway":
                self.config.management_gateway = parts[2]
            elif len(parts) >= 3 and parts[0].lower() == "management" and parts[1].lower() in {"dns", "dns-server"}:
                self.config.management_dns_servers.extend(parts[2:])
            elif len(parts) >= 3 and parts[:2] == ["configure", "ssh-access-list"]:
                self.config.ssh_access_list.append(" ".join(parts[2:]))
            elif len(parts) >= 3 and parts[0].lower() == "nameif" and parts[1].lower() == "diagnostic":
                self.config.diagnostic_interface = parts[2]
            if parts[0].lower() in {"configure", "management", "show-network-style"}:
                self.config.management_settings.append(CiscoFTDManagementSetting(
                    name=parts[0], setting=" ".join(parts[:2]), values=parts[2:],
                    raw_lines=[line], source_attributes={"raw_command": line},
                ))
        return self.config

    def parse(self) -> IRConfig:
        cfg = self.parse_raw()
        return IRConfig(metadata=IRMetadata(
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
        ))
