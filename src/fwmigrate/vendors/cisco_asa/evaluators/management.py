"""ASA management command evaluation."""

from __future__ import annotations

import ipaddress
import re
from fwmigrate.vendors.cisco_asa.acl_parser import parse_endpoint
from fwmigrate.vendors.cisco_asa.model.management import CiscoDNSServerGroup, CiscoEnableCredential, CiscoICMPManagementRule, CiscoLoggingSetting, CiscoManagementAccessRule, CiscoManagementSetting, CiscoNTPServer, CiscoSNMPSetting
from fwmigrate.vendors.cisco_asa.net_utils import normalize_ipv4_network
from fwmigrate.extraction.sanitize import sanitize_raw_text
from . import _mark_explicit


class ManagementEvaluator:

    def _parse_ntp_authentication_command(self, line: str, line_number: int) -> bool:
        lower = line.lower().strip()
        negated = lower.startswith("no ")
        effective = line[3:].strip() if negated else line.strip()
        parts = effective.split()
        safe = sanitize_raw_text(line)

        setting = None
        secret_present = False
        if [part.lower() for part in parts] == ["ntp", "authenticate"]:
            setting = "ntp authenticate"
        elif len(parts) >= 3 and [part.lower() for part in parts[:2]] == ["ntp", "trusted-key"]:
            setting = f"ntp trusted-key {parts[2]}"
        elif len(parts) >= 3 and [part.lower() for part in parts[:2]] == ["ntp", "authentication-key"]:
            if not negated and len(parts) < 5:
                self._record_diagnostic(
                    line_number, line, "Malformed NTP authentication-key command", "ntp"
                )
            algorithm = parts[3] if len(parts) > 3 else None
            setting = " ".join(
                value for value in ("ntp authentication-key", parts[2], algorithm) if value
            )
            secret_present = not negated and len(parts) >= 5
        else:
            return False

        record = CiscoManagementSetting(
            name=f"ntp-auth:{line_number}",
            setting=setting,
            enabled=not negated,
            raw_lines=[safe],
            extraction_status="EXTRACTED" if setting is not None else "PARTIAL",
            requires_manual_review=False,
            explicit_fields={"setting", "enabled"},
            source_attributes={"raw_command": safe, "secret_present": secret_present},
        )
        self.config.management_settings.append(self._with_source_context(record, line_number))
        return True

    def _legacy_management(self, line: str) -> None:
        self.config.management_settings.append(CiscoManagementSetting(
            name=line.split()[0], setting=line.split()[0], raw_lines=[sanitize_raw_text(line)],
            source_attributes={"raw_command": sanitize_raw_text(line)}))

    def _parse_management_command_base(self, line: str, line_number: int) -> None:
        parts = line.split(); lower = line.lower(); command = parts[0].lower()
        if self._parse_ntp_authentication_command(line, line_number):
            return
        self._legacy_management(line)
        system = self.config.system_settings
        system.raw_lines.append(sanitize_raw_text(line))
        system.source_attributes.setdefault("raw_commands", []).append(sanitize_raw_text(line))
        if command == "hostname" and len(parts) == 2:
            system.hostname = parts[1]; system.extraction_status = "EXTRACTED"; system.requires_manual_review = False; return
        if lower == "no logging enable":
            self.config.logging_settings.append(CiscoLoggingSetting(name=f"logging:{line_number}", setting_type="enable", enabled=False, raw_line=sanitize_raw_text(line), raw_lines=[sanitize_raw_text(line)], source_order=line_number))
            return
        if lower.startswith("domain-name ") and len(parts) == 2:
            system.domain_name = parts[1]
            self.config.dns_settings.domain_name = parts[1]
            return
        if lower.startswith("clock timezone ") and len(parts) >= 4:
            system.timezone_name = parts[2]
            try: system.timezone_offset = int(parts[3])
            except ValueError: system.extraction_status = "PARSE_ERROR"; system.requires_manual_review = True; self._record_diagnostic(line_number, line, "Malformed timezone offset", "timezone")
            if len(parts) >= 5 and parts[4].lstrip("-").isdigit(): system.source_attributes["timezone_minutes"] = int(parts[4])
            return
        if lower.startswith("management-access ") and len(parts) == 2:
            system.management_access_interface = parts[1]; return
        if lower.startswith("http server ") and len(parts) == 3:
            self.config.management_settings.append(CiscoManagementSetting(
                name=f"http-server:{line_number}", setting="http server",
                enabled=parts[2].lower() == "enable", raw_lines=[sanitize_raw_text(line)],
                source_attributes={"raw_command": sanitize_raw_text(line)}))
            return
        same = re.fullmatch(r"same-security-traffic permit (inter|intra)-interface", lower)
        if same:
            setattr(system, f"same_security_{same.group(1)}", True); return
        if lower.startswith("ntp server "):
            item = CiscoNTPServer(name=f"ntp:{line_number}", server=parts[2] if len(parts) > 2 else None, source_order=line_number, raw_line=sanitize_raw_text(line), raw_lines=[sanitize_raw_text(line)], source_attributes={"raw_command": sanitize_raw_text(line)})
            try: ipaddress.ip_address(item.server or "")
            except ValueError: item.extraction_status = "PARSE_ERROR"; item.requires_manual_review = True; item.review_reasons.append("NTP server must be an IP address"); self._record_diagnostic(line_number, line, item.review_reasons[0], "ntp")
            for pos, token in enumerate(parts[3:], 3):
                if token.lower() in {"prefer", "source"} and token.lower() == "prefer": item.prefer = True
                elif token.lower() == "source" and pos + 1 < len(parts): item.interface = parts[pos + 1]
                elif token.lower() == "key" and pos + 1 < len(parts): item.key_id = parts[pos + 1]
            self.config.ntp_servers.append(item); return
        if command in {"ssh", "http", "telnet"}:
            ipv6_form = len(parts) >= 3 and ":" in parts[1]
            item = CiscoManagementAccessRule(
                name=f"{command}:{line_number}",
                protocol=command,
                source=parts[1] if len(parts) > 1 else None,
                mask_or_prefix=None if ipv6_form else (parts[2] if len(parts) > 2 else None),
                interface=(parts[2] if ipv6_form and len(parts) > 2 else
                           parts[3] if not ipv6_form and len(parts) > 3 else None),
                address_family="ipv6" if ipv6_form else "ipv4",
                raw_line=sanitize_raw_text(line),
                raw_lines=[sanitize_raw_text(line)],
                source_order=line_number,
                source_attributes={"raw_command": sanitize_raw_text(line)},
            )
            valid = True
            if ipv6_form:
                try:
                    valid = ipaddress.ip_network(item.source or "", strict=False).version == 6
                except ValueError:
                    valid = False
                if not item.interface:
                    valid = False
                reason = "Invalid management source IPv6 prefix"
            else:
                valid = len(parts) >= 4 and normalize_ipv4_network(
                    item.source or "", item.mask_or_prefix or ""
                ) is not None
                reason = "Invalid management source IPv4 address/netmask"
            if not valid:
                item.extraction_status = "PARSE_ERROR"
                item.requires_manual_review = True
                item.review_reasons.append(reason)
                self._record_diagnostic(line_number, line, reason, command)
            if "port" in [x.lower() for x in parts]:
                pos = [x.lower() for x in parts].index("port")
                if pos + 1 < len(parts) and parts[pos + 1].isdigit():
                    item.port = int(parts[pos + 1])
            self.config.management_access_rules.append(
                self._with_source_context(item, line_number)
            )
            return
        if lower.startswith("snmp-server "):
            item = CiscoSNMPSetting(name=f"snmp:{line_number}", setting_type="command", raw_line=sanitize_raw_text(line), raw_lines=[sanitize_raw_text(line)], source_order=line_number, source_attributes={"raw_command": sanitize_raw_text(line)})
            if len(parts) > 1 and parts[1].lower() in {"location", "contact"}:
                item.setting_type = parts[1].lower(); setattr(item, item.setting_type, line.split(None, 2)[2] if len(parts) > 2 else "")
            elif len(parts) > 2 and parts[1].lower() == "host":
                item.setting_type = "host"; item.interface, item.host = parts[2], parts[3] if len(parts) > 3 else None
                item.community_present = len(parts) > 4
                if "version" in [x.lower() for x in parts]: item.version = parts[[x.lower() for x in parts].index("version") + 1]
                if "username" in [x.lower() for x in parts]: item.username = parts[[x.lower() for x in parts].index("username") + 1]
            elif len(parts) > 1 and parts[1].lower() == "community": item.setting_type = "community"; item.community_present = True
            else: item.extraction_status = "PARTIAL"; item.requires_manual_review = True; item.review_reasons.append("Unsupported SNMP syntax")
            self.config.snmp_settings.append(item); return
        if lower.startswith("logging "):
            item = CiscoLoggingSetting(name=f"logging:{line_number}", setting_type=parts[1] if len(parts)>1 else "command", raw_line=sanitize_raw_text(line), raw_lines=[sanitize_raw_text(line)], source_order=line_number, source_attributes={"raw_command": sanitize_raw_text(line)})
            if lower == "logging enable": item.enabled = True; item.setting_type = "enable"
            elif lower == "no logging enable": item.enabled = False; item.setting_type = "enable"
            elif len(parts) > 2 and parts[1].lower() == "host": item.setting_type = "host"; item.interface, item.host = parts[2], parts[3] if len(parts)>3 else None
            elif len(parts) > 2 and parts[1].lower() in {"buffered", "trap", "console", "monitor"}: item.severity = parts[2]
            else: item.extraction_status = "PARTIAL"; item.requires_manual_review = True
            self.config.logging_settings.append(item); return
        if command == "enable":
            item = CiscoEnableCredential(name=f"enable:{line_number}", password_present="password" in lower, secret_present="secret" in lower, encrypted="encrypted" in lower, raw_line=sanitize_raw_text(line), raw_lines=[sanitize_raw_text(line)], source_order=line_number, source_attributes={"raw_command": sanitize_raw_text(line)})
            self.config.enable_credentials.append(item); return

    def _parse_icmp_management_command(self, line: str, line_number: int) -> None:
        parts = line.split()
        if len(parts) < 4:
            self._record_diagnostic(line_number, line, "Malformed ICMP management rule", "icmp")
            return
        action, interface = parts[1].lower(), parts[-1]
        endpoint, index = parse_endpoint(parts[2:-1], 0)
        icmp_type = parts[2 + index] if index < len(parts[2:-1]) else None
        rule = CiscoICMPManagementRule(
            name=f"icmp:{line_number}", action=action,
            source=endpoint.value if endpoint.valid else None,
            interface=interface, icmp_type=icmp_type, raw_line=sanitize_raw_text(line),
            raw_lines=[sanitize_raw_text(line)], source_order=line_number,
            source_attributes={"raw_command": sanitize_raw_text(line), "source_endpoint": endpoint.raw},
        )
        if not endpoint.valid:
            rule.extraction_status = "PARSE_ERROR"
            rule.requires_manual_review = True
            rule.review_reasons.append("Invalid ICMP management source selector")
            self._record_diagnostic(line_number, line, rule.review_reasons[0], "icmp")
        self.config.icmp_management_rules.append(self._with_source_context(rule, line_number))

    def _parse_management_command(self, line: str, line_number: int) -> None:
        from ..parser_mpf import _parse_management_command
        return _parse_management_command(self, line, line_number)

    def _parse_hostname_line(self, line):
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            self.config.hostname = parts[1]
            self.config.system_settings.hostname = parts[1]
            _mark_explicit(self.config, "hostname")
            _mark_explicit(self.config.system_settings, "hostname")

    def _parse_sysopt_permit_vpn(self, line, line_number, enabled):
        record = CiscoManagementSetting(
            name=f"sysopt-connection-permit-vpn:{line_number}",
            setting="sysopt connection permit-vpn",
            enabled=enabled,
            raw_lines=[sanitize_raw_text(line)],
            explicit_fields={"setting", "enabled"},
            source_attributes={"raw_command": sanitize_raw_text(line)},
        )
        self.config.management_settings.append(self._with_source_context(record, line_number))

    def _parse_dns_server_group(self, lines, i, line_number, line, dns_group):
        group = CiscoDNSServerGroup(
            name=dns_group.group(1), source_context=self._line_contexts.get(line_number),
            raw_lines=[line], source_order=line_number,
            source_attributes={"raw_command": line, "raw_commands": [line]},
            extraction_status="PARTIAL", requires_manual_review=False,
        )
        i += 1
        while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
            child = lines[i].strip()
            safe_child = sanitize_raw_text(child)
            group.raw_lines.append(safe_child)
            group.child_order.append(safe_child)
            group.source_attributes["raw_commands"].append(safe_child)
            tokens = child.split()
            key, values = tokens[0].lower(), tokens[1:] if tokens else ("", [])
            group.raw_settings.append({"key": key, "values": values, "line_number": i + 1, "raw": safe_child})
            if key == "retries" and len(values) == 1 and values[0].isdigit():
                group.retries = int(values[0])
            elif key == "timeout" and len(values) == 1 and values[0].isdigit():
                group.timeout = int(values[0])
            elif key in {"expire-entry-timer", "poll-timer"} and values and values[-1].isdigit():
                setattr(group, "expire_entry_timer" if key == "expire-entry-timer" else "poll_timer", int(values[-1]))
            elif key in {"retries", "timeout", "expire-entry-timer", "poll-timer"}:
                group.extraction_status = "PARSE_ERROR"
                group.requires_manual_review = True
                group.review_reasons.append(f"Malformed DNS {key}")
                self._record_diagnostic(i + 1, child, f"Malformed DNS {key}", "dns", group.name)
            elif key not in {"name-server", "domain-name"}:
                group.requires_manual_review = True
                group.review_reasons.append("Unsupported DNS server-group child retained")
            match = re.match(r"^name-server\s+(\S+)", child, re.IGNORECASE)
            if match:
                address = match.group(1)
                try:
                    ipaddress.ip_address(address)
                except ValueError:
                    group.extraction_status = "PARSE_ERROR"
                    group.review_reasons.append("DNS name-server must be an IP address")
                    self._record_diagnostic(i + 1, child, "Malformed DNS name-server address", "dns", group.name)
                else:
                    group.name_servers.append(address)
            domain = re.match(r"^domain-name\s+(.+)$", child, re.IGNORECASE)
            if domain:
                group.domain_name = domain.group(1).strip()
            i += 1
        self.config.dns_server_groups.append(group)
        return i

    def _parse_no_http_server(self, line, line_number):
        self._parse_management_command(line[3:].strip(), line_number)
        self.config.management_settings[-1].enabled = False
        self.config.management_settings[-1].raw_lines = [sanitize_raw_text(line)]
        self.config.management_settings[-1].source_attributes["raw_command"] = sanitize_raw_text(line)

    def _parse_dns_group_selection(self, line):
        self.config.dns_settings.default_server_group = line.split()[1]
        self.config.dns_settings.command_history.append(sanitize_raw_text(line))
