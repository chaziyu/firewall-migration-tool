from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import date
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fwmigrate.core.constants import IR_KEYWORD_ANY, IR_KEYWORD_ANY_IPV4, IR_KEYWORD_ANY_IPV6
from fwmigrate.ir.core import (
    IRAddress,
    IRAddressGroup,
    IRConfig,
    IRInterface,
    IRMetadata,
    IRNATRule,
    IRPolicy,
    IRRoute,
    IRSchedule,
    IRService,
    IRServiceGroup,
    IRServicePort,
    IRZone,
)
from fwmigrate.ir.enums import AddressType, NATTranslationMode, NATType, PolicyAction, ServiceProtocol
from fwmigrate.parsers.cisco_asa.acl_parser import KNOWN_PROTOCOLS, parse_acl_binding, parse_acl_line
from fwmigrate.parsers.cisco_asa.model import (
    CiscoASAConfig,
    CiscoAccessRule,
    CiscoDiagnostic,
    CiscoAAARecord,
    CiscoAAAServerGroup, CiscoAAAServerHost, CiscoLocalUser,
    CiscoAAAAuthenticationRule, CiscoAAAAuthorizationRule, CiscoAAAAccountingRule,
    CiscoASAContext, CiscoConnectionControl, CiscoDHCPOption, CiscoDHCPRelay,
    CiscoDHCPRelayServer, CiscoDHCPServer, CiscoDNSServerGroup,
    CiscoFailoverSetting, CiscoManagementSetting, CiscoSystemSettings, CiscoNTPServer,
    CiscoManagementAccessRule, CiscoSNMPSetting, CiscoLoggingSetting, CiscoEnableCredential,
    CiscoFailoverConfig, CiscoFailoverGroup, CiscoFailoverInterfaceIP, CiscoFailoverMACAddress,
    CiscoClassMap, CiscoClassMapMatch, CiscoInspectAction, CiscoMPFConnectionAction,
    CiscoMPFPoliceAction, CiscoPolicyMapClass, CiscoTCPMap,
    CiscoCryptoMap,
    CiscoGroupPolicy,
    CiscoIKEPolicy,
    CiscoIKEv2Proposal,
    CiscoIPsecTransformSet,
    CiscoVPNAddressPool,
    CiscoInterface,
    CiscoIPv6Address,
    CiscoNamedGroup,
    CiscoNATRule,
    CiscoRouteMap,
    CiscoRouteMapRule,
    CiscoNetworkGroup,
    CiscoNetworkGroupMember,
    CiscoNetworkObject,
    CiscoNetworkServiceObject,
    CiscoPortSpec,
    CiscoServiceGroup,
    CiscoServiceGroupMember,
    CiscoServiceObject,
    CiscoServicePort,
    CiscoNamedGroupMember,
    CiscoStaticRoute,
    CiscoServicePolicy,
    CiscoPolicyMap,
    CiscoTunnelGroup,
    CiscoTimeRange,
    CiscoTimeRangeClause,
)
from fwmigrate.parsers.cisco_asa.net_utils import normalize_ipv4_network, parse_ipv4_netmask
from fwmigrate.parsers.cisco_asa.service_parser import parse_service_clause
from fwmigrate.parsers.cisco_asa.reference_validation import apply_reference_issues, validate_references
from fwmigrate.extraction.sanitize import sanitize_raw_text


def mask_to_cidr(mask: str) -> Optional[int]:
    """Backward-compatible strict mask helper. Invalid masks return ``None``."""
    return parse_ipv4_netmask(mask)


def _safe_name(prefix: str, expression: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_]+", "_", expression).strip("_").lower()
    clean = clean[:48] or "value"
    digest = hashlib.sha1(expression.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}_{clean}_{digest}"


class CiscoASAParser:
    """Deterministic offline parser for Cisco ASA running configuration."""

    def __init__(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        self.raw_lines = content.splitlines()
        self.zone_mapping = zone_mapping or {}
        self.config = CiscoASAConfig()
        self._nat_section_counts: Dict[str, int] = {}
        self._line_contexts: Dict[int, Optional[str]] = {}

    @staticmethod
    def _build_context_ownership(lines: List[str]) -> Dict[int, Optional[str]]:
        """Map mixed context sections without treating definition children as local config."""
        ownership: Dict[int, Optional[str]] = {}
        active: Optional[str] = None
        for index, raw in enumerate(lines):
            line = raw.strip()
            ownership[index + 1] = active
            if not line or line.startswith(("!", ":")) or raw[:1].isspace():
                continue
            switch = re.match(r"^changeto\s+context\s+(\S+)$", line, re.IGNORECASE)
            if switch:
                active = switch.group(1)
                ownership[index + 1] = active
                continue
            if re.match(r"^changeto\s+(?:system|admin)$", line, re.IGNORECASE):
                active = None if line.lower().endswith("system") else "admin"
                ownership[index + 1] = active
                continue
            context = re.match(r"^context\s+(\S+)$", line, re.IGNORECASE)
            if not context:
                continue
            next_index = index + 1
            while next_index < len(lines) and not lines[next_index].strip():
                next_index += 1
            has_definition_children = (
                next_index < len(lines)
                and not lines[next_index].strip().startswith(("!", ":"))
                and lines[next_index][:1].isspace()
            )
            active = None if has_definition_children else context.group(1)
            ownership[index + 1] = active
        return ownership

    def _with_source_context(self, record: Any, line_number: int) -> Any:
        context = self._line_contexts.get(line_number)
        if context is not None:
            if hasattr(record, "source_context"):
                record.source_context = context
            if hasattr(record, "source_attributes"):
                record.source_attributes["source_context"] = context
        return record

    def _record_unsupported(self, line_number: int, line: str, reason: str) -> None:
        self.config.unsupported_commands.append(
            {"line_number": line_number, "raw_line": sanitize_raw_text(line), "reason": reason}
        )

    def _record_diagnostic(
        self, line_number: int, line: str, reason: str, section: str,
        object_name: Optional[str] = None, migration_effect: str = "PARSE_ERROR",
    ) -> None:
        diagnostic = CiscoDiagnostic(
            line_number=line_number, section=section, object_name=object_name,
            raw_line=sanitize_raw_text(line), reason=reason, migration_effect=migration_effect,
            severity="error" if migration_effect == "PARSE_ERROR" else "warning",
        )
        self.config.diagnostics.append(diagnostic)
        if migration_effect == "PARSE_ERROR":
            self.config.parse_errors.append(diagnostic.model_dump())

    def _record_acl_consumer(self, acl_name: str, consumer_type: str, line_number: int, line: str) -> None:
        self.config.acl_consumers.setdefault(acl_name, []).append({
            "consumer_type": consumer_type, "line_number": line_number, "raw_line": line,
            "source_context": self._line_contexts.get(line_number),
        })

    def _legacy_management(self, line: str) -> None:
        self.config.management_settings.append(CiscoManagementSetting(
            name=line.split()[0], setting=line.split()[0], raw_lines=[sanitize_raw_text(line)],
            source_attributes={"raw_command": sanitize_raw_text(line)}))

    def _parse_management_command(self, line: str, line_number: int) -> None:
        parts = line.split(); lower = line.lower(); command = parts[0].lower()
        self._legacy_management(line)
        system = self.config.system_settings
        system.raw_lines.append(sanitize_raw_text(line))
        system.source_attributes.setdefault("raw_commands", []).append(sanitize_raw_text(line))
        if command == "hostname" and len(parts) == 2:
            system.hostname = parts[1]; system.migration_status = "NORMALIZED"; system.requires_manual_review = False; return
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
            except ValueError: system.migration_status = "PARSE_ERROR"; system.requires_manual_review = True; self._record_diagnostic(line_number, line, "Malformed timezone offset", "timezone")
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
            except ValueError: item.migration_status = "PARSE_ERROR"; item.requires_manual_review = True; item.review_reasons.append("NTP server must be an IP address"); self._record_diagnostic(line_number, line, item.review_reasons[0], "ntp")
            for pos, token in enumerate(parts[3:], 3):
                if token.lower() in {"prefer", "source"} and token.lower() == "prefer": item.prefer = True
                elif token.lower() == "source" and pos + 1 < len(parts): item.interface = parts[pos + 1]
                elif token.lower() == "key" and pos + 1 < len(parts): item.key_id = parts[pos + 1]
            self.config.ntp_servers.append(item); return
        if command in {"ssh", "http", "telnet"}:
            item = CiscoManagementAccessRule(name=f"{command}:{line_number}", protocol=command, source=parts[1] if len(parts)>1 else None, mask_or_prefix=parts[2] if len(parts)>2 else None, interface=parts[3] if len(parts)>3 else None, raw_line=sanitize_raw_text(line), raw_lines=[sanitize_raw_text(line)], source_order=line_number, source_attributes={"raw_command": sanitize_raw_text(line)})
            if len(parts) < 4:
                item.migration_status = "PARSE_ERROR"; item.requires_manual_review = True; item.review_reasons.append("Malformed management access rule"); self._record_diagnostic(line_number, line, item.review_reasons[0], command)
            elif normalize_ipv4_network(item.source or "", item.mask_or_prefix or "") is None:
                item.migration_status = "PARSE_ERROR"; item.requires_manual_review = True; item.review_reasons.append("Invalid management source IPv4 address/netmask"); self._record_diagnostic(line_number, line, item.review_reasons[0], command)
            if "port" in [x.lower() for x in parts]:
                pos = [x.lower() for x in parts].index("port")
                if pos + 1 < len(parts) and parts[pos + 1].isdigit(): item.port = int(parts[pos + 1])
            self.config.management_access_rules.append(item); return
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
            else: item.migration_status = "PARTIALLY_NORMALIZED"; item.requires_manual_review = True; item.review_reasons.append("Unsupported SNMP syntax")
            self.config.snmp_settings.append(item); return
        if lower.startswith("logging "):
            item = CiscoLoggingSetting(name=f"logging:{line_number}", setting_type=parts[1] if len(parts)>1 else "command", raw_line=sanitize_raw_text(line), raw_lines=[sanitize_raw_text(line)], source_order=line_number, source_attributes={"raw_command": sanitize_raw_text(line)})
            if lower == "logging enable": item.enabled = True; item.setting_type = "enable"
            elif lower == "no logging enable": item.enabled = False; item.setting_type = "enable"
            elif len(parts) > 2 and parts[1].lower() == "host": item.setting_type = "host"; item.interface, item.host = parts[2], parts[3] if len(parts)>3 else None
            elif len(parts) > 2 and parts[1].lower() in {"buffered", "trap", "console", "monitor"}: item.severity = parts[2]
            else: item.migration_status = "PARTIALLY_NORMALIZED"; item.requires_manual_review = True
            self.config.logging_settings.append(item); return
        if command == "enable":
            item = CiscoEnableCredential(name=f"enable:{line_number}", password_present="password" in lower, secret_present="secret" in lower, encrypted="encrypted" in lower, raw_line=sanitize_raw_text(line), raw_lines=[sanitize_raw_text(line)], source_order=line_number, source_attributes={"raw_command": sanitize_raw_text(line)})
            self.config.enable_credentials.append(item); return

    def _parse_failover_command(self, line: str, line_number: int, children: Optional[List[str]] = None) -> None:
        parts = line.split(); lower = line.lower(); cfg = self.config.failover_config
        safe = sanitize_raw_text(line); cfg.raw_lines.append(safe); cfg.source_attributes.setdefault("raw_commands", []).append(safe)
        setting = CiscoFailoverSetting(name="failover", setting=parts[0], migration_status="PARTIALLY_NORMALIZED", requires_manual_review=False, raw_lines=[safe], source_attributes={"raw_command": safe})
        self.config.failover_settings.append(setting)
        if lower in {"failover", "no failover"}: cfg.enabled = lower == "failover"
        elif len(parts) >= 4 and lower.startswith("failover lan unit "): cfg.unit_role = parts[3].lower()
        elif len(parts) >= 5 and lower.startswith("failover lan interface "): cfg.lan_interface_name, cfg.lan_interface = parts[3], parts[4]
        elif len(parts) >= 4 and lower.startswith("failover state link "): cfg.state_link_name, cfg.state_link_interface = (parts[3], parts[4]) if len(parts) > 4 else (None, parts[3])
        elif len(parts) >= 3 and lower.startswith("failover link "):
            cfg.stateful_link_name, cfg.stateful_link_interface = (parts[2], parts[3]) if len(parts) > 3 else (None, parts[2])
            cfg.state_link_name, cfg.state_link_interface = cfg.stateful_link_name, cfg.stateful_link_interface
        elif lower.startswith("failover key "): cfg.key_present = True
        elif len(parts) >= 5 and lower.startswith("failover interface ip "):
            standby_pos = next((pos for pos, value in enumerate(parts) if value.lower() == "standby"), None)
            prefix = parts[5] if len(parts) > 5 and parts[5].lower() != "standby" else None
            active = parts[4]
            family = "ipv6" if ":" in active else "ipv4"
            item = CiscoFailoverInterfaceIP(name=f"failover-ip:{line_number}", logical_name=parts[3], interface=parts[3], active_ip=active, netmask_or_prefix=prefix, address_family=family, standby_ip=parts[standby_pos + 1] if standby_pos is not None and standby_pos + 1 < len(parts) else None, raw_line=safe, raw_lines=[safe], source_order=line_number)
            for value in (item.active_ip, item.standby_ip):
                try: ipaddress.ip_interface(value or "") if "/" in (value or "") else ipaddress.ip_address(value or "")
                except ValueError: item.migration_status="PARSE_ERROR"; item.requires_manual_review=True; item.review_reasons.append("Malformed failover interface IP")
            cfg.interface_ips.append(item)
        elif len(parts) >= 5 and lower.startswith("failover mac address "):
            item = CiscoFailoverMACAddress(name=f"failover-mac:{line_number}", interface=parts[3], active_mac=parts[4], standby_mac=parts[6] if len(parts)>6 and parts[5].lower()=="standby" else None, raw_line=safe, raw_lines=[safe], source_order=line_number)
            if not all(re.fullmatch(r"[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}", x or "") for x in (item.active_mac, item.standby_mac) if x): item.migration_status="PARSE_ERROR"; item.requires_manual_review=True; item.review_reasons.append("Malformed failover MAC address")
            cfg.mac_addresses.append(item)
        elif lower.startswith("failover replication http"): cfg.replication_http = True
        elif len(parts) >= 3 and lower.startswith("failover polltime "): cfg.polltime = " ".join(parts[2:])
        elif len(parts) >= 3 and lower.startswith("failover holdtime "): cfg.holdtime = " ".join(parts[2:])
        elif len(parts) >= 3 and lower.startswith("failover timeout "): cfg.timeout = " ".join(parts[2:])
        elif len(parts) >= 3 and lower.startswith("failover group "):
            try: group_id = int(parts[2])
            except ValueError: group_id = None
            group = CiscoFailoverGroup(name=f"failover-group:{parts[2] if len(parts) > 2 else line_number}", group_id=group_id, raw_lines=[safe], source_order=line_number, source_attributes={"raw_command": safe})
            for child in children or []:
                child_parts = child.split()
                if child_parts and child_parts[0].lower() in {"primary", "secondary"}: group.unit_role = child_parts[0].lower()
                elif len(child_parts) > 1 and child_parts[0].lower() == "priority":
                    try: group.priority = int(child_parts[1])
                    except ValueError: group.review_reasons.append("Malformed failover group priority")
                group.raw_lines.append(sanitize_raw_text(child))
            cfg.failover_groups.append(group)
        else: cfg.migration_status="PARTIALLY_NORMALIZED"; cfg.requires_manual_review=True; cfg.review_reasons.append("Unsupported failover syntax")

    @staticmethod
    def _append_unique(values: List[str], additions: Iterable[str]) -> None:
        for value in additions:
            if value not in values:
                values.append(value)

    def _parse_crypto_map_line(self, line: str, line_number: int, dynamic: bool = False) -> None:
        parts = line.split()
        offset = 2
        if len(parts) <= offset + 1 or not parts[offset + 1].isdigit():
            self._record_diagnostic(line_number, line, "Malformed crypto map sequence", "crypto map", migration_effect="PARSE_ERROR")
            return
        name, sequence = parts[offset], int(parts[offset + 1])
        source_context = self._line_contexts.get(line_number)
        key = (name, sequence, dynamic, source_context)
        record = next((item for item in self.config.crypto_maps if (item.name, item.sequence, item.is_dynamic, item.source_context) == key), None)
        if record is None:
            record = CiscoCryptoMap(name=name, map_name=name, sequence=sequence, is_dynamic=dynamic,
                                    map_type="dynamic" if dynamic else "static", source_order=line_number,
                                    raw_lines=[], source_attributes={"raw_command": line})
            self.config.crypto_maps.append(self._with_source_context(record, line_number))
        safe_line = sanitize_raw_text(line)
        record.raw_lines.append(safe_line)
        tokens = parts[offset + 2:]
        if len(tokens) >= 3 and tokens[:2] == ["match", "address"]:
            record.acl_name = tokens[2]
        elif tokens[:2] == ["set", "peer"] and len(tokens) >= 3:
            self._append_unique([record.peer] if record.peer else [], [tokens[2]])
            record.peer = tokens[2]
        elif tokens[:2] == ["set", "transform-set"]:
            self._append_unique(record.transform_sets, tokens[2:])
        elif tokens[:2] == ["set", "ikev2"] and len(tokens) >= 4 and tokens[2].lower() in {"ipsec-proposal", "ipsec-proposals"}:
            self._append_unique(record.ikev2_proposals, tokens[3:])
        elif tokens[:2] == ["set", "pfs"] and len(tokens) >= 3:
            record.pfs_group = tokens[2] if tokens[2].lower() != "none" else None
        elif tokens[:3] == ["set", "security-association", "lifetime"]:
            if len(tokens) >= 5 and tokens[3].lower() in {"seconds", "kilobytes"} and tokens[4].isdigit():
                setattr(record, f"security_association_lifetime_{tokens[3].lower()}", int(tokens[4]))
            else:
                record.raw_options.append(safe_line)
                record.migration_status = "PARSE_ERROR"
                record.requires_manual_review = True
        elif tokens[:2] == ["set", "connection-type"] and len(tokens) >= 3:
            record.raw_options.append(safe_line)
        elif tokens[:1] == ["interface"] and len(tokens) >= 2:
            record.interface_attachment = tokens[1]
        else:
            lowered = [token.lower() for token in tokens]
            if "dynamic" in lowered and lowered.index("dynamic") + 1 < len(tokens):
                record.dynamic_map = tokens[lowered.index("dynamic") + 1]
            elif tokens:
                record.raw_options.append(safe_line)
                record.migration_status = "PARTIALLY_NORMALIZED"
                record.review_reasons.append("Unsupported crypto-map child syntax")

    def _parse_ike_child(self, record: CiscoIKEPolicy, children: List[str], line_number: int) -> None:
        for child in children:
            parts = child.split()
            if len(parts) < 2:
                record.raw_options.append(sanitize_raw_text(child))
                continue
            key, value = parts[0].lower(), " ".join(parts[1:])
            target = {"authentication": "authentication", "encryption": "encryption", "hash": "hash_algorithm",
                      "integrity": "integrity", "prf": "prf"}.get(key)
            if target:
                setattr(record, target, value)
            elif key == "group":
                record.dh_group = value
            elif key == "lifetime" and len(parts) == 2 and parts[1].isdigit():
                record.lifetime_seconds = int(parts[1])
            elif key == "lifetime":
                record.migration_status = "PARSE_ERROR"
                record.requires_manual_review = True
                record.raw_options.append(sanitize_raw_text(child))
                self._record_diagnostic(line_number, child, "Malformed IKE lifetime", "crypto ike policy", record.name)
            else:
                record.migration_status = "PARTIALLY_NORMALIZED"
                record.requires_manual_review = True
                record.raw_options.append(sanitize_raw_text(child))
                record.review_reasons.append("Unsupported IKE policy child syntax")

    def _aaa_record(self, line: str, index: int, name: Optional[str] = None) -> None:
        safe = sanitize_raw_text(line)
        parts = line.split()
        self.config.aaa_records.append(self._with_source_context(CiscoAAARecord(
            name=name or (parts[1] if len(parts) > 1 else f"line-{index + 1}"),
            raw_lines=[safe],
            has_secret=any(token.lower() in {"key", "password", "secret", "encrypted", "login-password", "common-password"} for token in parts),
            source_attributes={"raw_command": safe, "secret_present": any(token.lower() in {"key", "password", "secret", "login-password", "common-password"} for token in parts)},
        ), index + 1))

    def _parse_aaa_server(self, line: str, children: List[str], index: int) -> None:
        parts = line.split()
        if len(parts) < 3 or parts[1].lower() == "protocol":
            self._record_diagnostic(index + 1, line, "Malformed aaa-server declaration", "aaa-server")
            self._aaa_record(line, index)
            return
        group_name = parts[1]
        if len(parts) >= 4 and parts[2].lower() == "protocol":
            protocol = parts[3]
            group = CiscoAAAServerGroup(name=group_name, protocol=protocol, raw_lines=[sanitize_raw_text(line)], source_attributes={"raw_command": sanitize_raw_text(line)})
            if protocol.lower() not in {"radius", "tacacs+", "ldap"}:
                group.migration_status = "PARTIALLY_NORMALIZED"
                group.requires_manual_review = True
                group.review_reasons.append("AAA server protocol is preserved but not semantically verified")
            if any(item.name == group_name and item.source_context == self._line_contexts.get(index + 1) for item in self.config.aaa_server_groups):
                group.migration_status = "PARTIALLY_NORMALIZED"
                group.requires_manual_review = True
                group.review_reasons.append("Duplicate AAA server-group definition")
            self.config.aaa_server_groups.append(self._with_source_context(group, index + 1))
            self._aaa_record(line, index, group_name)
            return
        host_match = re.match(r"^aaa-server\s+(\S+)\s+(?:\(([^)]+)\)\s+)?host\s+(\S+)(?:\s+(.*))?$", line, re.I)
        if not host_match:
            self._record_diagnostic(index + 1, line, "Malformed aaa-server host declaration", "aaa-server")
            self._aaa_record(line, index, group_name)
            return
        group_name, interface, host, remainder = host_match.groups()
        group = next((item for item in self.config.aaa_server_groups if item.name == group_name and item.source_context == self._line_contexts.get(index + 1)), None)
        protocol = group.protocol if group else None
        record = CiscoAAAServerHost(
            name=f"{group_name}:{host}", group_name=group_name, host=host,
            interface=interface, protocol=protocol,
            raw_lines=[sanitize_raw_text(line)],
            source_attributes={"raw_command": sanitize_raw_text(line), "subcommands": [sanitize_raw_text(child) for child in children]},
        )
        if remainder:
            children = [remainder, *children]
        for child in children:
            safe = sanitize_raw_text(child)
            record.raw_lines.append(safe)
            tokens = child.split()
            if not tokens:
                continue
            key, value = tokens[0].lower(), tokens[1:]
            if key in {"authentication-port", "accounting-port", "timeout", "retries", "retry"}:
                if len(value) != 1 or not value[0].isdigit():
                    record.migration_status = "PARSE_ERROR"
                    record.requires_manual_review = True
                    self._record_diagnostic(index + 1, child, f"Malformed AAA {key}", "aaa-server", record.name)
                else:
                    setattr(record, {"authentication-port": "authentication_port", "accounting-port": "accounting_port", "timeout": "timeout", "retries": "retries", "retry": "retries"}[key], int(value[0]))
            elif key in {"key", "password", "login-password", "secret", "common-password", "radius-common-password"}:
                record.key_present |= key == "key"
                record.password_present |= key in {"password", "login-password"}
                record.server_secret_present |= key in {"secret", "login-password"}
                record.radius_common_password_present |= key in {"common-password", "radius-common-password"}
            elif key in {"ldap-base-dn", "ldap-scope", "ldap-naming-attribute", "ldap-login-dn"} and value:
                setattr(record, key.replace("-", "_"), " ".join(value))
            elif key in {"ldap-over-ssl", "ldap-over-ssl-enabled"}:
                record.ldap_over_ssl = True
            else:
                record.migration_status = "PARTIALLY_NORMALIZED"
                record.requires_manual_review = True
                record.source_attributes.setdefault("unmodeled_lines", []).append(safe)
                record.review_reasons.append("Unsupported AAA server-host option")
        self.config.aaa_server_hosts.append(self._with_source_context(record, index + 1))
        if group:
            group.hosts.append(host)
        self._aaa_record(line, index, group_name)

    def _parse_aaa_rule(self, line: str, index: int) -> None:
        parts = line.split()
        family = parts[1].lower() if len(parts) > 1 else ""
        target_collection = {"authentication": self.config.aaa_authentication_rules, "authorization": self.config.aaa_authorization_rules, "accounting": self.config.aaa_accounting_rules}.get(family)
        if target_collection is None or len(parts) < 3:
            self._record_diagnostic(index + 1, line, "Malformed AAA rule", "aaa")
            self._aaa_record(line, index)
            return
        values = parts[2:]
        service = values[0] if values else None
        fallback = any(value.upper() == "LOCAL" for value in values[1:])
        groups = [value for value in values[1:] if value.upper() != "LOCAL"]
        server_group = groups[-1] if groups else None
        target = groups[0] if len(groups) > 1 else None
        cls = {"authentication": CiscoAAAAuthenticationRule, "authorization": CiscoAAAAuthorizationRule, "accounting": CiscoAAAAccountingRule}[family]
        record = cls(name=f"{family}:{index + 1}", service=service, management_protocol=service, target=target, server_group=server_group, fallback_local=fallback, interface=target, raw_line=sanitize_raw_text(line), raw_lines=[sanitize_raw_text(line)], source_attributes={"raw_command": sanitize_raw_text(line)})
        if not server_group and not fallback:
            record.migration_status = "PARTIALLY_NORMALIZED"
            record.requires_manual_review = True
            record.review_reasons.append("AAA rule has no resolvable server group or LOCAL fallback")
        target_collection.append(self._with_source_context(record, index + 1))
        self._aaa_record(line, index)

    def _parse_local_username(self, line: str, index: int) -> None:
        parts = line.split()
        if len(parts) < 2:
            self._record_diagnostic(index + 1, line, "Malformed username command", "username")
            self._aaa_record(line, index)
            return
        record = CiscoLocalUser(name=parts[1], username=parts[1], raw_line=sanitize_raw_text(line), raw_lines=[sanitize_raw_text(line)], source_attributes={"raw_command": sanitize_raw_text(line)})
        pos = 2
        while pos < len(parts):
            key = parts[pos].lower()
            if key == "privilege" and pos + 1 < len(parts) and parts[pos + 1].isdigit():
                record.privilege = int(parts[pos + 1]); pos += 2; continue
            if key in {"password", "secret"}:
                record.password_present |= key == "password"; record.secret_present |= key == "secret"; pos += 2; continue
            if key == "encrypted":
                record.encrypted = True; pos += 1; continue
            if key == "nopassword":
                record.nopassword = True; pos += 1; continue
            if key in {"authentication", "aaa"} and pos + 1 < len(parts):
                record.authentication_type = parts[pos + 1]; pos += 2; continue
            pos += 1
        previous = next((item for item in self.config.local_users if item.username == record.username and item.source_context == self._line_contexts.get(index + 1)), None)
        if previous and (previous.privilege, previous.authentication_type) != (record.privilege, record.authentication_type):
            record.migration_status = previous.migration_status = "PARTIALLY_NORMALIZED"
            record.requires_manual_review = previous.requires_manual_review = True
            record.review_reasons.append("Conflicting duplicate local-user definition")
            previous.review_reasons.append("Conflicting duplicate local-user definition")
        self.config.local_users.append(self._with_source_context(record, index + 1))
        self._aaa_record(line, index)

    def _parse_source_only_records(self, lines: List[str]) -> None:
        """Capture ASA VPN, AAA, and MPF syntax without guessing target semantics."""
        def block(start: int) -> tuple[List[str], int]:
            children: List[str] = []
            index = start + 1
            while index < len(lines) and lines[index][:1].isspace() and not lines[index].strip().startswith("!"):
                children.append(lines[index].strip())
                index += 1
            return children, index

        for index, raw in enumerate(lines):
            line = raw.strip()
            if not line or line.startswith(("!", ":")):
                continue
            lower = line.lower()
            children, _ = block(index)
            if re.match(r"^track\s+\d+\s+", lower):
                track_id = int(line.split()[1])
                if track_id not in self.config.route_tracking_ids:
                    self.config.route_tracking_ids.append(track_id)
            elif re.match(r"^crypto\s+ikev[12]\s+policy\s+\d+", lower):
                match = re.match(r"^crypto\s+(ikev[12])\s+policy\s+(\d+)", line, re.IGNORECASE)
                self.config.ike_policies.append(self._with_source_context(CiscoIKEPolicy(
                    name=f"{match.group(1)}:{match.group(2)}", version=match.group(1),
                    number=int(match.group(2)), raw_lines=[line, *children],
                    source_attributes={"raw_command": line, "subcommands": children},
                ), index + 1))
                self._parse_ike_child(self.config.ike_policies[-1], children, index + 1)
            elif re.match(r"^crypto\s+ipsec\s+ikev2\s+ipsec-proposal\s+\S+", lower):
                match = re.match(r"^crypto\s+ipsec\s+ikev2\s+ipsec-proposal\s+(\S+)", line, re.I)
                record = CiscoIKEv2Proposal(name=match.group(1), raw_lines=[sanitize_raw_text(line), *map(sanitize_raw_text, children)], source_attributes={"raw_command": line})
                for child in children:
                    parts = child.split()
                    if len(parts) >= 3 and parts[0].lower() == "protocol" and parts[1].lower() == "esp":
                        targets = {"encryption": record.encryption_algorithms, "integrity": record.integrity_algorithms, "prf": record.prf_algorithms}
                        positions = [(pos, targets[parts[pos].lower()]) for pos in range(2, len(parts)) if parts[pos].lower() in targets]
                        for pos, target in positions:
                            end = next((next_pos for next_pos, _ in positions if next_pos > pos), len(parts))
                            self._append_unique(target, parts[pos + 1:end])
                        if positions:
                            continue
                    if parts and parts[0].lower() == "group" and len(parts) > 1:
                        self._append_unique(record.dh_groups, parts[1:])
                        continue
                    record.migration_status = "PARTIALLY_NORMALIZED"
                    record.review_reasons.append("Unsupported IKEv2 proposal child syntax")
                self.config.ikev2_proposals.append(self._with_source_context(record, index + 1))
            elif re.match(r"^crypto\s+ca\s+trustpoint\s+\S+", lower):
                name = line.split()[3]
                if name not in self.config.trustpoints:
                    self.config.trustpoints.append(name)
            elif re.match(r"^crypto\s+ipsec\s+(?:ikev[12]\s+)?transform-set\s+\S+", lower):
                match = re.match(r"^crypto\s+ipsec\s+(?:ikev[12]\s+)?transform-set\s+(\S+)\s*(.*)$", line, re.I)
                values = match.group(2).split()
                self.config.ipsec_transform_sets.append(self._with_source_context(CiscoIPsecTransformSet(
                    name=match.group(1), encryption=values[0] if values else None,
                    authentication=" ".join(values[1:]) or None, raw_line=sanitize_raw_text(line),
                    raw_lines=[sanitize_raw_text(line)], source_attributes={"raw_command": line}), index + 1))
                record = self.config.ipsec_transform_sets[-1]
                for child in children:
                    if child.lower().startswith("mode "):
                        record.mode = child.split(maxsplit=1)[1]
                    else:
                        record.source_attributes.setdefault("unmodeled_lines", []).append(sanitize_raw_text(child))
                if not values:
                    record.migration_status = "PARSE_ERROR"
                    record.requires_manual_review = True
            elif re.match(r"^crypto\s+dynamic-map\s+", lower):
                self._parse_crypto_map_line(line, index + 1, True)
            elif lower.startswith("crypto map "):
                self._parse_crypto_map_line(line, index + 1)
            elif lower.startswith("ip local pool "):
                parts = line.split()
                record = CiscoVPNAddressPool(name=parts[3] if len(parts) > 3 else "unknown", raw_line=sanitize_raw_text(line), raw_lines=[sanitize_raw_text(line)], source_attributes={"raw_command": line})
                if len(parts) >= 6:
                    record.start, record.end = parts[4], parts[5]
                    record.mask = parts[6] if len(parts) > 6 else None
                    try:
                        start, end = ipaddress.ip_address(record.start), ipaddress.ip_address(record.end)
                        if start.version != end.version or (record.mask and parse_ipv4_netmask(record.mask) is None):
                            raise ValueError
                        record.address_family = f"ipv{start.version}"
                    except ValueError:
                        record.migration_status = "PARSE_ERROR"
                        record.requires_manual_review = True
                        self._record_diagnostic(index + 1, line, "Malformed VPN address pool", "ip local pool", record.name)
                else:
                    record.migration_status = "PARSE_ERROR"
                    record.requires_manual_review = True
                self.config.vpn_address_pools.append(self._with_source_context(record, index + 1))
            elif lower.startswith("tunnel-group "):
                parts = line.split()
                record = CiscoTunnelGroup(name=parts[1] if len(parts) > 1 else "unknown", raw_lines=[sanitize_raw_text(line), *map(sanitize_raw_text, children)])
                record.source_attributes["raw_command"] = line
                if len(parts) > 2 and parts[2].lower() in {"general-attributes", "ipsec-attributes"}:
                    children = [*children, " ".join(parts[2:])]
                if len(parts) > 2 and parts[2].lower() == "type":
                    record.group_type = parts[3] if len(parts) > 3 else None
                section = None
                for child in children:
                    child_parts = child.split()
                    if child.lower() in {"general-attributes", "ipsec-attributes"}:
                        section = child.lower()
                        continue
                    attrs = record.general_attributes if section == "general-attributes" else record.ipsec_attributes
                    if "pre-shared-key" in child_parts:
                        record.ikev1_psk_present = True
                        attrs["has_pre_shared_key"] = True
                        attrs.setdefault("raw_subcommands", []).append(re.sub(r"(?i)(pre-shared-key)\s+\S+", r"\1 [REDACTED]", child))
                    elif child_parts and child_parts[0].lower() == "default-group-policy" and len(child_parts) > 1:
                        record.default_group_policy = child_parts[1]
                    elif child_parts and child_parts[0].lower() == "address-pool":
                        self._append_unique(record.address_pools, child_parts[1:])
                    elif child_parts and child_parts[0].lower() == "trust-point" and len(child_parts) > 1:
                        record.trustpoint = child_parts[1]
                    elif child_parts and child_parts[0].lower() in {"ikev1", "ikev2"} and len(child_parts) > 2:
                        setattr(record, f"{child_parts[0].lower()}_{child_parts[1].lower().replace('-', '_')}", " ".join(child_parts[2:]))
                    elif child_parts and child_parts[0].lower() in {"authentication", "ikev1-authentication", "ikev2-authentication"}:
                        record.authentication_method = " ".join(child_parts[1:])
                    elif child_parts:
                        attrs.setdefault("raw_subcommands", []).append(sanitize_raw_text(child))
                if record.raw_lines:
                    record.migration_status = "PARTIALLY_NORMALIZED"
                self.config.tunnel_groups.append(self._with_source_context(record, index + 1))
            elif lower.startswith("group-policy "):
                parts = line.split()
                name = parts[1] if len(parts) > 1 else "unknown"
                source_context = self._line_contexts.get(index + 1)
                record = next((item for item in self.config.group_policies if item.name == name and item.source_context == source_context), None)
                if record is None:
                    record = CiscoGroupPolicy(name=name, raw_lines=[], source_attributes={"raw_command": line, "subcommands": []})
                    self.config.group_policies.append(self._with_source_context(record, index + 1))
                record.raw_lines.extend([sanitize_raw_text(line), *map(sanitize_raw_text, children)])
                record.source_attributes["subcommands"].extend(map(sanitize_raw_text, children))
                for child in children:
                    child_parts = child.split()
                    if len(child_parts) < 2:
                        record.raw_attributes.setdefault("unmodeled_lines", []).append(sanitize_raw_text(child))
                        continue
                    key, values = child_parts[0].lower(), child_parts[1:]
                    if key == "address-pools": self._append_unique(record.address_pools, values[1:] if values[0].lower() == "value" else values)
                    elif key == "dns-server": self._append_unique(record.dns_servers, values[1:] if values[0].lower() == "value" else values)
                    elif key == "split-tunnel-policy": record.split_tunnel_policy = values[0]
                    elif key == "split-tunnel-network-list": record.split_tunnel_acl = values[-1]
                    elif key == "vpn-tunnel-protocol": self._append_unique(record.vpn_protocols, values)
                    elif key == "vpn-idle-timeout": record.idle_timeout = " ".join(values)
                    elif key == "vpn-session-timeout": record.session_timeout = " ".join(values)
                    elif key == "default-domain": record.default_domain = " ".join(values)
                    elif key == "group-policy": record.parent = values[-1]
                    else:
                        record.raw_attributes.setdefault("unmodeled_lines", []).append(sanitize_raw_text(child))
                        record.migration_status = "PARTIALLY_NORMALIZED"
                record.migration_status = "PARTIALLY_NORMALIZED"
            elif lower.startswith("aaa-server "):
                self._parse_aaa_server(line, children, index)
            elif lower.startswith(("aaa authentication ", "aaa authorization ", "aaa accounting ")):
                self._parse_aaa_rule(line, index)
            elif lower.startswith("username "):
                self._parse_local_username(line, index)
            elif lower.startswith("class-map") and not raw[:1].isspace():
                self.config.class_maps.append(self._with_source_context(self._parse_class_map_block(lines, index), index + 1))
            elif lower.startswith("policy-map") and not raw[:1].isspace():
                self.config.policy_maps.append(self._with_source_context(self._parse_policy_map_block(lines, index), index + 1))
            elif lower.startswith("tcp-map") and not raw[:1].isspace():
                self.config.tcp_maps.append(self._with_source_context(self._parse_tcp_map_block(lines, index), index + 1))
            elif lower.startswith("service-policy") and not raw[:1].isspace():
                self.config.service_policies.append(self._with_source_context(self._parse_service_policy_line(line, index + 1), index + 1))

    @staticmethod
    def _raw_block(lines: List[str], start: int) -> List[tuple[int, str, str]]:
        rows = []
        index = start + 1
        while index < len(lines) and lines[index][:1].isspace() and not lines[index].strip().startswith("!"):
            raw = lines[index]
            rows.append((index + 1, raw, raw.strip()))
            index += 1
        return rows

    @staticmethod
    def _mpf_partial(record: Any, reason: str) -> None:
        record.migration_status = "PARTIALLY_NORMALIZED"
        record.requires_manual_review = True
        if reason not in record.review_reasons:
            record.review_reasons.append(reason)

    def _mpf_parse_error(self, record: Any, line_number: int, line: str, section: str, reason: str) -> None:
        record.migration_status = "PARSE_ERROR"
        record.requires_manual_review = True
        if hasattr(record, "review_reasons") and reason not in record.review_reasons:
            record.review_reasons.append(reason)
        self._record_diagnostic(line_number, line, reason, section, getattr(record, "name", None))

    def _parse_class_map_block(self, lines: List[str], index: int) -> CiscoClassMap:
        line = lines[index].strip()
        parts = line.split()
        mode = None
        name = "unknown"
        malformed = False
        if len(parts) == 2:
            name = parts[1]
        elif len(parts) == 3 and parts[1].lower() in {"match-any", "match-all"}:
            mode, name = parts[1].lower(), parts[2]
        else:
            malformed = True
            if len(parts) > 1:
                name = parts[-1]
        record = CiscoClassMap(
            name=name, match_type=mode, match_any=mode == "match-any" if mode else None,
            match_all=mode == "match-all" if mode else None,
            raw_lines=[sanitize_raw_text(line)],
            source_attributes={"raw_command": sanitize_raw_text(line)},
            migration_status="PARTIALLY_NORMALIZED", requires_manual_review=True,
        )
        if malformed:
            self._mpf_parse_error(record, index + 1, line, "class-map", "Malformed class-map header")
        for line_number, _, child in self._raw_block(lines, index):
            safe_child = sanitize_raw_text(child)
            record.raw_lines.append(safe_child)
            if child.lower().startswith("description "):
                record.description = child.split(maxsplit=1)[1]
                continue
            if not child.lower().startswith("match"):
                self._mpf_partial(record, "Unsupported class-map child syntax")
                record.source_attributes.setdefault("unmodeled_lines", []).append(safe_child)
                continue
            record.match_lines.append(safe_child)
            match = re.fullmatch(r"match\s+access-list\s+(\S+)", child, re.IGNORECASE)
            if match:
                record.matches.append(CiscoClassMapMatch(
                    match_type="access_list", value=match.group(1), acl_name=match.group(1),
                    raw=safe_child, source_order=line_number,
                ))
                continue
            match = re.fullmatch(r"match\s+any", child, re.IGNORECASE)
            if match:
                record.matches.append(CiscoClassMapMatch(match_type="any", raw=safe_child, source_order=line_number))
                continue
            match = re.fullmatch(r"match\s+protocol\s+(\S+)", child, re.IGNORECASE)
            if match:
                record.matches.append(CiscoClassMapMatch(
                    match_type="protocol", value=match.group(1), protocol=match.group(1),
                    raw=safe_child, source_order=line_number,
                ))
                continue
            match = re.fullmatch(r"match\s+port\s+(.+)", child, re.IGNORECASE)
            if match:
                record.matches.append(CiscoClassMapMatch(
                    match_type="port", value=match.group(1), port=match.group(1),
                    raw=safe_child, source_order=line_number,
                ))
                continue
            if re.match(r"match\s+(?:access-list|protocol|port)\s*$", child, re.IGNORECASE) or child.lower() == "match":
                self._mpf_parse_error(record, line_number, child, "class-map", "Malformed class-map match syntax")
                continue
            self._mpf_partial(record, "Unsupported class-map match syntax")
            record.source_attributes.setdefault("unmodeled_lines", []).append(safe_child)
        return record

    def _parse_policy_map_block(self, lines: List[str], index: int) -> CiscoPolicyMap:
        line = lines[index].strip()
        parts = line.split()
        name = parts[1] if len(parts) == 2 else (parts[-1] if len(parts) > 1 else "unknown")
        record = CiscoPolicyMap(
            name=name, raw_lines=[sanitize_raw_text(line)],
            source_attributes={"raw_command": sanitize_raw_text(line)},
            migration_status="PARTIALLY_NORMALIZED", requires_manual_review=True,
        )
        if len(parts) != 2:
            self._mpf_parse_error(record, index + 1, line, "policy-map", "Malformed policy-map header")
        current: Optional[CiscoPolicyMapClass] = None
        for line_number, _, child in self._raw_block(lines, index):
            safe_child = sanitize_raw_text(child)
            record.raw_lines.append(safe_child)
            if child.lower().startswith("description ") and current is None:
                record.description = child.split(maxsplit=1)[1]
                continue
            if child.lower() == "class" or child.lower().startswith("class "):
                class_parts = child.split()
                class_name = class_parts[1] if len(class_parts) == 2 else "unknown"
                current = CiscoPolicyMapClass(
                    class_name=class_name, source_order=line_number,
                    raw_lines=[safe_child], migration_status="PARTIALLY_NORMALIZED",
                    requires_manual_review=True, source_attributes={"raw_header": safe_child},
                )
                record.classes.append(current)
                record.class_sections.append(safe_child)
                if len(class_parts) != 2:
                    self._mpf_parse_error(current, line_number, child, "policy-map", "Malformed policy-map class header")
                continue
            if current is None:
                self._mpf_partial(record, "Unsupported policy-map child syntax")
                record.source_attributes.setdefault("unmodeled_lines", []).append(safe_child)
                continue
            current.raw_lines.append(safe_child)
            self._parse_mpf_action(current, child, line_number)
        return record

    def _parse_mpf_action(self, section: CiscoPolicyMapClass, line: str, line_number: int) -> None:
        parts = line.split()
        lower = line.lower()
        if lower == "inspect" or lower.startswith("inspect "):
            if len(parts) < 2:
                self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed inspect action: missing protocol")
                return
            protocol = parts[1].lower()
            action = CiscoInspectAction(protocol=protocol, raw=sanitize_raw_text(line), source_order=line_number)
            supported = {"dns", "ftp", "http", "icmp", "sip", "esmtp", "netbios", "sunrpc", "tftp", "ip-options", "skinny"}
            extras = parts[2:]
            if protocol not in supported:
                action.migration_status = "PARTIALLY_NORMALIZED"
                action.requires_manual_review = True
                action.review_reasons.append("Unsupported inspect protocol")
            elif protocol == "icmp" and extras == ["error"]:
                action.parameters = extras
            elif extras and extras[0].lower() == "policy":
                if len(extras) < 2:
                    self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed inspect policy reference")
                    return
                action.policy_name = extras[1]
                action.parameters = extras[2:]
                action.migration_status = "PARTIALLY_NORMALIZED"
                action.requires_manual_review = True
                action.review_reasons.append("Referenced inspect policy requires target review")
            elif extras and protocol in {"dns", "http", "sip", "esmtp"}:
                action.policy_name, action.parameters = extras[0], extras[1:]
                action.migration_status = "PARTIALLY_NORMALIZED"
                action.requires_manual_review = True
                action.review_reasons.append("Referenced inspect policy requires target review")
            elif extras:
                action.parameters = extras
                action.migration_status = "PARTIALLY_NORMALIZED"
                action.requires_manual_review = True
                action.review_reasons.append("Unsupported inspect action option")
            section.inspect_actions.append(action)
            return
        if lower.startswith("tcp-map") or lower.startswith("set connection tcp-map"):
            lowered_parts = [part.lower() for part in parts]
            if len(parts) == 2 and lowered_parts[0] == "tcp-map":
                section.tcp_map = parts[1]
            elif len(parts) == 4 and lowered_parts[:3] == ["set", "connection", "tcp-map"]:
                section.tcp_map = parts[3]
            else:
                self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed tcp-map reference")
            return
        if lower.startswith("set connection"):
            section.connection_actions.append(self._parse_connection_action(section, line, line_number))
            return
        if lower.startswith("police"):
            section.police_actions.append(self._parse_police_action(section, line, line_number))
            return
        self._mpf_partial(section, "Unsupported policy-map class action syntax")
        section.source_attributes.setdefault("unmodeled_lines", []).append(sanitize_raw_text(line))

    def _parse_connection_action(self, section: CiscoPolicyMapClass, line: str, line_number: int) -> CiscoMPFConnectionAction:
        parts = line.split()
        action = CiscoMPFConnectionAction(raw=sanitize_raw_text(line), source_order=line_number)
        if len(parts) < 4:
            self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed set connection action")
            return action
        key = parts[2].lower()
        values = parts[3:]
        numeric = {
            "conn-max": "max_connections", "embryonic-conn-max": "max_embryonic",
            "per-client-max": "per_client_max", "per-client-embryonic-max": "per_client_embryonic",
        }
        if key in numeric:
            if len(values) != 1 or not values[0].isdigit():
                self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed set connection numeric value")
            else:
                setattr(action, numeric[key], int(values[0]))
        elif key == "timeout" and len(values) >= 2 and values[0].lower() == "embryonic":
            action.timeout_embryonic = " ".join(values[1:])
        elif key in {"random-sequence-number", "tcp-intercept"} and len(values) == 1:
            setattr(action, key.replace("-", "_"), values[0])
        else:
            self._mpf_partial(section, "Unsupported set connection action syntax")
            action.review_reasons.append("Unsupported set connection action syntax")
        return action

    @staticmethod
    def _valid_timeout(value: str) -> bool:
        return bool(re.fullmatch(r"\d{1,2}:\d{2}:\d{2}", value)) and int(value.split(":", 1)[0]) >= 0 and int(value.split(":")[1]) < 60 and int(value.rsplit(":", 1)[1]) < 60

    def _parse_global_conn(self, line: str, line_number: int) -> CiscoConnectionControl:
        parts = line.split()
        item = CiscoConnectionControl(
            name="conn", setting="conn", values=parts[1:], control_type="connection_limit",
            raw_lines=[line], source_order=line_number, source_attributes={"raw_command": line},
            migration_status="PARTIALLY_NORMALIZED", requires_manual_review=False,
        )
        fields = {
            "conn-max": "max_connections", "embryonic-conn-max": "max_embryonic",
            "per-client-max": "per_client_max", "per-client-embryonic-max": "per_client_embryonic",
        }
        if len(parts) != 2 or parts[0].lower() not in fields:
            item.control_type = "generic_connection_control"
            item.requires_manual_review = True
            item.review_reasons.append("Unsupported global connection-control syntax")
            return item
        if not parts[1].isdigit():
            item.migration_status = "PARSE_ERROR"
            item.requires_manual_review = True
            item.review_reasons.append("Connection limit must be numeric")
            self._record_diagnostic(line_number, line, "Malformed global connection limit", "conn")
            return item
        setattr(item, fields[parts[0].lower()], int(parts[1]))
        return item

    def _parse_timeout_command(self, line: str, line_number: int) -> CiscoConnectionControl:
        parts = line.split()
        item = CiscoConnectionControl(
            name="timeout", setting="timeout", values=parts[1:], control_type="timeout",
            raw_lines=[line], source_order=line_number, source_attributes={"raw_command": line},
            migration_status="PARTIALLY_NORMALIZED", requires_manual_review=False,
        )
        fields = {
            "embryonic": "timeout_embryonic", "half-closed": "timeout_half_closed",
            "conn": "timeout_tcp", "udp": "timeout_udp", "icmp": "timeout_icmp",
            "xlate": "timeout_xlate", "pat-xlate": "timeout_pat_xlate",
            "sunrpc": "timeout_sunrpc", "h225": "timeout_h225", "h323": "timeout_h323",
            "sip": "timeout_sip", "sip_media": "timeout_sip_media", "sip-media": "timeout_sip_media",
        }
        key = parts[1].lower() if len(parts) > 1 else ""
        value = parts[2] if len(parts) > 2 else ""
        if key not in fields:
            item.requires_manual_review = True
            item.review_reasons.append("Unsupported timeout domain")
            return item
        if len(parts) != 3 or not self._valid_timeout(value):
            item.migration_status = "PARSE_ERROR"
            item.requires_manual_review = True
            item.review_reasons.append("Malformed ASA timeout duration")
            self._record_diagnostic(line_number, line, "Malformed timeout duration", "timeout")
            return item
        setattr(item, fields[key], value)
        return item

    def _parse_threat_detection(self, line: str, line_number: int) -> CiscoConnectionControl:
        parts = line.split()
        disabled = len(parts) >= 3 and parts[0].lower() == "no" and parts[1].lower() == "threat-detection"
        type_index = 2 if disabled else 1
        item = CiscoConnectionControl(
            name="threat-detection", setting="threat-detection", values=parts[type_index + 1:],
            control_type="threat_detection", raw_lines=[line], source_order=line_number,
            source_attributes={"raw_command": line}, migration_status="PARTIALLY_NORMALIZED",
            requires_manual_review=False,
        )
        if len(parts) <= type_index:
            item.migration_status = "PARSE_ERROR"
            item.requires_manual_review = True
            item.review_reasons.append("Missing threat-detection type")
            self._record_diagnostic(line_number, line, "Malformed threat-detection command", "threat-detection")
            return item
        item.threat_detection_type = parts[type_index].lower()
        item.enabled = not disabled
        if item.threat_detection_type in {"basic-threat", "scanning-threat", "statistics", "rate", "access-list"}:
            values = parts[2:]
            if values and len(values) % 2:
                item.requires_manual_review = True
                item.review_reasons.append("Unsupported threat-detection parameters")
            for index in range(0, len(values) - 1, 2):
                key, value = values[index].lower(), values[index + 1]
                if key in {"average-rate", "burst-rate", "interval"}:
                    if not value.isdigit():
                        item.migration_status = "PARSE_ERROR"
                        item.requires_manual_review = True
                        item.review_reasons.append("Threat-detection rate must be numeric")
                        self._record_diagnostic(line_number, line, "Malformed threat-detection rate", "threat-detection")
                        break
                    if key == "average-rate":
                        item.rate = int(value)
                    elif key == "burst-rate":
                        item.burst = int(value)
                    else:
                        item.source_attributes["interval"] = int(value)
                else:
                    item.requires_manual_review = True
                    item.review_reasons.append("Unsupported threat-detection parameter")
        else:
            item.requires_manual_review = True
            item.review_reasons.append("Unsupported threat-detection variant")
        return item

    @staticmethod
    def _ip(value: str) -> bool:
        try:
            return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
        except ValueError:
            return False

    def _dhcp_server(self, interface: Optional[str], line_number: int) -> CiscoDHCPServer:
        if interface is None and len(self.config.dhcp_servers) == 1:
            return self.config.dhcp_servers[0]
        key = interface or "global"
        item = next((server for server in self.config.dhcp_servers if server.name == f"dhcpd:{key}"), None)
        if item is None:
            item = CiscoDHCPServer(
                name=f"dhcpd:{key}", interface=interface, source_order=line_number,
                migration_status="PARTIALLY_NORMALIZED", requires_manual_review=False,
            )
            self.config.dhcp_servers.append(item)
        return item

    def _parse_dhcpd_command(self, line: str, line_number: int) -> None:
        parts = line.split()
        command = parts[1].lower() if len(parts) > 1 else ""
        values = parts[2:]
        if command == "enable":
            interface = values[0] if values else None
        else:
            interface = values[-1] if command in {"address", "dns", "domain"} and len(values) > 1 and not self._ip(values[-1]) and "-" not in values[-1] and not values[-1].isdigit() else None
        if interface and command != "enable":
            values = values[:-1]
        item = self._dhcp_server(interface, line_number)
        if interface is None and command in {"address", "enable", "dns"}:
            item.requires_manual_review = True
            item.review_reasons.append("DHCP interface reference is missing")
        item.raw_lines.append(line)
        item.source_attributes.setdefault("raw_commands", []).append(line)
        if command == "address":
            if len(values) != 1 or "-" not in values[0]:
                item.migration_status = "PARSE_ERROR"
                item.review_reasons.append("Malformed DHCP address pool")
                self._record_diagnostic(line_number, line, "Malformed DHCP address pool", "dhcpd")
                return
            start, end = values[0].split("-", 1)
            if not self._ip(start) or not self._ip(end) or ipaddress.ip_address(start) > ipaddress.ip_address(end):
                item.migration_status = "PARSE_ERROR"
                item.review_reasons.append("Invalid or reversed DHCP address pool")
                self._record_diagnostic(line_number, line, "Invalid or reversed DHCP address pool", "dhcpd")
                return
            item.pool = values[0]
            item.pool_start, item.pool_end = start, end
        elif command == "enable":
            item.interface = values[0] if values else item.interface
            item.enabled = True
        elif command == "dns":
            if not values or any(not self._ip(value) for value in values):
                item.migration_status = "PARSE_ERROR"
                item.review_reasons.append("DHCP DNS servers must be IP addresses")
                self._record_diagnostic(line_number, line, "Malformed DHCP DNS server", "dhcpd")
            else:
                item.dns_servers.extend(values)
        elif command == "domain":
            if values:
                item.domain_name = " ".join(values)
        elif command == "lease":
            if len(values) != 1 or not values[0].isdigit():
                item.migration_status = "PARSE_ERROR"
                item.review_reasons.append("DHCP lease must be numeric")
                self._record_diagnostic(line_number, line, "Malformed DHCP lease", "dhcpd")
            else:
                item.lease_seconds = int(values[0])
        elif command == "option" and len(values) >= 2:
            item.options.append(CiscoDHCPOption(code=values[0], value=" ".join(values[1:]), raw=line, source_order=line_number))
        else:
            item.requires_manual_review = True
            item.review_reasons.append("Unsupported DHCP command")

    def _parse_dhcprelay_command(self, line: str, line_number: int) -> None:
        parts = line.split()
        command = parts[1].lower() if len(parts) > 1 else ""
        relay = next((item for item in self.config.dhcp_relays if item.name == "dhcprelay"), None)
        if relay is None:
            relay = CiscoDHCPRelay(name="dhcprelay", migration_status="PARTIALLY_NORMALIZED", requires_manual_review=False)
            self.config.dhcp_relays.append(relay)
        relay.raw_lines.append(line)
        relay.source_attributes.setdefault("raw_commands", []).append(line)
        relay.source_order = relay.source_order or line_number
        if command == "server" and len(parts) >= 3:
            server = parts[2]
            interface = parts[3] if len(parts) > 3 else None
            entry = CiscoDHCPRelayServer(server=server, interface=interface, raw=line, source_order=line_number)
            relay.server_entries.append(entry)
            relay.servers.append(server)
            relay.server = relay.server or server
            relay.interface = relay.interface or interface
            if not self._ip(server):
                relay.migration_status = "PARSE_ERROR"
                relay.review_reasons.append("DHCP relay server must be an IP address")
                self._record_diagnostic(line_number, line, "Malformed DHCP relay server", "dhcprelay")
        elif command == "enable" and len(parts) >= 3:
            relay.enabled = True
            relay.enabled_interfaces.append(parts[2])
        elif command == "timeout" and len(parts) == 3 and parts[2].isdigit():
            relay.timeout = int(parts[2])
        else:
            relay.requires_manual_review = True
            relay.review_reasons.append("Unsupported DHCP relay option")

    def _parse_police_action(self, section: CiscoPolicyMapClass, line: str, line_number: int) -> CiscoMPFPoliceAction:
        parts = line.split()
        action = CiscoMPFPoliceAction(raw=sanitize_raw_text(line), source_order=line_number)
        values = parts[1:]
        if values and values[0].lower() in {"input", "output"}:
            values = values[1:]
        if values and values[0].lower() == "rate":
            values = values[1:]
        if not values or not values[0].isdigit():
            self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed police rate")
            return action
        action.rate = int(values[0])
        position = 1
        if position < len(values) and values[position].lower() == "burst":
            position += 1
        if position < len(values) and not values[position].lower().endswith("-action"):
            if not values[position].isdigit():
                self._mpf_parse_error(section, line_number, line, "policy-map", "Malformed police burst")
                return action
            action.burst = int(values[position])
            position += 1
        while position < len(values):
            key = values[position].lower()
            if key not in {"conform-action", "exceed-action"} or position + 1 >= len(values):
                self._mpf_partial(section, "Unsupported police action option")
                action.review_reasons.append("Unsupported police action option")
                break
            value = values[position + 1]
            if key == "conform-action":
                action.conform_action = value
            else:
                action.exceed_action = value
            if value.lower() not in {"transmit", "drop", "set-cos-transmit", "set-prec-transmit"}:
                self._mpf_partial(section, "Unsupported police action modifier")
                action.review_reasons.append("Unsupported police action modifier")
            position += 2
        return action

    def _parse_tcp_map_block(self, lines: List[str], index: int) -> CiscoTCPMap:
        line = lines[index].strip()
        parts = line.split()
        name = parts[1] if len(parts) == 2 else (parts[-1] if len(parts) > 1 else "unknown")
        record = CiscoTCPMap(
            name=name, raw_lines=[sanitize_raw_text(line)],
            source_attributes={"raw_command": sanitize_raw_text(line)},
            migration_status="PARTIALLY_NORMALIZED", requires_manual_review=True,
        )
        if len(parts) != 2:
            self._mpf_parse_error(record, index + 1, line, "tcp-map", "Malformed tcp-map header")
        for line_number, _, child in self._raw_block(lines, index):
            safe_child = sanitize_raw_text(child)
            record.raw_lines.append(safe_child)
            match = re.fullmatch(r"(no\s+)?checksum-verification", child, re.IGNORECASE)
            if match:
                record.settings["checksum-verification"] = not bool(match.group(1))
                continue
            match = re.fullmatch(r"queue-limit\s+(\d+)", child, re.IGNORECASE)
            if match:
                record.settings["queue-limit"] = int(match.group(1))
                continue
            match = re.fullmatch(r"(reserved-bits|tcp-options|window-variation)\s+(\S+)", child, re.IGNORECASE)
            if match:
                record.settings[match.group(1).lower()] = match.group(2)
                continue
            if child.lower().startswith("queue-limit"):
                self._mpf_parse_error(record, line_number, child, "tcp-map", "Malformed tcp-map queue-limit")
            else:
                self._mpf_partial(record, "Unsupported tcp-map child syntax")
            record.source_attributes.setdefault("unmodeled_lines", []).append(safe_child)
        return record

    def _parse_service_policy_line(self, line: str, line_number: int) -> CiscoServicePolicy:
        parts = line.split()
        policy_name = parts[1] if len(parts) > 1 else None
        record = CiscoServicePolicy(
            name=policy_name or "unknown", policy_name=policy_name, attachment=parts[2] if len(parts) > 2 else None,
            interface=parts[3] if len(parts) == 4 and len(parts) > 2 and parts[2].lower() == "interface" else None,
            scope=parts[2].lower() if len(parts) > 2 else None,
            global_attachment=len(parts) == 3 and parts[2].lower() == "global",
            source_order=line_number, raw_lines=[sanitize_raw_text(line)],
            source_attributes={"raw_command": sanitize_raw_text(line)},
            migration_status="PARTIALLY_NORMALIZED", requires_manual_review=True,
        )
        if len(parts) < 2:
            self._mpf_parse_error(record, line_number, line, "service-policy", "Malformed service-policy: missing policy name")
        elif not ((len(parts) == 3 and parts[2].lower() == "global") or (len(parts) == 4 and parts[2].lower() == "interface")):
            self._mpf_partial(record, "Unsupported service-policy attachment syntax")
        elif parts[2].lower() == "interface" and not record.interface:
            self._mpf_parse_error(record, line_number, line, "service-policy", "Malformed service-policy interface attachment")
        return record

    def _parse_network_object(self, name: str, block: List[str]) -> CiscoNetworkObject:
        obj = CiscoNetworkObject(name=name, raw_lines=list(block))
        defined = False
        for sub in block:
            parts = sub.split()
            lower = sub.lower()
            if lower.startswith("host ") and len(parts) >= 2:
                try:
                    address = ipaddress.ip_address(parts[1])
                    value = str(address)
                    if defined and (obj.type, obj.value) != ("host", value):
                        obj.source_attributes.setdefault("conflicting_definitions", []).append(sub)
                        obj.migration_status = "PARSE_ERROR"
                        obj.requires_manual_review = True
                    elif not defined:
                        obj.type, obj.value = "host", value
                        obj.address_family = f"ipv{address.version}"
                        defined = True
                except ValueError:
                    obj.source_attributes["invalid_host"] = parts[1]
                    obj.migration_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
            elif lower.startswith("subnet ") and len(parts) >= 2:
                value = None
                if ":" in parts[1] and "/" in parts[1]:
                    try:
                        value = str(ipaddress.IPv6Network(parts[1], strict=False))
                        obj.address_family = "ipv6"
                    except ValueError:
                        value = None
                elif len(parts) >= 3:
                    value = normalize_ipv4_network(parts[1], parts[2])
                    obj.address_family = "ipv4" if value else None
                if value is None:
                    obj.migration_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
                    obj.source_attributes["invalid_subnet"] = " ".join(parts[1:])
                else:
                    if defined and (obj.type, obj.value) != ("subnet", value):
                        obj.source_attributes.setdefault("conflicting_definitions", []).append(sub)
                        obj.migration_status = "PARSE_ERROR"
                        obj.requires_manual_review = True
                    elif not defined:
                        obj.type, obj.value = "subnet", value
                        defined = True
            elif lower.startswith("range ") and len(parts) >= 3:
                try:
                    start, end = ipaddress.ip_address(parts[1]), ipaddress.ip_address(parts[2])
                    if start.version != end.version or int(start) > int(end):
                        raise ValueError
                    value = f"{start}-{end}"
                    if defined and (obj.type, obj.value) != ("range", value):
                        obj.source_attributes.setdefault("conflicting_definitions", []).append(sub)
                        obj.migration_status = "PARSE_ERROR"
                        obj.requires_manual_review = True
                    elif not defined:
                        obj.type, obj.value = "range", value
                        obj.address_family = f"ipv{start.version}"
                        defined = True
                except ValueError:
                    obj.migration_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
                    obj.source_attributes["invalid_range"] = " ".join(parts[1:3])
            elif lower.startswith("fqdn "):
                values = parts[1:]
                if values and values[0].lower() in {"v4", "v6"}:
                    family = values.pop(0).lower()
                    obj.address_family = "ipv4" if family == "v4" else "ipv6"
                    obj.source_attributes["address_family"] = obj.address_family
                if values:
                    value = " ".join(values)
                    if defined and (obj.type, obj.value) != ("fqdn", value):
                        obj.source_attributes.setdefault("conflicting_definitions", []).append(sub)
                        obj.migration_status = "PARSE_ERROR"
                        obj.requires_manual_review = True
                    elif not defined:
                        obj.type, obj.value = "fqdn", value
                        defined = True
            elif lower.startswith("description "):
                obj.description = sub.split(maxsplit=1)[1]
            elif lower.startswith("nat "):
                obj.nat_lines.append(sub)
            else:
                obj.source_attributes.setdefault("unmodeled_lines", []).append(sub)
        if obj.type is None or obj.value is None:
            obj.migration_status = "PARSE_ERROR"
            obj.requires_manual_review = True
        elif obj.source_attributes.get("unmodeled_lines"):
            obj.migration_status = "PARTIALLY_NORMALIZED"
            obj.requires_manual_review = True
        return obj

    def _context_definition(self, name: str, line: str) -> CiscoASAContext:
        context = next((item for item in self.config.contexts if item.name == name), None)
        if context is None:
            context = CiscoASAContext(name=name, raw_lines=[line], source_attributes={"raw_command": line, "raw_commands": [line]})
            self.config.contexts.append(context)
        else:
            context.raw_lines.append(line)
            context.source_attributes.setdefault("raw_commands", []).append(line)
        return context

    def parse_raw(self) -> CiscoASAConfig:
        self.config = CiscoASAConfig()
        self._nat_section_counts = {}
        lines = [line.rstrip() for line in self.raw_lines]
        self._line_contexts = self._build_context_ownership(lines)
        remarks: Dict[str, List[str]] = {}
        i = 0
        while i < len(lines):
            raw = lines[i]
            line = raw.strip()
            line_number = i + 1
            if not line or line.startswith((":", "!")):
                i += 1
                continue
            if line.lower().startswith("hostname "):
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    self.config.hostname = parts[1]
                    self.config.system_settings.hostname = parts[1]
                i += 1
                continue

            # no is stateful Cisco syntax, not a textual inverse. Only forms
            # with an unambiguous final-state meaning are applied here.
            if line.lower().startswith("no "):
                if line.lower() in {"no failover", "no logging enable"}:
                    (self._parse_failover_command if line.lower() == "no failover" else self._parse_management_command)(line, line_number)
                    i += 1
                    continue
                if line.lower().startswith("no threat-detection "):
                    self.config.connection_controls.append(self._parse_threat_detection(line, line_number))
                    i += 1
                    continue
                if line.lower().startswith("no http server "):
                    self._parse_management_command(line[3:].strip(), line_number)
                    self.config.management_settings[-1].enabled = False
                    self.config.management_settings[-1].raw_lines = [sanitize_raw_text(line)]
                    self.config.management_settings[-1].source_attributes["raw_command"] = sanitize_raw_text(line)
                    i += 1
                    continue
                if line.lower() == "no monitor-interface" or line.lower().startswith("no monitor-interface "):
                    parts = line.split()
                    name = parts[2] if len(parts) > 2 else ""
                    if name:
                        self.config.failover_config.interface_monitoring[name] = False
                    i += 1
                    continue
                negated = line[3:].strip()
                if negated.lower().startswith("access-group "):
                    binding = parse_acl_binding(negated, line_number)
                    if binding:
                        self.config.acl_bindings = [
                            item for item in self.config.acl_bindings
                            if item.raw_line.lower() != binding.raw_line.lower()
                        ]
                        self._record_unsupported(line_number, line, "Negated ACL binding is preserved as source-only state")
                        i += 1
                        continue
                self._record_unsupported(line_number, line, "Negated Cisco ASA command is preserved as source-only state")
                i += 1
                continue

            dns_group = re.match(r"^dns\s+server-group\s+(\S+)", line, re.IGNORECASE)
            if dns_group:
                group = CiscoDNSServerGroup(
                    name=dns_group.group(1), raw_lines=[line],
                    source_order=line_number,
                    source_attributes={"raw_command": line, "raw_commands": [line]},
                    migration_status="PARTIALLY_NORMALIZED", requires_manual_review=False,
                )
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    child = lines[i].strip()
                    group.raw_lines.append(child)
                    group.source_attributes["raw_commands"].append(child)
                    match = re.match(r"^name-server\s+(\S+)", child, re.IGNORECASE)
                    if match:
                        address = match.group(1)
                        try:
                            ipaddress.ip_address(address)
                        except ValueError:
                            group.migration_status = "PARSE_ERROR"
                            group.review_reasons.append("DNS name-server must be an IP address")
                            self._record_diagnostic(i + 1, child, "Malformed DNS name-server address", "dns", group.name)
                        else:
                            group.name_servers.append(address)
                    domain = re.match(r"^domain-name\s+(.+)$", child, re.IGNORECASE)
                    if domain:
                        group.domain_name = domain.group(1).strip()
                    i += 1
                self.config.dns_server_groups.append(group)
                continue

            # Source-oriented settings: keep exact command evidence and only
            # project values whose syntax is unambiguous.
            lower = line.lower()
            switch = re.match(r"^changeto\s+context\s+(\S+)$", line, re.IGNORECASE)
            if switch or re.match(r"^changeto\s+(?:system|admin)$", line, re.IGNORECASE):
                if switch:
                    self._context_definition(switch.group(1), line).source_attributes["execution_space_marker"] = True
                i += 1
                continue
            if lower.startswith(("clock timezone ", "ntp server ", "ssh ", "http ", "telnet ",
                                 "snmp-server ", "logging ", "management-access ", "domain-name ",
                                 "same-security-traffic ", "enable ", "no logging enable")) or lower == "enable":
                self._parse_management_command(line, line_number)
                i += 1
                continue
            if lower == "failover" or lower.startswith("failover "):
                children = []
                if lower.startswith("failover group "):
                    j = i + 1
                    while j < len(lines) and lines[j][:1].isspace() and not lines[j].strip().startswith("!"):
                        children.append(lines[j].strip()); j += 1
                    self._parse_failover_command(line, line_number, children)
                    i = j
                    continue
                self._parse_failover_command(line, line_number)
                i += 1
                continue
            if lower.startswith(("monitor-interface ", "no monitor-interface ")) or lower == "no monitor-interface":
                enabled = not lower.startswith("no ")
                name = line.split()[-1] if enabled else (line.split()[1] if len(line.split()) > 1 else "")
                if name:
                    self.config.failover_config.interface_monitoring[name] = enabled
                    self.config.failover_config.raw_lines.append(sanitize_raw_text(line))
                    self.config.failover_config.source_attributes.setdefault("raw_commands", []).append(sanitize_raw_text(line))
                i += 1
                continue
            if lower in {"failover", "no failover"} or lower.startswith(("dhcpd ", "dhcprelay ", "dns ", "domain-name ",
                                 "ntp ", "timezone ", "ssh ", "http ", "telnet ",
                                 "snmp-server ", "logging ", "management-access ",
                                 "failover ", "no failover", "context ", "admin-context ", "admin-context",
                                 "allocate-interface ", "allocate-interface", "config-url ", "config-url", "resource-class ", "resource-class", "threat-detection ", "conn ", "conn-",
                                 "embryonic-conn-", "per-client-",
                                 "timeout ")):
                attrs = {"raw_command": line}
                if lower.startswith(("conn ", "conn-", "embryonic-conn-", "per-client-")):
                    self.config.connection_controls.append(self._parse_global_conn(line, line_number))
                elif lower.startswith("timeout "):
                    self.config.connection_controls.append(self._parse_timeout_command(line, line_number))
                elif lower.startswith("threat-detection "):
                    self.config.connection_controls.append(self._parse_threat_detection(line, line_number))
                elif lower.startswith("dhcpd "):
                    self._parse_dhcpd_command(line, line_number)
                elif lower.startswith("dhcprelay "):
                    self._parse_dhcprelay_command(line, line_number)
                elif lower.startswith("dns "):
                    parts = line.split()
                    if len(parts) >= 3 and parts[1].lower() == "domain-lookup":
                        self.config.dns_settings.lookup_interfaces.append(parts[2])
                        self.config.dns_settings.raw_lines.append(line)
                        self.config.dns_settings.source_attributes.setdefault("raw_commands", []).append(line)
                        i += 1
                        continue
                    group = parts[1] if len(parts) > 1 else "default"
                    record = next((item for item in self.config.dns_server_groups if item.name == group), None)
                    if record is None:
                        record = CiscoDNSServerGroup(name=group, raw_lines=[], source_attributes={"raw_commands": []})
                        self.config.dns_server_groups.append(record)
                    record.raw_lines.append(line)
                    record.source_attributes.setdefault("raw_commands", []).append(line)
                elif lower.startswith("domain-name "):
                    self.config.dns_settings.domain_name = line.split(maxsplit=1)[1]
                    self.config.system_settings.domain_name = self.config.dns_settings.domain_name
                    self.config.dns_settings.raw_lines.append(line)
                    self.config.dns_settings.source_attributes.setdefault("raw_commands", []).append(line)
                elif lower in {"failover", "no failover"} or lower.startswith("failover "):
                    self.config.failover_settings.append(CiscoFailoverSetting(name="failover", setting=line.split(maxsplit=1)[0], raw_lines=[line], source_attributes=attrs))
                elif lower.startswith("context "):
                    name = line.split()[1] if len(line.split()) > 1 else "unknown"
                    self._context_definition(name, line)
                elif lower == "admin-context" or lower in {"allocate-interface", "config-url", "resource-class"} or lower.startswith(("allocate-interface ", "config-url ", "admin-context ", "resource-class ")):
                    if not self.config.contexts:
                        self._record_unsupported(line_number, line, "ASA context command has no owning context definition")
                        i += 1
                        continue
                    context = self.config.contexts[-1]
                    context.raw_lines.append(line)
                    context.source_attributes.setdefault("raw_commands", []).append(line)
                    if lower == "allocate-interface" or lower.startswith("allocate-interface "):
                        parts = line.split()
                        if len(parts) > 1:
                            context.allocated_interfaces.append(parts[1])
                        else:
                            context.migration_status = "PARSE_ERROR"
                            context.requires_manual_review = True
                            context.review_reasons.append("Malformed allocate-interface command")
                            self._record_diagnostic(line_number, line, "Malformed allocate-interface command", "context", context.name)
                    elif lower == "config-url" or lower.startswith("config-url "):
                        parts = line.split(maxsplit=1)
                        if len(parts) > 1:
                            context.config_url = parts[1]
                        else:
                            context.migration_status = "PARSE_ERROR"
                            context.requires_manual_review = True
                            context.review_reasons.append("Malformed config-url command")
                            self._record_diagnostic(line_number, line, "Malformed config-url command", "context", context.name)
                    elif lower == "resource-class" or lower.startswith("resource-class "):
                        parts = line.split(maxsplit=1)
                        if len(parts) > 1:
                            context.resource_class = parts[1]
                        else:
                            context.migration_status = "PARSE_ERROR"
                            context.requires_manual_review = True
                            context.review_reasons.append("Malformed resource-class command")
                            self._record_diagnostic(line_number, line, "Malformed resource-class command", "context", context.name)
                    else:
                        context.admin_context = True
                elif lower.startswith(("ssh ", "http ", "telnet ", "snmp-server ", "logging ", "management-access ", "domain-name ", "ntp ", "timezone ")):
                    self.config.management_settings.append(CiscoManagementSetting(name=line.split()[0], setting=line.split()[0], raw_lines=[line], source_attributes=attrs))
                else:
                    self.config.connection_controls.append(CiscoConnectionControl(name=line.split()[0], setting=line.split()[0], values=line.split()[1:], raw_lines=[line], source_attributes=attrs))
                i += 1
                continue

            match = re.match(r"^interface\s+(\S+)", line, re.IGNORECASE)
            if match:
                interface = CiscoInterface(name=match.group(1))
                interface_name = interface.name
                if re.match(r"^Port-channel(\d+)$", interface_name, re.IGNORECASE):
                    interface.interface_type = "port-channel"
                    interface.port_channel_id = int(re.search(r"(\d+)$", interface_name).group(1))
                elif re.match(r"^BVI(\d+)$", interface_name, re.IGNORECASE):
                    interface.interface_type = "bvi"
                    interface.bvi_id = int(re.search(r"(\d+)$", interface_name).group(1))
                elif re.match(r"^Redundant(\d+)$", interface_name, re.IGNORECASE):
                    interface.interface_type = "redundant"
                elif re.match(r"^\S+\.\d+$", interface_name):
                    interface.interface_type = "subinterface"
                    interface.parent_interface, _, vlan = interface_name.rpartition(".")
                    interface.vlan_id = int(vlan)
                else:
                    interface.interface_type = "physical"
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    interface.raw_lines.append(sub)
                    parts = sub.split()
                    lower = sub.lower()
                    if lower.startswith("nameif "):
                        if interface.nameif is not None:
                            interface.source_attributes.setdefault("nameif_history", []).append(interface.nameif)
                        interface.nameif = sub.split(maxsplit=1)[1]
                    elif lower == "no nameif":
                        interface.nameif = None
                        interface.source_attributes.setdefault("negated_commands", []).append(sub)
                    elif lower.startswith("security-level "):
                        if interface.security_level is not None:
                            interface.source_attributes.setdefault("security_level_history", []).append(interface.security_level)
                        try:
                            interface.security_level = int(parts[1])
                        except (IndexError, ValueError):
                            interface.migration_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                    elif lower == "no security-level":
                        interface.security_level = None
                        interface.source_attributes.setdefault("negated_commands", []).append(sub)
                    elif lower.startswith("vlan "):
                        try:
                            interface.vlan_id = int(parts[1])
                            interface.interface_type = "subinterface"
                        except (IndexError, ValueError):
                            interface.migration_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                            interface.source_attributes.setdefault("invalid_interface_settings", []).append(sub)
                    elif lower.startswith("channel-group "):
                        try:
                            interface.channel_group = int(parts[1])
                            interface.channel_group_mode = parts[3] if len(parts) >= 4 and parts[2].lower() == "mode" else None
                        except (IndexError, ValueError):
                            interface.migration_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                            interface.source_attributes.setdefault("invalid_interface_settings", []).append(sub)
                    elif lower.startswith("member-interface "):
                        interface.redundant_interface_members.append(parts[1])
                        interface.interface_type = "redundant"
                    elif lower.startswith("bridge-group "):
                        try:
                            interface.bridge_group = int(parts[1])
                            if interface.interface_type == "physical":
                                interface.interface_type = "bridge-member"
                        except (IndexError, ValueError):
                            interface.migration_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                            interface.source_attributes.setdefault("invalid_interface_settings", []).append(sub)
                    elif lower.startswith("mtu "):
                        try:
                            if interface.mtu is not None:
                                interface.source_attributes.setdefault("mtu_history", []).append(interface.mtu)
                            interface.mtu = int(parts[1])
                        except (IndexError, ValueError):
                            interface.migration_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                            interface.source_attributes.setdefault("invalid_interface_settings", []).append(sub)
                    elif lower.startswith(("routing-context ", "vrf forwarding ")):
                        _, value = sub.split(maxsplit=1)
                        if lower.startswith("vrf forwarding "):
                            interface.vrf = value
                        else:
                            interface.routing_context = value
                    elif lower.startswith("ip address "):
                        interface.source_attributes.setdefault("ip_address_history", []).append(sub)
                        if len(parts) >= 3 and parts[2].lower() == "dhcp":
                            interface.ip_mode = "dhcp"
                            interface.dhcp_setroute = "setroute" in {p.lower() for p in parts[3:]}
                            interface.source_attributes["ip_address"] = " ".join(parts[2:])
                        elif len(parts) >= 4:
                            interface.ip_mode, interface.ip, interface.mask = "static", parts[2], parts[3]
                            if len(parts) >= 6 and parts[4].lower() == "standby":
                                interface.standby_ip = parts[5]
                            elif len(parts) > 4:
                                interface.source_attributes.setdefault("unmodeled_ip_address_tokens", []).extend(parts[4:])
                    elif lower.startswith("ipv6 address "):
                        args = parts[2:]
                        if args and args[0].lower() == "autoconfig":
                            interface.ipv6_autoconfig = True
                        elif args and args[0].lower() == "dhcp":
                            interface.ipv6_dhcp = True
                            interface.ipv6_dhcp_setroute = "setroute" in {p.lower() for p in args[1:]}
                        elif args:
                            try:
                                address = str(ipaddress.IPv6Interface(args[0]))
                                standby = None
                                eui64 = "eui-64" in {p.lower() for p in args[1:]}
                                link_local = "link-local" in {p.lower() for p in args[1:]}
                                if "standby" in {p.lower() for p in args[1:]}:
                                    pos = [p.lower() for p in args].index("standby")
                                    standby = str(ipaddress.IPv6Address(args[pos + 1])) if pos + 1 < len(args) else None
                                interface.ipv6_addresses.append(CiscoIPv6Address(
                                    address=address, standby=standby, eui64=eui64,
                                    link_local=link_local, raw=sub,
                                ))
                            except (ValueError, IndexError):
                                interface.migration_status = "PARSE_ERROR"
                                interface.requires_manual_review = True
                                interface.source_attributes.setdefault("invalid_ipv6_addresses", []).append(sub)
                    elif lower == "management-only":
                        interface.management_only = True
                    elif lower.startswith("description "):
                        interface.description = sub.split(maxsplit=1)[1]
                    elif lower.startswith("policy-route route-map "):
                        parts = sub.split()
                        if len(parts) == 3:
                            interface.policy_route_maps.append(parts[2])
                        else:
                            interface.source_attributes.setdefault("invalid_routing_settings", []).append(sub)
                    elif lower == "shutdown":
                        interface.shutdown = True
                        interface.administrative_state = "down"
                    elif lower == "no shutdown":
                        interface.shutdown = False
                        interface.administrative_state = "up"
                    elif lower == "no ip address":
                        interface.ip = interface.mask = interface.ip_mode = interface.standby_ip = None
                        interface.source_attributes.setdefault("negated_commands", []).append(sub)
                    else:
                        interface.source_attributes.setdefault("unmodeled_lines", []).append(sub)
                    i += 1
                if interface.ip_mode == "static" and normalize_ipv4_network(interface.ip or "", interface.mask or "") is None:
                    interface.migration_status = "PARSE_ERROR"
                    interface.requires_manual_review = True
                    interface.source_attributes["invalid_ip_address"] = f"{interface.ip or ''} {interface.mask or ''}".strip()
                    self._record_diagnostic(line_number, line, "Invalid interface IPv4 address/netmask", "interface", interface.name)
                elif interface.source_attributes.get("unmodeled_lines"):
                    interface.requires_manual_review = True
                    interface.migration_status = "PARTIALLY_NORMALIZED"
                if interface.dhcp_setroute or interface.ipv6_dhcp_setroute or interface.management_only or interface.ipv6_addresses:
                    interface.requires_manual_review = True
                    if interface.migration_status == "NORMALIZED":
                        interface.migration_status = "PARTIALLY_NORMALIZED"
                self.config.interfaces.append(self._with_source_context(interface, line_number))
                continue

            match = re.match(r"^object\s+network\s+(\S+)", line, re.IGNORECASE)
            if match:
                i += 1
                block: List[str] = []
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    block.append(lines[i].strip())
                    i += 1
                obj = self._parse_network_object(match.group(1), block)
                self.config.network_objects.append(self._with_source_context(obj, line_number))
                if obj.migration_status == "PARSE_ERROR":
                    self._record_diagnostic(
                        line_number, line, "Network object contains malformed or incomplete address syntax",
                        "object network", obj.name,
                    )
                for nat_line in obj.nat_lines:
                    self._parse_nat_line(nat_line, line_number, owning_object=obj.name)
                continue

            match = re.match(r"^object-group\s+network\s+(\S+)", line, re.IGNORECASE)
            if match:
                group = CiscoNetworkGroup(name=match.group(1))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    sub_line_number = i + 1
                    group.raw_lines.append(sub)
                    parts = sub.split()
                    lower = sub.lower()
                    member = None
                    error = None
                    if lower.startswith("network-object"):
                        if len(parts) == 3 and parts[1].lower() == "host":
                            try:
                                address = ipaddress.ip_address(parts[2])
                                member = CiscoNetworkGroupMember(
                                    type="host", value=str(address), address_family=f"ipv{address.version}",
                                    raw=sub, resolved=True, resolved_target_type="host",
                                )
                                group.members.append(_safe_name("asa_inline_host", str(address)))
                            except ValueError:
                                error = f"Invalid host IP: {parts[2]}"
                        elif len(parts) == 3 and parts[1].lower() == "object":
                            member = CiscoNetworkGroupMember(type="network_object", value=parts[2], raw=sub)
                            group.members.append(parts[2])
                        elif len(parts) == 2 and ":" in parts[1]:
                            try:
                                network = ipaddress.IPv6Network(parts[1], strict=False)
                                member = CiscoNetworkGroupMember(
                                    type="inline_network", value=str(network), address_family="ipv6",
                                    raw=sub, resolved=True, resolved_target_type="network",
                                )
                                group.members.append(_safe_name("asa_inline_net", str(network)))
                            except ValueError:
                                error = f"Invalid IPv6 prefix: {parts[1]}"
                        elif len(parts) == 3:
                            try:
                                address = ipaddress.ip_address(parts[1])
                            except ValueError:
                                error = f"Invalid IPv4 network address: {parts[1]}"
                            else:
                                if address.version != 4 or ":" in parts[2]:
                                    error = "IPv4/IPv6 mismatch"
                                else:
                                    value = normalize_ipv4_network(parts[1], parts[2])
                                    if value is None:
                                        error = f"Invalid IPv4 netmask: {parts[2]}"
                                    else:
                                        member = CiscoNetworkGroupMember(
                                            type="inline_network", value=value, address_family="ipv4",
                                            raw=sub, resolved=True, resolved_target_type="network",
                                        )
                                        group.members.append(_safe_name("asa_inline_net", value))
                        else:
                            error = "Invalid network-object operand count or syntax"
                    elif lower.startswith("group-object"):
                        if len(parts) == 2:
                            member = CiscoNetworkGroupMember(type="network_group", value=parts[1], raw=sub)
                            group.members.append(parts[1])
                        else:
                            error = "Invalid group-object operand count or syntax"
                    elif lower.startswith("description "):
                        group.description = sub.split(maxsplit=1)[1]
                    else:
                        group.migration_status = "PARTIALLY_NORMALIZED"
                        group.requires_manual_review = True
                        group.source_attributes.setdefault("unmodeled_lines", []).append(sub)
                    if member is not None:
                        group.member_entries.append(member)
                    if error:
                        group.migration_status = "PARSE_ERROR"
                        group.requires_manual_review = True
                        group.review_reasons.append(error)
                        group.source_attributes.setdefault("invalid_members", []).append({"raw": sub, "reason": error})
                        self._record_diagnostic(sub_line_number, sub, error, "object-group network", group.name)
                    i += 1
                self.config.network_groups.append(self._with_source_context(group, line_number))
                continue

            match = re.match(r"^object\s+network-service\s+(\S+)", line, re.IGNORECASE)
            if match:
                obj = CiscoNetworkServiceObject(name=match.group(1))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    obj.raw_lines.append(sub)
                    parts = sub.split()
                    if sub.lower().startswith("description "):
                        obj.description = sub.split(maxsplit=1)[1]
                    elif parts:
                        obj.members.append(sub)
                    i += 1
                obj.source_attributes["combined_address_service_semantics"] = True
                self.config.network_service_objects.append(self._with_source_context(obj, line_number))
                continue

            match = re.match(r"^object-group\s+network-service\s+(\S+)", line, re.IGNORECASE)
            if match:
                group = CiscoNetworkServiceObject(name=match.group(1))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    group.raw_lines.append(sub)
                    if sub.lower().startswith("description "):
                        group.description = sub.split(maxsplit=1)[1]
                    else:
                        group.members.append(sub)
                    i += 1
                group.source_attributes["combined_address_service_semantics"] = True
                self.config.network_service_groups.append(self._with_source_context(group, line_number))
                continue

            match = re.match(r"^object-group\s+(protocol|icmp-type|user|security)\s+(\S+)", line, re.IGNORECASE)
            if match:
                group_type, group_name = match.group(1).lower(), match.group(2)
                group = CiscoNamedGroup(name=group_name, group_type=group_type)
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    group.raw_lines.append(sub)
                    if sub.lower().startswith("description "):
                        group.description = sub.split(maxsplit=1)[1]
                    else:
                        group.members.append(sub)
                        parts = sub.split()
                        if group_type == "protocol" and parts:
                            if parts[0].lower() == "protocol-object" and len(parts) == 2:
                                group.member_entries.append(CiscoNamedGroupMember(
                                    type="protocol", value=parts[1], raw=sub, resolved=True,
                                    resolved_target_type="protocol",
                                ))
                            elif parts[0].lower() == "group-object" and len(parts) == 2:
                                group.member_entries.append(CiscoNamedGroupMember(
                                    type="protocol_group", value=parts[1], raw=sub,
                                ))
                        elif group_type == "icmp-type" and parts:
                            if parts[0].lower() == "icmp-object" and len(parts) == 2:
                                group.member_entries.append(CiscoNamedGroupMember(
                                    type="icmp_type", value=parts[1], raw=sub, resolved=True,
                                    resolved_target_type="icmp_type",
                                ))
                            elif parts[0].lower() == "group-object" and len(parts) == 2:
                                group.member_entries.append(CiscoNamedGroupMember(
                                    type="icmp_group", value=parts[1], raw=sub,
                                ))
                    i += 1
                target = {
                    "protocol": self.config.protocol_groups,
                    "icmp-type": self.config.icmp_type_groups,
                    "user": self.config.user_groups,
                    "security": self.config.security_groups,
                }[group_type]
                target.append(self._with_source_context(group, line_number))
                continue

            match = re.match(r"^object\s+service\s+(\S+)", line, re.IGNORECASE)
            if match:
                obj = CiscoServiceObject(name=match.group(1))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    obj.raw_lines.append(sub)
                    if sub.lower().startswith("service "):
                        ports, error = parse_service_clause(sub.split()[1:])
                        obj.ports.extend(ports)
                        if error:
                            obj.migration_status = "PARSE_ERROR"
                            obj.requires_manual_review = True
                    elif sub.lower().startswith("description "):
                        obj.description = sub.split(maxsplit=1)[1]
                    else:
                        obj.migration_status = "PARTIALLY_NORMALIZED"
                        obj.requires_manual_review = True
                    i += 1
                if not obj.ports:
                    obj.migration_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
                obj.source_attributes["raw_lines"] = obj.raw_lines
                self.config.service_objects.append(self._with_source_context(obj, line_number))
                if obj.migration_status == "PARSE_ERROR":
                    self._record_diagnostic(line_number, line, "Service object contains malformed or missing service syntax", "object service", obj.name)
                continue

            match = re.match(r"^object-group\s+service\s+(\S+)(?:\s+(\S+))?", line, re.IGNORECASE)
            if match:
                group = CiscoServiceGroup(name=match.group(1), protocol=match.group(2))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    group.raw_lines.append(sub)
                    parts = sub.split()
                    lower = sub.lower()
                    if lower.startswith("group-object ") and len(parts) >= 2:
                        group.members.append(parts[1])
                        group.member_entries.append(CiscoServiceGroupMember(
                            type="service_group", value=parts[1], raw=sub,
                        ))
                    elif lower.startswith("service-object object ") and len(parts) >= 3:
                        group.members.append(parts[2])
                        group.member_entries.append(CiscoServiceGroupMember(
                            type="service_object", value=parts[2], raw=sub,
                        ))
                    elif lower.startswith("service-object "):
                        ports, error = parse_service_clause(parts[1:])
                        group.service_objects.extend(ports)
                        for port in ports:
                            group.member_entries.append(CiscoServiceGroupMember(
                                type="inline_service", protocol=port.protocol,
                                source=port.source, destination=port.destination,
                                icmp_type=port.icmp_type, icmp_code=port.icmp_code, raw=sub,
                            ))
                        if error:
                            group.migration_status = "PARSE_ERROR"
                            group.requires_manual_review = True
                            group.review_reasons.append(error)
                    elif lower.startswith("port-object "):
                        if not group.protocol:
                            group.migration_status = "PARTIALLY_NORMALIZED"
                            group.requires_manual_review = True
                            group.review_reasons.append("port-object requires a declared service-group protocol")
                            group.member_entries.append(CiscoServiceGroupMember(
                                type="port_object", raw=sub,
                            ))
                        else:
                            pseudo = [group.protocol, "destination", *parts[1:]]
                            ports, error = parse_service_clause(pseudo)
                            group.service_objects.extend(ports)
                            for port in ports:
                                group.member_entries.append(CiscoServiceGroupMember(
                                    type="port_object", protocol=port.protocol,
                                    destination=port.destination, raw=sub,
                                ))
                            if error:
                                group.migration_status = "PARSE_ERROR"
                                group.requires_manual_review = True
                                group.review_reasons.append(error)
                    elif lower.startswith("description "):
                        group.description = sub.split(maxsplit=1)[1]
                    else:
                        group.migration_status = "PARTIALLY_NORMALIZED"
                        group.requires_manual_review = True
                    i += 1
                self.config.service_groups.append(self._with_source_context(group, line_number))
                if group.migration_status == "PARSE_ERROR":
                    self._record_diagnostic(line_number, line, "Service group contains malformed service syntax", "object-group service", group.name)
                group.source_attributes["raw_lines"] = group.raw_lines
                continue

            match = re.match(r"^time-range\s+(\S+)", line, re.IGNORECASE)
            if match:
                schedule = CiscoTimeRange(name=match.group(1))
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    schedule.raw_lines.append(sub)
                    parts = sub.split()
                    lower_parts = [part.lower() for part in parts]
                    if lower_parts and lower_parts[0] == "absolute":
                        clause, error = self._parse_time_range_absolute_clause(sub, len(schedule.clauses) + 1)
                        schedule.clauses.append(clause)
                        if error:
                            schedule.migration_status = "PARSE_ERROR"
                            schedule.requires_manual_review = True
                            schedule.review_reasons.append(error)
                    elif lower_parts and lower_parts[0] == "periodic":
                        clause, error = self._parse_time_range_periodic_clause(sub, len(schedule.clauses) + 1)
                        schedule.clauses.append(clause)
                        if error:
                            schedule.migration_status = "PARSE_ERROR"
                            schedule.requires_manual_review = True
                            schedule.review_reasons.append(error)
                    else:
                        schedule.migration_status = "PARTIALLY_NORMALIZED"
                        schedule.requires_manual_review = True
                        schedule.review_reasons.append(f"Unmodeled time-range clause: {sub}")
                        schedule.source_attributes.setdefault("unmodeled_lines", []).append(sub)
                    i += 1
                schedule.source_attributes["clauses"] = [item.model_dump() for item in schedule.clauses]
                self.config.time_ranges.append(self._with_source_context(schedule, line_number))
                if schedule.migration_status == "PARSE_ERROR":
                    self._record_diagnostic(line_number, line, "; ".join(schedule.review_reasons), "time-range", schedule.name)
                continue

            if line.lower().startswith("access-list "):
                rule, error = parse_acl_line(line, line_number, remarks)
                if rule:
                    self.config.access_rules.append(self._with_source_context(rule, line_number))
                    if rule.migration_status == "PARSE_ERROR":
                        self._record_diagnostic(line_number, line, "; ".join(rule.review_reasons), "access-list", rule.acl_name)
                if error:
                    if error.startswith("Unsupported ACL type"):
                        self._record_unsupported(line_number, line, error)
                    else:
                        self._record_diagnostic(line_number, line, error, "access-list")
                i += 1
                continue
            if line.lower().startswith("access-group "):
                binding = parse_acl_binding(line, line_number)
                if binding:
                    self.config.acl_bindings.append(self._with_source_context(binding, line_number))
                    self._record_acl_consumer(binding.acl_name, "access-group", line_number, line)
                else:
                    self._record_diagnostic(line_number, line, "Malformed access-group binding", "access-group")
                i += 1
                continue
            consumer_patterns = (
                (r"^crypto\s+map\s+\S+\s+\S+\s+match\s+address\s+(\S+)", "crypto-map"),
                (r"^match\s+access-list\s+(\S+)", "class-map"),
                (r"^capture\s+\S+\s+.*\baccess-list\s+(\S+)", "capture"),
                (r"^aaa\s+.*\bmatch\s+(\S+)", "aaa"),
            )
            consumer_match = next(((re.match(pattern, line, re.IGNORECASE), kind) for pattern, kind in consumer_patterns if re.match(pattern, line, re.IGNORECASE)), None)
            if consumer_match:
                match_obj, kind = consumer_match
                self._record_acl_consumer(match_obj.group(1), kind, line_number, line)
                self._record_unsupported(line_number, line, f"{kind} ACL consumer is preserved as extract-only")
                i += 1
                continue
            if line.lower().startswith("nat "):
                self._parse_nat_line(line, line_number)
                i += 1
                continue
            if line.lower().startswith(("route ", "ipv6 route ")):
                route, error = self._parse_route_line(line)
                if route:
                    self.config.static_routes.append(self._with_source_context(route, line_number))
                if error:
                    self._record_diagnostic(line_number, line, error, "ipv6 route" if line.lower().startswith("ipv6") else "route")
                i += 1
                continue
            route_map_match = re.match(r"^route-map\s+(\S+)\s+(permit|deny)\s+(\d+)$", line, re.IGNORECASE)
            if route_map_match:
                route_map = CiscoRouteMap(name=route_map_match.group(1), raw_lines=[line])
                rule = CiscoRouteMapRule(
                    name=route_map.name, sequence=int(route_map_match.group(3)),
                    action=route_map_match.group(2).lower(), raw_lines=[line],
                    source_attributes={"raw_header": line},
                )
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    rule.raw_lines.append(sub)
                    route_map.raw_lines.append(sub)
                    match_acl = re.match(r"^match\s+access-list\s+(\S+)$", sub, re.IGNORECASE)
                    next_hop = re.match(r"^set\s+ip\s+next-hop\s+(\S+)$", sub, re.IGNORECASE)
                    set_interface = re.match(r"^set\s+interface\s+(\S+)$", sub, re.IGNORECASE)
                    if match_acl:
                        rule.match_acl = match_acl.group(1)
                    elif next_hop:
                        rule.set_next_hop = next_hop.group(1)
                    elif set_interface:
                        rule.set_interface = set_interface.group(1)
                    else:
                        rule.raw_options.append(sub)
                    i += 1
                route_map = self._with_source_context(route_map, line_number)
                existing = next((item for item in self.config.route_maps if item.name == route_map.name and item.source_context == route_map.source_context), None)
                if existing is None:
                    route_map.rules.append(rule)
                    self.config.route_maps.append(route_map)
                else:
                    existing.rules.append(rule)
                    existing.raw_lines.extend(route_map.raw_lines)
                continue
            if not raw[:1].isspace() and re.match(r"^(?:class-map|policy-map|tcp-map)\b", line, re.IGNORECASE):
                i += 1
                while i < len(lines) and lines[i][:1].isspace() and not lines[i].strip().startswith("!"):
                    i += 1
                continue
            if not raw[:1].isspace() and line.lower().startswith("service-policy"):
                i += 1
                continue
            self._record_unsupported(line_number, line, "No Cisco ASA extraction handler")
            i += 1
        self._parse_source_only_records(lines)
        apply_reference_issues(self.config, validate_references(self.config))
        self._compute_object_nat_order()
        return self.config

    def _compute_object_nat_order(self) -> None:
        """Resolve Section 2 precedence after all network objects are known."""
        objects = {(item.source_context, item.name): item for item in self.config.network_objects}
        for rule in self.config.nat_rules:
            if rule.section != "object":
                rule.effective_source_order = (
                    rule.section_order or 0
                ) * 1_000_000 + (rule.sequence if rule.sequence is not None else rule.source_order_within_section or 0)
                continue

            owner = objects.get((rule.source_context, rule.owning_object or ""))
            details: Dict[str, Any] = {
                "section": rule.section,
                "source_mode": rule.source_mode,
                "real_source": rule.real_source,
                "owning_object": rule.owning_object,
                "object_name": rule.owning_object,
                "source_order": rule.source_order,
                "source_order_within_section": rule.source_order_within_section,
                "static_before_dynamic": rule.source_mode == "static",
            }
            if rule.source_mode not in {"static", "dynamic"}:
                rule.object_nat_precedence = None
                rule.object_nat_specificity = None
                rule.requires_manual_review = True
                if rule.migration_status != "PARSE_ERROR":
                    rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.append("Object NAT type is unresolved")
            elif owner is None or owner.type is None or owner.value is None or owner.migration_status == "PARSE_ERROR":
                rule.object_nat_precedence = 0 if rule.source_mode == "static" else 1
                rule.object_nat_specificity = None
                rule.requires_manual_review = True
                if rule.migration_status != "PARSE_ERROR":
                    rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.append("Object NAT owning object is missing or malformed")
            else:
                details["address_kind"] = owner.type
                if owner.type == "fqdn":
                    rule.object_nat_specificity = None
                    rule.requires_manual_review = True
                    if rule.migration_status != "PARSE_ERROR":
                        rule.migration_status = "PARTIALLY_NORMALIZED"
                    rule.review_reasons.append("FQDN object NAT address size and lowest IP are unresolved")
                else:
                    try:
                        if owner.type == "host":
                            address = ipaddress.ip_address(owner.value)
                            quantity, lowest, specificity = 1, int(address), address.max_prefixlen
                        elif owner.type == "subnet":
                            network = ipaddress.ip_network(owner.value, strict=False)
                            quantity, lowest, specificity = network.num_addresses, int(network.network_address), network.prefixlen
                        elif owner.type == "range":
                            start, end = (ipaddress.ip_address(value) for value in owner.value.split("-", 1))
                            if start.version != end.version or int(start) > int(end):
                                raise ValueError("invalid address range")
                            quantity, lowest, specificity = int(end) - int(start) + 1, int(start), None
                        else:
                            raise ValueError("unsupported address type")
                        details.update({
                            "address_quantity": quantity,
                            "lowest_real_ip": str(ipaddress.ip_address(lowest)),
                            "lowest_real_ip_int": lowest,
                            "address_prefix_length": specificity,
                        })
                        rule.object_nat_specificity = quantity
                    except ValueError:
                        rule.requires_manual_review = True
                        if rule.migration_status != "PARSE_ERROR":
                            rule.migration_status = "PARTIALLY_NORMALIZED"
                        rule.review_reasons.append("Object NAT owning object address characteristics are unresolved")
                rule.object_nat_precedence = 0 if rule.source_mode == "static" else 1

            details.update({
                "object_nat_precedence": rule.object_nat_precedence,
                "object_nat_specificity": rule.object_nat_specificity,
            })
            rule.effective_order_inputs = details

        def key(rule: CiscoNATRule) -> tuple:
            if rule.section == "manual":
                return (1, rule.sequence if rule.sequence is not None else 1_000_000, rule.source_order or 0)
            if rule.section == "object":
                inputs = rule.effective_order_inputs
                quantity = inputs.get("address_quantity", 2**129)
                lowest = inputs.get("lowest_real_ip_int", 2**129)
                return (
                    2, rule.object_nat_precedence if rule.object_nat_precedence is not None else 2,
                    quantity,
                    lowest,
                    (rule.owning_object or "").casefold(), rule.source_order or 0,
                )
            return (3, rule.sequence if rule.sequence is not None else 1_000_000, rule.source_order or 0)

        for index, rule in enumerate(sorted(self.config.nat_rules, key=key), 1):
            rule.effective_source_order = index

    def _parse_route_line(self, line: str) -> Tuple[Optional[CiscoStaticRoute], Optional[str]]:
        tokens = line.split()
        ipv6 = len(tokens) >= 2 and tokens[0].lower() == "ipv6" and tokens[1].lower() == "route"
        index = 2 if ipv6 else 1
        required = 3 if ipv6 else 4
        interface = tokens[index] if len(tokens) > index else None
        if len(tokens) - index < required:
            return CiscoStaticRoute(interface=interface, address_family="ipv6" if ipv6 else "ipv4", raw_line=line,
                                    migration_status="PARSE_ERROR", requires_manual_review=True), "Incomplete static route statement"
        if ipv6:
            destination, mask, gateway = tokens[index + 1], None, tokens[index + 2]
            index += 3
            try:
                destination = str(ipaddress.IPv6Network(destination, strict=False))
                ipaddress.IPv6Address(gateway)
            except ValueError:
                return CiscoStaticRoute(
                    interface=interface, destination=destination, gateway=gateway,
                    address_family="ipv6", raw_line=line, migration_status="PARSE_ERROR",
                    requires_manual_review=True,
                ), "Invalid IPv6 route prefix or next hop"
        else:
            destination, mask, gateway = tokens[index + 1:index + 4]
            index += 4
            try:
                ipaddress.IPv4Address(gateway)
            except ValueError:
                return CiscoStaticRoute(interface=interface, destination=destination, mask=mask, gateway=gateway,
                                        address_family="ipv4", raw_line=line, migration_status="PARSE_ERROR",
                                        requires_manual_review=True), "Invalid IPv4 route next hop"
        route = CiscoStaticRoute(
            interface=interface, destination=destination, mask=mask, gateway=gateway,
            address_family="ipv6" if ipv6 else "ipv4", raw_line=line,
        )
        if not ipv6 and normalize_ipv4_network(destination, mask or "") is None:
            route.migration_status = "PARSE_ERROR"
            route.requires_manual_review = True
            return route, "Invalid IPv4 route destination/netmask"
        while index < len(tokens):
            token = tokens[index].lower()
            if token.isdigit() and route.administrative_distance is None:
                route.administrative_distance = int(token)
                index += 1
            elif token == "track" and index + 1 < len(tokens) and tokens[index + 1].isdigit():
                route.track_id = int(tokens[index + 1])
                index += 2
            elif token == "tunneled":
                route.tunneled = True
                index += 1
            else:
                route.raw_options.append(tokens[index])
                index += 1
        if route.track_id is not None:
            route.review_reasons.append("Route tracking dependency requires target review")
        if route.tunneled:
            route.review_reasons.append("ASA tunneled route semantics require target review")
        if route.raw_options:
            route.review_reasons.append(f"Unparsed route options: {' '.join(route.raw_options)}")
        if route.review_reasons:
            route.migration_status = "PARTIALLY_NORMALIZED"
            route.requires_manual_review = True
        return route, None

    def _parse_nat_line(self, line: str, line_number: int, owning_object: Optional[str] = None) -> None:
        match = re.match(r"^nat(?:\s+\(([^,]*),([^)]*)\))?\s+(.+)$", line, re.IGNORECASE)
        if not match:
            self._record_diagnostic(line_number, line, "Malformed NAT statement", "nat")
            return
        src_if = match.group(1).strip() or None if match.group(1) is not None else None
        dst_if = match.group(2).strip() or None if match.group(2) is not None else None
        tail = match.group(3).split()
        section = "after-auto" if tail and tail[0].lower() == "after-auto" else "object" if owning_object else "manual"
        if section == "after-auto":
            tail = tail[1:]
        sequence = None
        if tail and tail[0].isdigit():
            sequence = int(tail.pop(0))
        self._nat_section_counts[section] = self._nat_section_counts.get(section, 0) + 1
        within = self._nat_section_counts[section]
        section_order = {"manual": 1, "object": 2, "after-auto": 3}[section]
        rule = CiscoNATRule(
            name=f"nat_{section}_{line_number}", source_interface=src_if, destination_interface=dst_if,
            section=section, sequence=sequence, source_sequence=sequence, owning_object=owning_object,
            source_order=line_number, source_order_within_section=within, section_order=section_order,
            raw_line=line,
            source_attributes={"raw_command": line},
        )
        index = 0

        def parse_mapped_source(position: int) -> int:
            if position >= len(tail):
                return position
            token = tail[position]
            lower = token.lower()
            if lower == "interface":
                rule.mapped_source_mode = "interface"
                rule.mapped_source = "interface"
                position += 1
                if position < len(tail) and tail[position].lower() == "ipv6":
                    rule.mapped_source_address_family = "ipv6"
                    position += 1
                return position
            if lower == "pat-pool":
                rule.mapped_source_mode = "pat_pool"
                if position + 1 < len(tail):
                    rule.pat_pool = tail[position + 1]
                    rule.mapped_source = rule.pat_pool
                    position += 2
                    while position < len(tail) and tail[position].lower() in {
                        "round-robin", "extended", "flat", "include-reserve", "block-allocation"
                    }:
                        rule.pat_pool_options.append(tail[position])
                        position += 1
                return position
            rule.mapped_source_mode = rule.source_mode
            rule.mapped_source = token
            return position + 1

        if owning_object:
            if index < len(tail) and tail[index].lower() in {"static", "dynamic"}:
                rule.source_mode = tail[index].lower()
                rule.real_source = owning_object
                index = parse_mapped_source(index + 1)
            else:
                rule.review_reasons.append("Object NAT is missing static/dynamic translation mode")
        elif index < len(tail) and tail[index].lower() == "source":
            if index + 2 < len(tail):
                rule.source_mode = tail[index + 1].lower()
                rule.real_source = tail[index + 2]
                index = parse_mapped_source(index + 3)
            else:
                index = len(tail)
                rule.review_reasons.append("Incomplete NAT source clause")

        if index < len(tail) and tail[index].lower() == "destination":
            if index + 3 < len(tail):
                rule.destination_mode = tail[index + 1].lower()
                # Cisco twice-NAT grammar is destination static MAPPED REAL.
                rule.mapped_destination = tail[index + 2]
                rule.real_destination = tail[index + 3]
                index += 4
            else:
                rule.review_reasons.append("Incomplete NAT destination clause")
                index = len(tail)

        if index < len(tail) and tail[index].lower() == "service":
            if index + 3 < len(tail):
                rule.service_protocol = tail[index + 1].lower()
                rule.original_service = tail[index + 2]
                rule.translated_service = tail[index + 3]
                index += 4
            elif index + 2 < len(tail):
                rule.original_service = tail[index + 1]
                rule.translated_service = tail[index + 2]
                index += 3
            else:
                rule.review_reasons.append("Incomplete NAT service translation")
                index = len(tail)

        option_names = {
            "dns", "no-proxy-arp", "route-lookup", "unidirectional", "inactive", "net-to-net",
            "round-robin", "extended", "flat", "include-reserve", "block-allocation",
        }
        while index < len(tail):
            token = tail[index]
            lower = token.lower()
            if lower == "description":
                rule.description = " ".join(tail[index + 1:]) or None
                index = len(tail)
            elif lower in option_names:
                rule.options.append(lower)
                if lower in {"round-robin", "extended", "flat", "include-reserve", "block-allocation"}:
                    rule.pat_pool_options.append(lower)
                index += 1
            else:
                rule.raw_options.append(token)
                index += 1

        rule.dns = "dns" in rule.options
        rule.no_proxy_arp = "no-proxy-arp" in rule.options
        rule.route_lookup = "route-lookup" in rule.options
        rule.unidirectional = "unidirectional" in rule.options
        rule.inactive = "inactive" in rule.options
        rule.net_to_net = "net-to-net" in rule.options

        if sequence == 0 and len(tail) >= 2 and tail[0].lower() == "access-list":
            rule.access_list = tail[1]
            rule.identity_nat = rule.nat_exemption = True
            rule.migration_status = "EXTRACT_ONLY"
            rule.requires_manual_review = True
            rule.review_reasons.append("ASA NAT exemption is preserved as source-only access-list semantics")
        elif rule.source_mode == "static" and rule.real_source == rule.mapped_source:
            rule.identity_nat = True
        elif not rule.real_source or not rule.mapped_source:
            rule.migration_status = "PARSE_ERROR"
            rule.requires_manual_review = True
            rule.review_reasons.append("NAT source translation operands are incomplete")
        partial_details = []
        if rule.destination_mode:
            partial_details.append("twice-NAT destination translation")
        if rule.original_service:
            partial_details.append("service/PAT translation")
        if rule.mapped_source_address_family == "ipv6":
            partial_details.append("interface IPv6 translation")
        if rule.pat_pool_options:
            partial_details.append(f"PAT pool modifiers: {' '.join(rule.pat_pool_options)}")
        noncanonical_options = [opt for opt in rule.options if opt != "inactive"]
        if noncanonical_options:
            partial_details.append(f"NAT modifiers: {' '.join(noncanonical_options)}")
        if rule.raw_options:
            partial_details.append(f"Unparsed NAT tokens: {' '.join(rule.raw_options)}")
        if partial_details and rule.migration_status != "PARSE_ERROR":
            rule.migration_status = "PARTIALLY_NORMALIZED"
            rule.requires_manual_review = True
            rule.review_reasons.extend(partial_details)
        if rule.nat_exemption:
            rule.migration_status = "EXTRACT_ONLY"
        if rule.migration_status == "PARSE_ERROR":
            self._record_diagnostic(line_number, line, "; ".join(rule.review_reasons), "nat", owning_object)
        self.config.nat_rules.append(self._with_source_context(rule, line_number))

    @staticmethod
    def _protocol(protocol: str) -> Optional[ServiceProtocol]:
        return {
            "tcp": ServiceProtocol.TCP, "udp": ServiceProtocol.UDP, "sctp": ServiceProtocol.SCTP,
            "icmp": ServiceProtocol.ICMP, "icmp6": ServiceProtocol.ICMPV6, "ip": ServiceProtocol.IP,
        }.get(protocol.lower())

    @staticmethod
    def _port_values(spec: Optional[CiscoPortSpec]) -> Optional[List[str]]:
        if spec is None:
            return []
        if spec.operator == "eq" and spec.values:
            return [spec.values[0]]
        if spec.operator == "range" and len(spec.values) == 2:
            return [f"{spec.values[0]}-{spec.values[1]}"]
        if spec.operator in {"object", "object-group"} and spec.values:
            return [spec.object_name or spec.values[0]]
        if spec.operator in {"lt", "gt", "neq"} and spec.values:
            try:
                value = int(spec.values[0])
            except ValueError:
                # Cisco-local names must not be guessed as IANA ports.
                return [f"{spec.operator} {spec.values[0]}"]
            if not 1 <= value <= 65535:
                return None
            if spec.operator == "lt":
                return [f"1-{value - 1}"] if value > 1 else []
            if spec.operator == "gt":
                return [f"{value + 1}-65535"] if value < 65535 else []
            result = []
            if value > 1:
                result.append(f"1-{value - 1}")
            if value < 65535:
                result.append(f"{value + 1}-65535")
            return result
        return None

    def _ir_service_ports(self, ports: Iterable[CiscoServicePort]) -> Tuple[List[IRServicePort], List[str]]:
        result: List[IRServicePort] = []
        errors: List[str] = []
        for item in ports:
            protocol = self._protocol(item.protocol)
            if protocol is None:
                protocol = ServiceProtocol.IP
                errors.append(f"IP protocol '{item.protocol}' is source-preserved and requires target capability review")
            destinations = self._port_values(item.destination)
            sources = self._port_values(item.source)
            if item.destination and destinations is None:
                errors.append(f"Unsupported destination-port operator '{item.destination.operator}'")
                continue
            if item.source and sources is None:
                errors.append(f"Unsupported source-port operator '{item.source.operator}'")
                continue
            if item.destination is None:
                destinations = ["any" if protocol in {ServiceProtocol.ICMP, ServiceProtocol.ICMPV6, ServiceProtocol.IP} else "1-65535"]
            elif not destinations:
                errors.append("Destination-port expression matches no ports")
                continue
            if item.source is None:
                sources = [None]
            elif not sources:
                errors.append("Source-port expression matches no ports")
                continue
            icmp_type = int(item.icmp_type) if item.icmp_type and item.icmp_type.isdigit() else None
            for destination in destinations:
                for source in sources:
                    result.append(IRServicePort(
                        protocol=protocol, port=destination, source_port=source, raw_source_value=item.raw,
                        icmptype=icmp_type, icmpcode=item.icmp_code,
                    ))
            if item.icmp_type and icmp_type is None:
                errors.append(f"Named ICMP type '{item.icmp_type}' requires review")
        return result, errors

    @staticmethod
    def _validate_time_range_clock(value: str) -> bool:
        return bool(re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value))

    @staticmethod
    def _normalize_time_range_days(values: List[str]) -> Optional[List[str]]:
        aliases = {
            "mon": "monday", "monday": "monday", "tue": "tuesday", "tuesday": "tuesday",
            "wed": "wednesday", "wednesday": "wednesday", "thu": "thursday", "thursday": "thursday",
            "fri": "friday", "friday": "friday", "sat": "saturday", "saturday": "saturday",
            "sun": "sunday", "sunday": "sunday",
        }
        if len(values) == 1 and values[0].lower() in {"daily", "weekdays", "weekend"}:
            return [values[0].lower()]
        normalized = [aliases.get(value.lower()) for value in values]
        return normalized if normalized and all(normalized) else None

    @classmethod
    def _parse_time_range_absolute_clause(cls, raw: str, source_order: int) -> Tuple[CiscoTimeRangeClause, Optional[str]]:
        parts = raw.split()
        clause = CiscoTimeRangeClause(clause_type="absolute", raw=raw, source_order=source_order)
        if len(parts) < 2 or parts[1].lower() not in {"start", "end"}:
            return clause, "Malformed absolute time-range clause"

        def timestamp(tokens: List[str]) -> Optional[str]:
            if len(tokens) != 4 or not cls._validate_time_range_clock(tokens[0]):
                return None
            months = {name.lower(): number for number, name in enumerate(
                ("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"), 1
            )}
            if not tokens[1].isdigit() or tokens[2].lower() not in months or not tokens[3].isdigit():
                return None
            try:
                date(int(tokens[3]), months[tokens[2].lower()], int(tokens[1]))
            except ValueError:
                return None
            return " ".join(tokens)

        if parts[1].lower() == "start":
            start_tokens = parts[2:6]
            clause.start = timestamp(start_tokens)
            if clause.start is None:
                return clause, "Malformed absolute start value"
            if len(parts) > 6:
                if len(parts) != 11 or parts[6].lower() != "end":
                    return clause, "Malformed absolute end value"
                clause.end = timestamp(parts[7:11])
                if clause.end is None:
                    return clause, "Malformed absolute end value"
        else:
            if len(parts) != 6:
                return clause, "Malformed absolute end value"
            clause.end = timestamp(parts[2:6])
            if clause.end is None:
                return clause, "Malformed absolute end value"
        return clause, None

    @classmethod
    def _parse_time_range_periodic_clause(cls, raw: str, source_order: int) -> Tuple[CiscoTimeRangeClause, Optional[str]]:
        parts = raw.split()
        clause = CiscoTimeRangeClause(clause_type="periodic", raw=raw, source_order=source_order)
        if len(parts) < 5 or parts[0].lower() != "periodic":
            return clause, "Malformed periodic time-range clause"
        to_positions = [index for index, value in enumerate(parts) if value.lower() == "to"]
        to_index = to_positions[0] if len(to_positions) == 1 else -1
        if to_index < 3 or to_index + 2 != len(parts):
            return clause, "Malformed periodic time-range clause"
        days = cls._normalize_time_range_days(parts[1:to_index - 1])
        if days is None:
            return clause, "Invalid periodic day selector"
        if not cls._validate_time_range_clock(parts[to_index - 1]) or not cls._validate_time_range_clock(parts[to_index + 1]):
            return clause, "Invalid periodic clock value"
        clause.days, clause.start, clause.end = days, parts[to_index - 1], parts[to_index + 1]
        return clause, None

    def transform_to_ir(self) -> IRConfig:
        cfg = self.parse_raw()
        ir = IRConfig(metadata=IRMetadata(hostname=cfg.hostname, source_vendor="cisco_asa", source_product="Cisco ASA"))

        explicit_zones: Dict[tuple[Optional[str], str], IRZone] = {}
        for interface in cfg.interfaces:
            zone = interface.nameif or self.zone_mapping.get(interface.name)
            if zone:
                explicit_zones.setdefault(
                    (interface.source_context, zone),
                    IRZone(name=zone, source_context=interface.source_context),
                ).interfaces.append(interface.name)
            ip_value = normalize_ipv4_network(interface.ip or "", interface.mask or "") if interface.ip_mode == "static" else None
            parse_errors = []
            if interface.ip_mode == "static" and ip_value is None:
                parse_errors.append(f"Invalid IPv4 address/netmask: {interface.ip or ''} {interface.mask or ''}".strip())
            ir.interfaces.append(IRInterface(
                name=interface.name, source_context=interface.source_context, zone=zone, ip=ip_value, description=interface.description,
                status=not interface.shutdown, addressing_mode=interface.ip_mode,
                interface_type=interface.interface_type, parent=interface.parent_interface,
                vlanid=interface.vlan_id, mtu=interface.mtu, members=interface.redundant_interface_members,
                dhcp_client=True if interface.ip_mode == "dhcp" else None,
                ipv6_source_settings={
                    "addresses": [item.model_dump() for item in interface.ipv6_addresses],
                    "autoconfig": interface.ipv6_autoconfig,
                    "dhcp": interface.ipv6_dhcp,
                    "dhcp_setroute": interface.ipv6_dhcp_setroute,
                },
                requires_manual_review=interface.requires_manual_review or bool(parse_errors),
                parse_errors=parse_errors, source_attributes={
                    **interface.source_attributes,
                    "nameif": interface.nameif,
                    "security_level": interface.security_level,
                    "standby_ip": interface.standby_ip,
                    "dhcp_setroute": interface.dhcp_setroute,
                    "management_only": interface.management_only,
                    "interface_type": interface.interface_type,
                    "parent_interface": interface.parent_interface,
                    "vlan_id": interface.vlan_id,
                    "port_channel_id": interface.port_channel_id,
                    "channel_group": interface.channel_group,
                    "channel_group_mode": interface.channel_group_mode,
                    "redundant_interface_members": interface.redundant_interface_members,
                    "bridge_group": interface.bridge_group,
                    "bvi_id": interface.bvi_id,
                    "routing_context": interface.routing_context,
                    "vrf": interface.vrf,
                    "administrative_state": interface.administrative_state,
                    "policy_route_maps": interface.policy_route_maps,
                    "raw_lines": interface.raw_lines,
                },
                migration_status=interface.migration_status,
            ))
        ir.zones = list(explicit_zones.values())

        inline_addresses: Dict[tuple[Optional[str], str], IRAddress] = {}
        for obj in cfg.network_objects:
            if obj.type is None or obj.value is None:
                continue
            kwargs = dict(
                name=obj.name, source_context=obj.source_context, description=obj.description, source_type=obj.type,
                address_family=obj.address_family,
                source_attributes={**obj.source_attributes, "raw_lines": obj.raw_lines},
                migration_status=obj.migration_status, requires_manual_review=obj.requires_manual_review,
            )
            if obj.type == "host":
                kwargs.update(type=AddressType.HOST, subnet=obj.value, is_ipv6=obj.address_family == "ipv6")
            elif obj.type == "subnet":
                kwargs.update(type=AddressType.NETWORK, subnet=obj.value, is_ipv6=obj.address_family == "ipv6")
            elif obj.type == "range":
                start, end = obj.value.split("-", 1)
                kwargs.update(type=AddressType.RANGE, ip_range_start=start, ip_range_end=end, is_ipv6=obj.address_family == "ipv6")
            else:
                kwargs.update(type=AddressType.FQDN, fqdn=obj.value)
            ir.addresses.append(IRAddress(**kwargs))

        for group in cfg.network_groups:
            for entry in group.member_entries:
                if entry.type == "host":
                    name = _safe_name("asa_inline_host", entry.value)
                    inline_addresses[(group.source_context, name)] = IRAddress(
                        name=name, source_context=group.source_context, type=AddressType.HOST, subnet=entry.value, raw_value=entry.raw,
                        address_family=entry.address_family, is_ipv6=entry.address_family == "ipv6",
                    )
                elif entry.type == "inline_network":
                    name = _safe_name("asa_inline_net", entry.value)
                    inline_addresses[(group.source_context, name)] = IRAddress(
                        name=name, source_context=group.source_context, type=AddressType.NETWORK, subnet=entry.value, raw_value=entry.raw,
                        address_family=entry.address_family, is_ipv6=entry.address_family == "ipv6",
                    )
            ir.address_groups.append(IRAddressGroup(
                name=group.name, source_context=group.source_context, members=group.members, description=group.description,
                migration_status=group.migration_status, requires_manual_review=group.requires_manual_review,
                address_family=group.address_family,
                source_attributes={
                    **group.source_attributes, "raw_lines": group.raw_lines,
                    "review_reasons": list(group.review_reasons),
                    "member_entries": [entry.model_dump() for entry in group.member_entries],
                },
            ))

        for obj in cfg.service_objects:
            ports, errors = self._ir_service_ports(obj.ports)
            if not ports:
                continue
            ir.services.append(IRService(
                name=obj.name, source_context=obj.source_context, ports=ports, description=obj.description,
                source_protocol=obj.ports[0].protocol if len({item.protocol for item in obj.ports}) == 1 else None,
                source_protocol_number=int(obj.ports[0].protocol) if len(obj.ports) == 1 and obj.ports[0].protocol.isdigit() else None,
                source_attributes={**obj.source_attributes, "raw_lines": obj.raw_lines},
                migration_status="PARTIALLY_NORMALIZED" if errors else obj.migration_status,
                requires_manual_review=obj.requires_manual_review or bool(errors),
                audit_note="; ".join(errors) or None,
            ))

        for group in cfg.service_groups:
            members = list(group.members)
            if group.service_objects:
                name = _safe_name("asa_group_service", group.name)
                ports, errors = self._ir_service_ports(group.service_objects)
                if ports:
                    ir.services.append(IRService(
                        name=name, source_context=group.source_context, ports=ports, description=f"Inline services for {group.name}",
                        source_protocol=group.protocol,
                        migration_status="PARTIALLY_NORMALIZED" if errors else group.migration_status,
                        requires_manual_review=group.requires_manual_review or bool(errors),
                        audit_note="; ".join(errors) or None,
                        source_attributes={**group.source_attributes, "raw_lines": group.raw_lines},
                    ))
                    members.append(name)
            ir.service_groups.append(IRServiceGroup(
                name=group.name, source_context=group.source_context, members=members, description=group.description,
                migration_status=group.migration_status, requires_manual_review=group.requires_manual_review,
                source_attributes={"protocol": group.protocol, **group.source_attributes, "raw_lines": group.raw_lines,
                                   "member_entries": [entry.model_dump() for entry in group.member_entries],
                                   "review_reasons": list(group.review_reasons)},
            ))

        for group in [*cfg.protocol_groups, *cfg.icmp_type_groups]:
            members: List[str] = []
            entries = group.member_entries or [CiscoNamedGroupMember(
                type="protocol" if group.group_type == "protocol" else "icmp_type",
                value=raw.split()[1], raw=raw, resolved=True,
            ) for raw in group.members if len(raw.split()) >= 2]
            for entry in entries:
                raw = entry.raw
                parts = raw.split()
                if entry.type in {"protocol", "icmp_type"}:
                    value = entry.value
                    service_name = _safe_name(f"asa_{group.group_type}", f"{group.name}:{value}")
                    protocol_value = value if group.group_type == "protocol" else "icmp"
                    source_port = CiscoServicePort(
                        protocol=protocol_value,
                        icmp_type=value if group.group_type == "icmp-type" else None,
                        raw=raw,
                    )
                    ports, errors = self._ir_service_ports([source_port])
                    if ports:
                        ir.services.append(IRService(
                            name=service_name, source_context=group.source_context, ports=ports, source_protocol=protocol_value,
                            source_protocol_number=int(value) if value.isdigit() and group.group_type == "protocol" else None,
                            migration_status="PARTIALLY_NORMALIZED", requires_manual_review=True,
                            audit_note="; ".join(errors) or f"ASA {group.group_type} member requires target review",
                            source_attributes={"raw_line": raw, "owning_group": group.name},
                        ))
                        members.append(service_name)
                elif entry.type in {"protocol_group", "icmp_group"}:
                    members.append(entry.value)
            ir.service_groups.append(IRServiceGroup(
                name=group.name, source_context=group.source_context, members=members, unsafe_members=list(members),
                description=group.description, migration_status="PARTIALLY_NORMALIZED",
                requires_manual_review=True,
                source_attributes={"group_type": group.group_type, "raw_lines": group.raw_lines,
                                   "member_entries": [entry.model_dump() for entry in group.member_entries],
                                   "review_reasons": list(group.review_reasons)},
            ))

        for schedule in cfg.time_ranges:
            first = schedule.clauses[0] if schedule.clauses else None
            ir.schedules.append(IRSchedule(
                name=schedule.name, source_context=schedule.source_context,
                start=first.start if first else None,
                end=first.end if first else None,
                days=first.days if first else [],
                schedule_type=first.clause_type if first else "source-only",
                windows=[{
                    "type": clause.clause_type, "start": clause.start, "end": clause.end,
                    "days": clause.days, "source_order": clause.source_order, "raw": clause.raw,
                } for clause in schedule.clauses],
                source_attributes={
                    "clauses": [item.model_dump() for item in schedule.clauses],
                    "raw_lines": schedule.raw_lines,
                    "migration_status": schedule.migration_status,
                    "requires_manual_review": schedule.requires_manual_review,
                    "review_reasons": schedule.review_reasons,
                },
            ))

        synthetic_services: Dict[tuple[Optional[str], str], IRService] = {}

        def endpoint_reference(rule: CiscoAccessRule, source: bool) -> List[str]:
            endpoint = rule.source_endpoint if source else rule.destination_endpoint
            if endpoint is None or not endpoint.valid or endpoint.value is None:
                return []
            if endpoint.type == "any":
                if endpoint.value == "any4":
                    rule.requires_manual_review = True
                    rule.migration_status = "PARTIALLY_NORMALIZED"
                    rule.review_reasons.append("IPv4-only universal address requires family-aware target support")
                    return [IR_KEYWORD_ANY_IPV4]
                if endpoint.value == "any6":
                    rule.requires_manual_review = True
                    rule.migration_status = "PARTIALLY_NORMALIZED"
                    rule.review_reasons.append("IPv6-only universal address requires family-aware target support")
                    return [IR_KEYWORD_ANY_IPV6]
                return [IR_KEYWORD_ANY]
            if endpoint.type in {"inline", "host"}:
                value = endpoint.value
                if endpoint.type == "host" and "/" not in value:
                    value = f"{value}/128" if ":" in value else f"{value}/32"
                prefix = "asa_inline_host" if endpoint.type == "host" or "/32" in value or "/128" in value else "asa_inline_net"
                name = _safe_name(prefix, value)
                addr_type = AddressType.HOST if prefix.endswith("host") else AddressType.NETWORK
                inline_addresses[(rule.source_context, name)] = IRAddress(
                    name=name, type=addr_type, subnet=value, raw_value=endpoint.raw,
                    address_family=endpoint.address_family, is_ipv6=endpoint.address_family == "ipv6",
                )
                return [name]
            if endpoint.type in {"interface", "object-group-network-service"}:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.append(
                    "Interface-address endpoint cannot be converted safely" if endpoint.type == "interface"
                    else "Network-service endpoint combines address and service semantics"
                )
                return []
            return [endpoint.value]

        def service_reference(rule: CiscoAccessRule) -> List[str]:
            if rule.protocol in {"object", "object-group"} and rule.protocol_object:
                return [rule.protocol_object]
            if rule.icmp_object_group:
                return [rule.icmp_object_group]
            if rule.destination_port and rule.destination_port.operator in {"object", "object-group"}:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.append("Referenced ACL port object/group requires target service validation")
                return [rule.destination_port.object_name] if rule.destination_port.object_name else []
            if rule.source_port and rule.source_port.operator in {"object", "object-group"}:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.append("Source-port object/group relationship is source-preserved")
                return []
            if rule.protocol == "ip" and not rule.destination_port and not rule.source_port:
                return [IR_KEYWORD_ANY]
            if (rule.protocol or "").lower() not in KNOWN_PROTOCOLS and not (rule.protocol or "").isdigit():
                return []
            port_model = CiscoServicePort(
                protocol=rule.protocol or "", source=rule.source_port, destination=rule.destination_port,
                icmp_type=rule.icmp_type, icmp_code=rule.icmp_code, raw=rule.raw_line,
            )
            ports, errors = self._ir_service_ports([port_model])
            if not ports:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.extend(errors)
                return []
            expression = f"{rule.protocol}:{rule.source_port.raw if rule.source_port else '*'}:{rule.destination_port.raw if rule.destination_port else '*'}:{rule.icmp_type or ''}"
            name = _safe_name("asa_inline_service", expression)
            if errors:
                rule.requires_manual_review = True
                rule.migration_status = "PARTIALLY_NORMALIZED"
                rule.review_reasons.extend(errors)
            source_protocol = rule.protocol or ""
            synthetic_services[(rule.source_context, name)] = IRService(
                name=name, source_context=rule.source_context, ports=ports,
                source_protocol=source_protocol,
                source_protocol_number=int(source_protocol) if source_protocol.isdigit() else None,
                migration_status="PARTIALLY_NORMALIZED" if errors else "NORMALIZED",
                requires_manual_review=bool(errors), audit_note="; ".join(errors) or None,
                source_attributes={"source_expression": expression},
            )
            return [name]

        bindings: Dict[tuple[Optional[str], str], List] = {}
        for binding in cfg.acl_bindings:
            bindings.setdefault((binding.source_context, binding.acl_name), []).append(binding)
        interface_zones = {
            (interface.source_context, interface.nameif): (interface.nameif or self.zone_mapping.get(interface.name))
            for interface in cfg.interfaces if interface.nameif
        }
        interface_zones.update({
            (interface.source_context, interface.name): (interface.nameif or self.zone_mapping.get(interface.name))
            for interface in cfg.interfaces
        })

        rules_by_acl: Dict[tuple[Optional[str], str], List[CiscoAccessRule]] = {}
        acl_order: List[tuple[Optional[str], str]] = []
        for rule in cfg.access_rules:
            key = (rule.source_context, rule.acl_name)
            if key not in rules_by_acl:
                acl_order.append(key)
            rules_by_acl.setdefault(key, []).append(rule)
        ordered_access_rules: List[CiscoAccessRule] = []
        for acl_key in acl_order:
            acl_rules = rules_by_acl[acl_key]
            sequences = [rule.source_sequence for rule in acl_rules if rule.source_sequence is not None]
            repeated = {sequence for sequence in sequences if sequences.count(sequence) > 1}
            unusual = bool(sequences and sequences != sorted(sequences))
            mixed = bool(sequences and len(sequences) != len(acl_rules))
            ordered = sorted(
                acl_rules,
                key=lambda rule: (
                    rule.source_sequence is None,
                    rule.source_sequence if rule.source_sequence is not None else 0,
                    rule.source_order if rule.source_order is not None else rule.source_line_number or 0,
                ),
            )
            for effective_order, rule in enumerate(ordered, 1):
                rule.effective_source_order = effective_order
                rule.source_attributes.update({
                    "source_order": rule.source_order,
                    "effective_source_order": effective_order,
                })
                ordering_reasons = []
                if rule.source_sequence in repeated:
                    ordering_reasons.append("Repeated ACL sequence number; source order retained as secondary ordering")
                    rule.id = f"{rule.id}_{rule.source_line_number}"
                if unusual:
                    ordering_reasons.append("ACL sequence order differs from source order; sequence order preserved with review")
                if mixed:
                    ordering_reasons.append("ACL mixes sequenced and unsequenced entries")
                for reason in ordering_reasons:
                    if reason not in rule.review_reasons:
                        rule.review_reasons.append(reason)
                if ordering_reasons:
                    rule.requires_manual_review = True
                    if rule.migration_status == "NORMALIZED":
                        rule.migration_status = "PARTIALLY_NORMALIZED"
            ordered_access_rules.extend(ordered)

        for rule in ordered_access_rules:
            rule_bindings = bindings.get((rule.source_context, rule.acl_name)) or []
            # ACL definitions used by crypto, class-map, capture, AAA, or no known
            # consumer are retained in the source model and are not transit rules.
            if not rule_bindings:
                continue
            for binding in rule_bindings:
                from_zone: List[str] = []
                to_zone: List[str] = []
                source_from: List[str] = []
                source_to: List[str] = []
                review = list(rule.review_reasons)
                status = rule.migration_status
                manual = rule.requires_manual_review
                extra = {**rule.source_attributes, "acl_name": rule.acl_name, "raw_line": rule.raw_line}
                suffix = "unbound"
                if binding is not None:
                    suffix = f"{binding.interface or 'global'}_{binding.direction or 'unknown'}"
                    extra.update({
                        "binding_direction": binding.direction, "binding_interface": binding.interface,
                        "global": binding.direction == "global", "control_plane": binding.control_plane,
                        "per_user_override": binding.per_user_override,
                        **binding.source_attributes,
                    })
                    zone = interface_zones.get((binding.source_context, binding.interface or ""))
                    if binding.direction == "in":
                        source_from = [binding.interface] if binding.interface else []
                        from_zone = [zone] if zone else []
                    elif binding.direction == "out":
                        source_to = [binding.interface] if binding.interface else []
                        to_zone = [zone] if zone else []
                    if binding.direction == "global" or binding.control_plane or binding.per_user_override or not zone and binding.direction != "global":
                        manual = True
                        status = "EXTRACT_ONLY" if binding.control_plane else "PARTIALLY_NORMALIZED"
                        review.append("ACL binding context cannot be represented as an ordinary transit policy")
                source_refs = endpoint_reference(rule, True)
                if rule.acl_type == "standard":
                    destination_refs = []
                    services = []
                    manual = True
                    status = "PARTIALLY_NORMALIZED"
                    review.append("Standard ACL has no extended protocol, destination, or service operands")
                else:
                    destination_refs = endpoint_reference(rule, False)
                    services = service_reference(rule)
                manual = manual or rule.requires_manual_review
                if rule.migration_status != "NORMALIZED":
                    status = rule.migration_status
                if binding.control_plane:
                    status = "EXTRACT_ONLY"
                review.extend(reason for reason in rule.review_reasons if reason not in review)
                if not source_refs or not destination_refs or not services:
                    manual = True
                    status = "PARSE_ERROR" if status == "NORMALIZED" else status
                    review.append("Policy has unresolved address or service semantics")
                if rule.time_range:
                    schedule = next((item for item in cfg.time_ranges if item.name == rule.time_range and item.source_context == rule.source_context), None)
                    if schedule is None:
                        manual = True
                        status = "PARTIALLY_NORMALIZED"
                        review.append(f"Schedule '{rule.time_range}' is unresolved")
                    elif schedule.requires_manual_review:
                        manual = True
                        status = "PARTIALLY_NORMALIZED"
                        review.extend(schedule.review_reasons or [f"Schedule '{rule.time_range}' requires review"])
                name = f"{rule.id}__{re.sub(r'[^A-Za-z0-9_]+', '_', suffix)}"
                ir.policies.append(IRPolicy(
                    name=name, source_context=rule.source_context, source_rule_id=rule.id, from_zone=from_zone, to_zone=to_zone,
                    source=source_refs, destination=destination_refs, service=services,
                    action=PolicyAction.ALLOW if rule.action == "permit" else PolicyAction.DENY if rule.action == "deny" else None,
                    source_from_interfaces=source_from, source_to_interfaces=source_to,
                    source_address_references=source_refs, destination_address_references=destination_refs,
                    source_service_references=services, source_action=rule.action,
                    source_schedule=rule.time_range, schedule=rule.time_range,
                    source_users=[rule.user] if rule.user else [], source_user_groups=[rule.user_group] if rule.user_group else [],
                    identity_dependency_review=bool(rule.user or rule.user_group), source_log_setting=rule.log_raw,
                    source_extra_settings=extra | {
                        "source_security_group_type": rule.source_security_group_type,
                        "source_security_group_value": rule.source_security_group_value,
                        "destination_security_group_type": rule.destination_security_group_type,
                        "destination_security_group_value": rule.destination_security_group_value,
                        "icmp_object_group": rule.icmp_object_group,
                    },
                    migration_status=status, review_reasons=list(dict.fromkeys(review)), requires_manual_review=manual,
                    description=rule.remark, disabled=rule.inactive, log_end=rule.log_enabled,
                ))

        ir.addresses.extend(inline_addresses.values())
        ir.services.extend(synthetic_services.values())

        def scoped_names(items: Iterable[Any], source_context: Optional[str]) -> set[str]:
            return {item.name for item in items if item.source_context == source_context}

        def address_names_for(source_context: Optional[str]) -> set[str]:
            return scoped_names(ir.addresses, source_context) | scoped_names(ir.address_groups, source_context) | {
                IR_KEYWORD_ANY, IR_KEYWORD_ANY_IPV4, IR_KEYWORD_ANY_IPV6,
            }

        def service_names_for(source_context: Optional[str]) -> set[str]:
            return scoped_names(ir.services, source_context) | scoped_names(ir.service_groups, source_context) | {IR_KEYWORD_ANY}

        def unsafe_names(items: Iterable[Any], source_context: Optional[str]) -> set[str]:
            return {item.name for item in items if item.source_context == source_context and (
                item.requires_manual_review or item.migration_status != "NORMALIZED"
            )}

        address_names = address_names_for(None)
        service_names = service_names_for(None)
        unsafe_addresses = unsafe_names([*ir.addresses, *ir.address_groups], None)
        unsafe_services = unsafe_names([*ir.services, *ir.service_groups], None)
        service_group_by_name = {(group.source_context, group.name): group for group in cfg.service_groups}
        for group in cfg.service_groups:
            group_address_names = service_names_for(group.source_context)
            errors = [
                f"Unresolved service-group reference: {member}"
                for member in group.members if member not in group_address_names
            ]
            visiting: set[str] = set()
            visited: set[str] = set()

            def visit_service(name: str) -> bool:
                if name in visiting:
                    return True
                if name in visited or (group.source_context, name) not in service_group_by_name:
                    return False
                visiting.add(name)
                cyclic = any(visit_service(member) for member in service_group_by_name[(group.source_context, name)].members)
                visiting.remove(name)
                visited.add(name)
                return cyclic

            if visit_service(group.name):
                errors.append("Cyclic nested service-group reference")
            if errors:
                group.migration_status = "PARTIALLY_NORMALIZED"
                group.requires_manual_review = True
                group.source_attributes["reference_validation"] = errors
                ir_group = next(item for item in ir.service_groups if item.name == group.name and item.source_context == group.source_context)
                ir_group.migration_status = group.migration_status
                ir_group.requires_manual_review = True
                ir_group.source_attributes["reference_validation"] = errors

        acl_names = {(rule.source_context, rule.acl_name) for rule in cfg.access_rules}
        for binding in cfg.acl_bindings:
            if (binding.source_context, binding.acl_name) not in acl_names:
                binding.migration_status = "PARTIALLY_NORMALIZED"
                binding.requires_manual_review = True
                binding.review_reasons.append(f"Unresolved ACL reference: {binding.acl_name}")
        for acl_name, consumers in cfg.acl_consumers.items():
            if not any((consumer.get("source_context"), acl_name) in acl_names for consumer in consumers):
                for consumer in consumers:
                    self._record_diagnostic(
                        consumer["line_number"], consumer["raw_line"],
                        f"Unresolved ACL reference: {acl_name}", consumer["consumer_type"],
                        migration_effect="PARTIALLY_NORMALIZED",
                    )
        for policy in ir.policies:
            policy_address_names = address_names_for(policy.source_context)
            policy_service_names = service_names_for(policy.source_context)
            policy_unsafe_addresses = unsafe_names([*ir.addresses, *ir.address_groups], policy.source_context)
            policy_unsafe_services = unsafe_names([*ir.services, *ir.service_groups], policy.source_context)
            unresolved = [ref for ref in policy.source + policy.destination if ref not in policy_address_names]
            unresolved += [ref for ref in policy.service if ref not in policy_service_names]
            if unresolved:
                policy.requires_manual_review = True
                policy.migration_status = "PARTIALLY_NORMALIZED"
                policy.review_reasons.append(f"Unresolved references: {', '.join(sorted(set(unresolved)))}")
            unsafe = set(policy.source + policy.destination).intersection(policy_unsafe_addresses)
            unsafe.update(set(policy.service).intersection(policy_unsafe_services))
            if unsafe:
                policy.requires_manual_review = True
                policy.migration_status = "PARTIALLY_NORMALIZED"
                policy.review_reasons.append(f"References source semantics requiring review: {', '.join(sorted(unsafe))}")

        ordered_nat_rules = sorted(cfg.nat_rules, key=lambda item: item.effective_source_order or 0)
        for index, nat in enumerate(ordered_nat_rules, 1):
            nat_address_names = address_names_for(nat.source_context)
            nat_service_names = service_names_for(nat.source_context)
            source = [nat.real_source] if nat.real_source else []
            # ASA destination twice-NAT is written MAPPED REAL: the first
            # operand matches the original packet and the second is translated.
            destination = [nat.mapped_destination] if nat.mapped_destination else []
            services = [nat.original_service] if nat.original_service else [IR_KEYWORD_ANY] if source else []
            nat_type = NATType.TWICE if nat.destination_mode else NATType.SOURCE
            translated_refs = [ref for ref in [nat.mapped_source, nat.real_destination] if ref and ref != "interface"]
            def unresolved_nat_ref(ref: str) -> bool:
                if ref in nat_address_names or ref in {"any", "interface"}:
                    return False
                try:
                    ipaddress.ip_address(ref)
                    return False
                except ValueError:
                    return True
            service_refs = [ref for ref in [nat.original_service, nat.translated_service] if ref]
            missing_refs = [ref for ref in source + destination + translated_refs if unresolved_nat_ref(ref)]
            missing_services = [ref for ref in service_refs if ref not in nat_service_names and not ref.isdigit()]
            manual = nat.requires_manual_review or bool(missing_refs)
            manual = manual or bool(missing_services)
            status = "PARTIALLY_NORMALIZED" if manual and nat.migration_status == "NORMALIZED" else nat.migration_status
            reasons = list(nat.review_reasons)
            if missing_refs:
                reasons.append(f"Unresolved NAT references: {', '.join(sorted(set(missing_refs)))}")
            if missing_services:
                reasons.append(f"Unresolved NAT service references: {', '.join(sorted(set(missing_services)))}")
            ir.nat_rules.append(IRNATRule(
                name=nat.name, source_context=nat.source_context, type=nat_type, sequence=nat.sequence if nat.sequence is not None else index,
                enabled="inactive" not in nat.options,
                source_from_interfaces=[nat.source_interface] if nat.source_interface else [],
                source_to_interfaces=[nat.destination_interface] if nat.destination_interface else [],
                from_zone=[nat.source_interface] if nat.source_interface else [], to_zone=[nat.destination_interface] if nat.destination_interface else [],
                source=source, destination=destination, services=services,
                source_translation_mode=(
                    NATTranslationMode.INTERFACE_ADDRESS if nat.mapped_source_mode == "interface"
                    else NATTranslationMode.POOL if nat.mapped_source_mode == "pat_pool"
                    else NATTranslationMode.STATIC if nat.source_mode == "static"
                    else NATTranslationMode.DYNAMIC_IP_AND_PORT if nat.source_mode == "dynamic"
                    else None
                ),
                source_pool_references=[nat.pat_pool] if nat.pat_pool else [],
                translated_sources=[nat.mapped_source] if nat.mapped_source else [],
                translated_destinations=[nat.real_destination] if nat.real_destination else [],
                translated_services=[nat.translated_service] if nat.translated_service else [],
                source_rule_id=str(nat.sequence or index), source_attributes={
                    **nat.source_attributes,
                    "raw_line": nat.raw_line,
                    "section": nat.section, "section_order": nat.section_order,
                    "source_sequence": nat.source_sequence,
                    "source_order": nat.source_order,
                    "source_order_within_section": nat.source_order_within_section,
                    "effective_source_order": nat.effective_source_order,
                    "owning_object": nat.owning_object, "source_mode": nat.source_mode,
                    "access_list": nat.access_list, "identity_nat": nat.identity_nat,
                    "nat_exemption": nat.nat_exemption, "object_nat_precedence": nat.object_nat_precedence,
                    "object_nat_specificity": nat.object_nat_specificity,
                    "effective_order_inputs": nat.effective_order_inputs,
                    "mapped_source_mode": nat.mapped_source_mode,
                    "mapped_source_address_family": nat.mapped_source_address_family,
                    "pat_pool": nat.pat_pool, "pat_pool_options": nat.pat_pool_options,
                    "destination_mode": nat.destination_mode,
                    "service_protocol": nat.service_protocol,
                    "dns": nat.dns, "no_proxy_arp": nat.no_proxy_arp,
                    "route_lookup": nat.route_lookup, "unidirectional": nat.unidirectional,
                    "inactive": nat.inactive, "net_to_net": nat.net_to_net,
                    "options": nat.options, "raw_options": nat.raw_options, "raw_line": nat.raw_line,
                }, migration_status=status, requires_manual_review=manual, review_reasons=reasons,
            ))

        for index, route in enumerate(cfg.static_routes, 1):
            destination = route.destination if route.address_family == "ipv6" else normalize_ipv4_network(route.destination, route.mask or "")
            errors = [] if destination else [f"Invalid route destination/netmask: {route.destination} {route.mask or ''}".strip()]
            ir.routes.append(IRRoute(
                name=f"route_{route.interface}_{index}", source_context=route.source_context, destination=destination,
                address_family=route.address_family,
                source_destination=route.destination if route.address_family == "ipv6" else f"{route.destination} {route.mask}", interface=route.interface,
                next_hop=route.gateway, administrative_distance=route.administrative_distance,
                migration_status="PARSE_ERROR" if errors else route.migration_status,
                parse_error=errors[0] if errors else None, review_reasons=errors + route.review_reasons,
                requires_manual_review=route.requires_manual_review or bool(errors),
            source_attributes={
                "raw_line": route.raw_line, "track_id": route.track_id,
                "tunneled": route.tunneled, "raw_options": route.raw_options,
                "routing_context": route.routing_context,
                **route.source_attributes,
            },
            ))
        return ir
