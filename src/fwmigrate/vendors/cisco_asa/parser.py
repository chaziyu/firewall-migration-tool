from __future__ import annotations

import hashlib
import ipaddress
import re
import shlex
from datetime import date
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fwmigrate.vendors.cisco_asa.acl_parser import KNOWN_PROTOCOLS, parse_acl_binding, parse_acl_line, parse_endpoint
from fwmigrate.vendors.cisco_asa.model.acl import CiscoAccessRule, CiscoACLRemark
from fwmigrate.vendors.cisco_asa.model.address import CiscoNetworkGroup, CiscoNetworkGroupMember, CiscoNetworkObject
from fwmigrate.vendors.cisco_asa.model.base import CiscoSourceRecord
from fwmigrate.vendors.cisco_asa.model.context import CiscoASAContext, CiscoAllocatedInterface, CiscoMultiContextSystem
from fwmigrate.vendors.cisco_asa.model.dhcp import CiscoDHCPOption, CiscoDHCPRelay, CiscoDHCPRelayServer, CiscoDHCPServer
from fwmigrate.vendors.cisco_asa.model.diagnostics import CiscoDiagnostic
from fwmigrate.vendors.cisco_asa.model.failover import CiscoFailoverConfig, CiscoFailoverGroup, CiscoFailoverInterfaceIP, CiscoFailoverMACAddress, CiscoFailoverSetting
from fwmigrate.vendors.cisco_asa.model.groups import CiscoNamedGroup, CiscoNamedGroupMember
from fwmigrate.vendors.cisco_asa.model.identity import CiscoAAAAccountingRule, CiscoAAAAuthenticationRule, CiscoAAAAuthorizationRule, CiscoAAARecord, CiscoAAAServerGroup, CiscoAAAServerHost, CiscoCommandPrivilege, CiscoLocalUser
from fwmigrate.vendors.cisco_asa.model.interface import CiscoIPv6Address, CiscoInterface
from fwmigrate.vendors.cisco_asa.model.management import CiscoConnectionControl, CiscoDNSServerGroup, CiscoEnableCredential, CiscoHTTPServerConfig, CiscoICMPManagementRule, CiscoLoggingSetting, CiscoManagementAccessRule, CiscoManagementSetting, CiscoNTPServer, CiscoSNMPSetting, CiscoSystemSettings
from fwmigrate.vendors.cisco_asa.model.mpf import CiscoClassMap, CiscoClassMapMatch, CiscoInspectAction, CiscoInspectionPolicySection, CiscoMPFConnectionAction, CiscoMPFPoliceAction, CiscoPolicyMap, CiscoPolicyMapClass, CiscoServicePolicy, CiscoTCPMap, CiscoTCPMapSetting
from fwmigrate.vendors.cisco_asa.model.nat import CiscoNATRule
from fwmigrate.vendors.cisco_asa.model.routing import CiscoPolicyRoutePathMonitor, CiscoRouteMap, CiscoRouteMapRule, CiscoSLAMonitor, CiscoStaticRoute, CiscoTrack
from fwmigrate.vendors.cisco_asa.model.schedule import CiscoTimeRange, CiscoTimeRangeClause
from fwmigrate.vendors.cisco_asa.model.service import CiscoNetworkServiceObject, CiscoPortSpec, CiscoServiceGroup, CiscoServiceGroupMember, CiscoServiceObject, CiscoServicePort
from fwmigrate.vendors.cisco_asa.model.source import CiscoASAConfig
from fwmigrate.vendors.cisco_asa.model.vpn import CiscoCryptoMap, CiscoGroupPolicy, CiscoIKEPolicy, CiscoIKEv2Proposal, CiscoIPsecProfile, CiscoIPsecTransformSet, CiscoTunnelGroup, CiscoTrustpointRecord, CiscoVPNAddressAssignment, CiscoVPNAddressPool, CiscoWebVPNConfig
from fwmigrate.vendors.cisco_asa.model.zone import CiscoTrafficZone
from fwmigrate.vendors.cisco_asa.net_utils import normalize_ipv4_network, parse_ipv4_netmask
from fwmigrate.vendors.cisco_asa.service_parser import parse_service_clause
from fwmigrate.extraction.sanitize import sanitize_raw_text


def mask_to_cidr(mask: str) -> Optional[int]:
    """Backward-compatible strict mask helper. Invalid masks return ``None``."""
    return parse_ipv4_netmask(mask)


def _safe_name(prefix: str, expression: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_]+", "_", expression).strip("_").lower()
    clean = clean[:48] or "value"
    digest = hashlib.sha1(expression.encode("utf-8")).hexdigest()[:8]
    return f"{prefix}_{clean}_{digest}"


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _mark_explicit(record: Any, *field_names: str) -> None:
    record.explicit_fields.update(field_names)


def _parse_interface_header(header: str) -> Optional[Dict[str, Any]]:
    match = re.fullmatch(r"interface\s+(.+?)\s*", header.strip(), re.I)
    if not match:
        return None
    value = match.group(1)
    logical = re.fullmatch(r"(BVI|Redundant|Port-channel|Vlan)\s*(\d+)(?:\.(\d+))?", value, re.I)
    if logical:
        family, number, suffix = logical.groups()
        label = {"bvi": "BVI", "redundant": "Redundant", "port-channel": "Port-channel", "vlan": "Vlan"}[family.lower()]
        name = f"{label}{number}" + (f".{suffix}" if suffix else "")
        kind = "subinterface" if suffix else {"bvi": "bvi", "redundant": "redundant", "port-channel": "port-channel", "vlan": "vlan"}[family.lower()]
        return {"name": name, "interface_type": kind, "parent_interface": f"{label}{number}" if suffix else None,
                "interface_suffix_vlan_id": int(suffix) if suffix else None,
                "bvi_id": int(number) if family.lower() == "bvi" and not suffix else None,
                "port_channel_id": int(number) if family.lower() == "port-channel" and not suffix else None,
                "vlan_id": int(number) if family.lower() == "vlan" and not suffix else None}
    if re.fullmatch(r"\S+\.\d+", value):
        parent, _, suffix = value.rpartition(".")
        return {"name": value, "interface_type": "subinterface", "parent_interface": parent,
                "interface_suffix_vlan_id": int(suffix), "bvi_id": None, "port_channel_id": None, "vlan_id": None}
    kind = "management" if re.match(r"Management", value, re.I) else "physical"
    return {"name": value, "interface_type": kind, "parent_interface": None,
            "interface_suffix_vlan_id": None, "bvi_id": None, "port_channel_id": None, "vlan_id": None}


def _pbr_acl_match_evidence(acl_names: List[str], rules: Iterable[CiscoAccessRule]) -> List[Dict[str, Any]]:
    evidence = []
    for acl_name in acl_names:
        for rule in rules:
            if rule.acl_name != acl_name:
                continue
            endpoint = lambda item: item.raw if item else None
            evidence.append({
                "acl": acl_name,
                "action": rule.action,
                "protocol": rule.protocol,
                "source": endpoint(rule.source_endpoint),
                "destination": endpoint(rule.destination_endpoint),
                "source_port": rule.source_port.raw if rule.source_port else None,
                "destination_port": rule.destination_port.raw if rule.destination_port else None,
            })
    return evidence


def _nat_port_range(value: Optional[str]) -> List[Dict[str, int]]:
    if not value:
        return []
    try:
        if "-" in value:
            start, end = (int(part) for part in value.split("-", 1))
        else:
            start = end = int(value)
        return [{"start": start, "end": end}]
    except ValueError:
        return []


class CiscoASAParser:
    """Deterministic offline parser for Cisco ASA running configuration."""

    def __init__(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        self.raw_lines = content.splitlines()
        self.zone_mapping = zone_mapping or {}
        self.config = CiscoASAConfig()
        self._nat_section_counts: Dict[str, int] = {}
        self._line_contexts: Dict[int, Optional[str]] = {}


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
        object_name: Optional[str] = None, extraction_effect: str = "PARSE_ERROR",
    ) -> None:
        diagnostic = CiscoDiagnostic(
            line_number=line_number, section=section, object_name=object_name,
            raw_line=sanitize_raw_text(line), reason=reason, extraction_effect=extraction_effect,
            severity="error" if extraction_effect == "PARSE_ERROR" else "warning",
        )
        self.config.diagnostics.append(diagnostic)
        if extraction_effect == "PARSE_ERROR":
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

    def _parse_management_command_base(self, line: str, line_number: int) -> None:
        parts = line.split(); lower = line.lower(); command = parts[0].lower()
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
            item = CiscoManagementAccessRule(name=f"{command}:{line_number}", protocol=command, source=parts[1] if len(parts)>1 else None, mask_or_prefix=parts[2] if len(parts)>2 else None, interface=parts[3] if len(parts)>3 else None, raw_line=sanitize_raw_text(line), raw_lines=[sanitize_raw_text(line)], source_order=line_number, source_attributes={"raw_command": sanitize_raw_text(line)})
            if len(parts) < 4:
                item.extraction_status = "PARSE_ERROR"; item.requires_manual_review = True; item.review_reasons.append("Malformed management access rule"); self._record_diagnostic(line_number, line, item.review_reasons[0], command)
            elif normalize_ipv4_network(item.source or "", item.mask_or_prefix or "") is None:
                item.extraction_status = "PARSE_ERROR"; item.requires_manual_review = True; item.review_reasons.append("Invalid management source IPv4 address/netmask"); self._record_diagnostic(line_number, line, item.review_reasons[0], command)
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

    def _parse_failover_command(self, line: str, line_number: int, children: Optional[List[str]] = None) -> None:
        parts = line.split(); lower = line.lower(); cfg = self.config.failover_config
        safe = sanitize_raw_text(line); cfg.raw_lines.append(safe); cfg.source_attributes.setdefault("raw_commands", []).append(safe)
        setting = CiscoFailoverSetting(name="failover", setting=parts[0], extraction_status="PARTIAL", requires_manual_review=False, raw_lines=[safe], source_attributes={"raw_command": safe})
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
                except ValueError: item.extraction_status="PARSE_ERROR"; item.requires_manual_review=True; item.review_reasons.append("Malformed failover interface IP")
            cfg.interface_ips.append(item)
        elif len(parts) >= 5 and lower.startswith("failover mac address "):
            item = CiscoFailoverMACAddress(name=f"failover-mac:{line_number}", interface=parts[3], active_mac=parts[4], standby_mac=parts[6] if len(parts)>6 and parts[5].lower()=="standby" else None, raw_line=safe, raw_lines=[safe], source_order=line_number)
            if not all(re.fullmatch(r"[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}", x or "") for x in (item.active_mac, item.standby_mac) if x): item.extraction_status="PARSE_ERROR"; item.requires_manual_review=True; item.review_reasons.append("Malformed failover MAC address")
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
                elif child_parts and child_parts[0].lower() == "preempt": group.preempt = True
                elif child_parts[:2] == ["no", "preempt"]: group.preempt = False
                elif child_parts[:2] == ["replication", "http"]: group.replication_http = True
                elif child_parts[:3] == ["no", "replication", "http"]: group.replication_http = False
                elif len(child_parts) > 1 and child_parts[0].lower() == "interface-policy": group.interface_policy = " ".join(child_parts[1:])
                elif len(child_parts) > 1 and child_parts[0].lower() == "polltime": group.polltime = " ".join(child_parts[1:])
                group.raw_children.append(sanitize_raw_text(child))
                group.raw_lines.append(sanitize_raw_text(child))
            cfg.failover_groups.append(group)
        else: cfg.extraction_status="PARTIAL"; cfg.requires_manual_review=True; cfg.review_reasons.append("Unsupported failover syntax")

    @staticmethod
    def _append_unique(values: List[str], additions: Iterable[str]) -> None:
        for value in additions:
            if value not in values:
                values.append(value)

    def _parse_crypto_map_line(self, line: str, line_number: int, dynamic: bool = False) -> None:
        parts = line.split()
        offset = 2
        if len(parts) == offset + 3 and parts[offset + 1].lower() == "interface":
            name, interface = parts[offset], parts[offset + 2]
            context = self._line_contexts.get(line_number)
            record = next((item for item in self.config.crypto_maps
                           if item.name == name and item.sequence is None
                           and item.source_context == context), None)
            if record is None:
                record = CiscoCryptoMap(name=name, map_name=name, source_order=line_number,
                                        raw_lines=[], source_attributes={"raw_command": line})
                self.config.crypto_maps.append(self._with_source_context(record, line_number))
            record.interface_attachment = interface
            record.raw_lines.append(sanitize_raw_text(line))
            return
        if len(parts) <= offset + 1 or not parts[offset + 1].isdigit():
            self._record_diagnostic(line_number, line, "Malformed crypto map sequence", "crypto map", extraction_effect="PARSE_ERROR")
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
        lowered = [token.lower() for token in tokens]
        if len(tokens) >= 3 and lowered[:2] == ["match", "address"]:
            record.acl_name = tokens[2]
        elif lowered[:2] == ["set", "peer"] and len(tokens) >= 3:
            self._append_unique(record.peers, [tokens[2]])
            record.peer = tokens[2]
        elif lowered[:2] == ["set", "transform-set"]:
            self._append_unique(record.transform_sets, tokens[2:])
        elif lowered[:2] == ["set", "ikev2"] and len(tokens) >= 4 and lowered[2] in {"ipsec-proposal", "ipsec-proposals"}:
            self._append_unique(record.ikev2_proposals, tokens[3:])
        elif lowered[:2] == ["set", "pfs"] and len(tokens) >= 3:
            record.pfs_group = tokens[2] if tokens[2].lower() != "none" else None
        elif lowered[:3] == ["set", "security-association", "lifetime"]:
            if len(tokens) >= 5 and lowered[3] in {"seconds", "kilobytes"} and tokens[4].isdigit():
                setattr(record, f"security_association_lifetime_{lowered[3]}", int(tokens[4]))
            else:
                record.raw_options.append(safe_line)
                record.extraction_status = "PARSE_ERROR"
                record.requires_manual_review = True
        elif lowered[:2] == ["set", "connection-type"] and len(tokens) >= 3:
            record.raw_options.append(safe_line)
        elif lowered[:1] == ["interface"] and len(tokens) >= 2:
            record.interface_attachment = tokens[1]
        else:
            lowered = [token.lower() for token in tokens]
            if "dynamic" in lowered and lowered.index("dynamic") + 1 < len(tokens):
                record.dynamic_map = tokens[lowered.index("dynamic") + 1]
            elif tokens:
                record.raw_options.append(safe_line)
                record.extraction_status = "PARTIAL"
                record.review_reasons.append("Unsupported crypto-map child syntax")

    def _parse_ike_child(self, record: CiscoIKEPolicy, children: List[str], line_number: int) -> None:
        for child in children:
            parts = child.split()
            if len(parts) < 2:
                record.raw_options.append(sanitize_raw_text(child))
                continue
            key, values = parts[0].lower(), parts[1:]
            value = " ".join(values)
            target = {"authentication": "authentication", "encryption": "encryption", "hash": "hash_algorithm",
                      "integrity": "integrity", "prf": "prf"}.get(key)
            if target:
                setattr(record, target, value)
                list_target = {
                    "encryption": record.encryption_algorithms,
                    "hash": record.hash_algorithms,
                    "integrity": record.integrity_algorithms,
                    "prf": record.prf_algorithms,
                }.get(key)
                if list_target is not None:
                    self._append_unique(list_target, values)
            elif key == "group":
                record.dh_group = value
                self._append_unique(record.dh_groups, values)
            elif key == "lifetime" and len(parts) == 2 and parts[1].isdigit():
                record.lifetime_seconds = int(parts[1])
            elif key == "lifetime":
                record.extraction_status = "PARSE_ERROR"
                record.requires_manual_review = True
                record.raw_options.append(sanitize_raw_text(child))
                self._record_diagnostic(line_number, child, "Malformed IKE lifetime", "crypto ike policy", record.name)
            else:
                record.extraction_status = "PARTIAL"
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
            source_context = self._line_contexts.get(index + 1)
            group = next((item for item in self.config.aaa_server_groups if item.name == group_name and item.source_context == source_context), None)
            if group is None:
                group = CiscoAAAServerGroup(name=group_name, protocol=protocol, raw_lines=[], source_attributes={"raw_commands": []})
                self.config.aaa_server_groups.append(self._with_source_context(group, index + 1))
            group.raw_lines.append(sanitize_raw_text(line))
            group.source_attributes.setdefault("raw_commands", []).append(sanitize_raw_text(line))
            if protocol.lower() not in {"radius", "tacacs+", "ldap"}:
                group.extraction_status = "PARTIAL"
                group.requires_manual_review = True
                group.review_reasons.append("AAA server protocol is preserved but not semantically verified")
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
                    record.extraction_status = "PARSE_ERROR"
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
                record.extraction_status = "PARTIAL"
                record.requires_manual_review = True
                record.raw_extra.setdefault("unmodeled_lines", []).append(safe)
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
        target = None
        cursor = 1
        if family == "authorization" and service in {"command", "exec", "network", "http", "serial", "telnet", "ssh"}:
            cursor = 1
        if cursor < len(values) and values[cursor].lower() in {"console", "inside", "outside", "management", "interface"}:
            target, cursor = values[cursor], cursor + 1
        server_group = values[cursor] if cursor < len(values) and values[cursor].upper() != "LOCAL" and values[cursor].lower() not in {"include", "exclude", "match", "access-list", "user", "user-group", "object-group-user"} else None
        cursor += 1 if server_group else 0
        options = values[cursor:]
        fallback = any(value.upper() == "LOCAL" for value in values[1:])
        acl_reference = None
        user_identity = None
        for pos, value in enumerate(options):
            if value.lower() in {"access-list", "acl"} and pos + 1 < len(options):
                acl_reference = options[pos + 1]
            if value.lower() in {"user", "user-group", "object-group-user"} and pos + 1 < len(options):
                user_identity = options[pos + 1]
        cls = {"authentication": CiscoAAAAuthenticationRule, "authorization": CiscoAAAAuthorizationRule, "accounting": CiscoAAAAccountingRule}[family]
        record = cls(name=f"{family}:{index + 1}", service=service, management_protocol=service, target=target, server_group=server_group, fallback_local=fallback, interface=target, options=options, acl_reference=acl_reference, user_identity=user_identity, raw_line=sanitize_raw_text(line), raw_lines=[sanitize_raw_text(line)], source_attributes={"raw_command": sanitize_raw_text(line)})
        if not server_group and not fallback:
            record.extraction_status = "PARTIAL"
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
                record.privilege = int(parts[pos + 1]); _mark_explicit(record, "privilege"); pos += 2; continue
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
        if previous:
            history = previous.source_attributes.setdefault("definition_history", [])
            history.append(previous.raw_line)
            record.source_attributes["definition_history"] = [*history, record.raw_line]
        if previous and (previous.privilege, previous.authentication_type) != (record.privilege, record.authentication_type):
            record.extraction_status = previous.extraction_status = "PARTIAL"
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
            if lower == "webvpn":
                context = self._line_contexts.get(index + 1)
                item = next((record for record in self.config.webvpn_configs if record.source_context == context), None)
                if item is None:
                    item = self._with_source_context(CiscoWebVPNConfig(name="webvpn", extraction_status="PARTIAL"), index + 1)
                    self.config.webvpn_configs.append(item)
                if self.config.webvpn is None:
                    self.config.webvpn = item
                item.raw_lines.append(sanitize_raw_text(line))
                for child in children:
                    safe = sanitize_raw_text(child)
                    item.raw_lines.append(safe)
                    parts = child.split()
                    if len(parts) >= 2 and parts[0].lower() == "enable":
                        self._append_unique(item.enabled_interfaces, parts[1:])
                        _mark_explicit(item, "enabled_interfaces")
                    elif parts[:2] == ["tunnel-group-list", "enable"] or parts[:2] == ["tunnel-group-list", "disable"]:
                        item.tunnel_group_list = parts[1].lower() == "enable"
                        _mark_explicit(item, "tunnel_group_list")
                    elif len(parts) >= 2 and parts[0].lower() in {"anyconnect", "svc"}:
                        (item.client_profiles if "profile" in parts[1].lower() else item.client_images).append(" ".join(parts[1:]))
                    elif parts and parts[0].lower() in {"certificate", "trust-point", "trustpoint"}:
                        item.trustpoint_references.extend(parts[1:])
                    else:
                        item.raw_extra.setdefault("unmodeled_lines", []).append(safe)
                continue
            elif lower.startswith(("vpn-addr-assign ", "no vpn-addr-assign ")):
                parts = line.split()
                negated = parts[0].lower() == "no"
                offset = 1 if negated else 0
                if len(parts) > offset + 1:
                    context = self._line_contexts.get(index + 1)
                    item = next((record for record in self.config.vpn_address_assignments if record.source_context == context), None)
                    if item is None:
                        item = self._with_source_context(CiscoVPNAddressAssignment(name="vpn-addr-assign"), index + 1)
                        self.config.vpn_address_assignments.append(item)
                    if self.config.vpn_address_assignment is None:
                        self.config.vpn_address_assignment = item
                    method = parts[offset + 1].lower()
                    if method in {"aaa", "dhcp", "local"}:
                        setattr(item, f"{method}_enabled", not negated)
                        _mark_explicit(item, f"{method}_enabled")
                        if not negated and method == "local" and len(parts) == offset + 4 and parts[offset + 2].lower() == "reuse-delay" and parts[offset + 3].isdigit():
                            item.reuse_delay = int(parts[offset + 3]); _mark_explicit(item, "reuse_delay")
                        elif not negated and method == "local" and len(parts) > offset + 2 and not (len(parts) == offset + 4 and parts[offset + 2].lower() == "reuse-delay"):
                            item.raw_extra.setdefault("unmodeled_lines", []).append(sanitize_raw_text(line))
                    else:
                        item.raw_extra.setdefault("unmodeled_lines", []).append(sanitize_raw_text(line))
                    item.raw_lines.append(sanitize_raw_text(line))
                continue
            elif lower.startswith("privilege "):
                match = re.fullmatch(r"privilege\s+(cmd|show|clear)\s+level\s+(\d+)\s+(?:mode\s+(\S+)\s+)?command\s+(.+)", line, re.I)
                if match:
                    form, level, mode_scope, command_text = match.groups()
                    level_value = int(level)
                    record = CiscoCommandPrivilege(
                        name=f"privilege:{index + 1}", privilege_level=level_value,
                        command_form=form.lower(), command=command_text,
                        cli_mode=mode_scope or None, raw_line=sanitize_raw_text(line),
                        raw_lines=[sanitize_raw_text(line)], source_order=index + 1,
                        explicit_fields={"privilege_level", "command_form", "command", *(('cli_mode',) if mode_scope else ())},
                        extraction_status="EXTRACTED" if 0 <= level_value <= 15 else "PARSE_ERROR",
                    )
                    if not 0 <= level_value <= 15:
                        record.review_reasons.append("Privilege level must be between 0 and 15")
                    self.config.command_privileges.append(self._with_source_context(record, index + 1))
                else:
                    self._record_unsupported(index + 1, line, "Malformed privilege command")
                continue
            elif re.match(r"^track\s+\d+\s+", lower):
                track_id = int(line.split()[1])
                if track_id not in self.config.route_tracking_ids:
                    self.config.route_tracking_ids.append(track_id)
                parts = line.split()
                record = CiscoTrack(name=f"track:{track_id}", track_id=track_id, track_type=parts[2] if len(parts) > 2 else None,
                                     sla_id=int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else None,
                                     raw_lines=[line], source_attributes={"raw_command": line})
                self.config.tracks.append(self._with_source_context(record, index + 1))
            elif re.match(r"^sla\s+monitor\s+\d+\b", lower):
                parts = line.split()
                sla_id = int(parts[2])
                record = CiscoSLAMonitor(name=f"sla:{sla_id}", sla_id=sla_id, operation=" ".join(parts[3:]),
                                         raw_lines=[line], source_attributes={"raw_command": line})
                for child in children:
                    record.raw_lines.append(child)
                    record.source_attributes.setdefault("raw_commands", []).append(child)
                    child_parts = child.split()
                    if child_parts[:1] == ["frequency"] and len(child_parts) == 2 and child_parts[1].isdigit():
                        record.frequency = int(child_parts[1])
                    elif child_parts[:1] == ["ip sla"]:
                        record.target = child_parts[-1]
                self.config.sla_monitors.append(self._with_source_context(record, index + 1))
            elif re.match(r"^router\s+\S+", lower):
                record = CiscoSourceRecord(name=f"router:{index + 1}", raw_lines=[line] + children,
                                            source_attributes={"protocol": line.split()[1], "raw_command": line})
                self.config.dynamic_routing.append(self._with_source_context(record, index + 1))
            elif re.match(r"^crypto\s+ikev[12]\s+policy\s+\d+", lower):
                match = re.match(r"^crypto\s+(ikev[12])\s+policy\s+(\d+)", line, re.IGNORECASE)
                self.config.ike_policies.append(self._with_source_context(CiscoIKEPolicy(
                    name=f"{match.group(1)}:{match.group(2)}", version=match.group(1),
                    number=int(match.group(2)), raw_lines=[line, *children],
                    source_attributes={"raw_command": line, "subcommands": children},
                ), index + 1))
                self._parse_ike_child(self.config.ike_policies[-1], children, index + 1)
            elif re.match(r"^crypto\s+ipsec\s+profile\s+\S+", lower):
                name = line.split()[3]
                record = CiscoIPsecProfile(name=name, raw_lines=[sanitize_raw_text(line)], source_attributes={"raw_command": sanitize_raw_text(line)})
                for child in children:
                    parts = child.split()
                    lowered = [part.lower() for part in parts]
                    if lowered[:3] == ["set", "ikev1", "transform-set"] and len(parts) > 3:
                        self._append_unique(record.ikev1_transform_sets, parts[3:])
                        _mark_explicit(record, "ikev1_transform_sets")
                    elif lowered[:3] == ["set", "ikev2", "ipsec-proposal"] and len(parts) > 3:
                        self._append_unique(record.ikev2_ipsec_proposals, parts[3:])
                        _mark_explicit(record, "ikev2_ipsec_proposals")
                    elif lowered[:2] == ["set", "pfs"] and len(parts) > 2:
                        record.pfs = " ".join(parts[2:])
                        _mark_explicit(record, "pfs")
                    elif lowered[:3] == ["set", "security-association", "lifetime"] and len(parts) == 5 and parts[3].lower() in {"seconds", "kilobytes"} and parts[4].isdigit():
                        setattr(record, f"sa_lifetime_{parts[3].lower()}", int(parts[4]))
                        _mark_explicit(record, f"sa_lifetime_{parts[3].lower()}")
                    elif lowered[:2] == ["set", "trustpoint"] and len(parts) == 3:
                        record.trustpoint = parts[2]
                        _mark_explicit(record, "trustpoint")
                    elif lowered == ["responder-only"]:
                        record.responder_only = True
                        _mark_explicit(record, "responder_only")
                    else:
                        safe_child = sanitize_raw_text(child)
                        record.raw_lines.append(safe_child)
                        record.raw_extra.setdefault("unmodeled_lines", []).append(safe_child)
                        record.extraction_status = "PARTIAL"
                        record.requires_manual_review = True
                        record.review_reasons.append("Unsupported IPsec profile child syntax")
                self.config.ipsec_profiles.append(self._with_source_context(record, index + 1))
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
                    record.extraction_status = "PARTIAL"
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
                        record.raw_extra.setdefault("unmodeled_lines", []).append(sanitize_raw_text(child))
                if not values:
                    record.extraction_status = "PARSE_ERROR"
                    record.requires_manual_review = True
            elif re.match(r"^crypto\s+dynamic-map\s+", lower):
                self._parse_crypto_map_line(line, index + 1, True)
            elif lower.startswith("crypto map "):
                self._parse_crypto_map_line(line, index + 1)
            elif lower.startswith("ip local pool "):
                parts = line.split()
                record = CiscoVPNAddressPool(name=parts[3] if len(parts) > 3 else "unknown", raw_line=sanitize_raw_text(line), raw_lines=[sanitize_raw_text(line)], source_attributes={"raw_command": line})
                range_parts = parts[4].split("-", 1) if len(parts) > 4 else []
                if len(range_parts) == 2 and range_parts[0] and range_parts[1]:
                    record.start, record.end = range_parts
                    if len(parts) == 7 and parts[5].lower() == "mask":
                        record.mask = parts[6]
                    elif len(parts) != 5:
                        record.extraction_status = "PARSE_ERROR"
                        record.requires_manual_review = True
                        record.raw_extra["unparsed_tokens"] = parts[5:]
                        self._record_diagnostic(index + 1, line, "Malformed VPN address pool options", "ip local pool", record.name)
                    try:
                        start, end = ipaddress.IPv4Address(record.start), ipaddress.IPv4Address(record.end)
                        mask = ipaddress.IPv4Address(record.mask) if record.mask else None
                        prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen if mask else None
                        if int(start) > int(end) or (prefix is not None and prefix in {31, 32}):
                            raise ValueError
                        record.address_family = "ipv4"
                    except ValueError:
                        record.extraction_status = "PARSE_ERROR"
                        record.requires_manual_review = True
                        self._record_diagnostic(index + 1, line, "Malformed VPN address pool", "ip local pool", record.name)
                else:
                    record.extraction_status = "PARSE_ERROR"
                    record.requires_manual_review = True
                    self._record_diagnostic(index + 1, line, "Malformed VPN address pool range", "ip local pool", record.name)
                self.config.vpn_address_pools.append(self._with_source_context(record, index + 1))
            elif lower.startswith("tunnel-group "):
                parts = line.split()
                name = parts[1] if len(parts) > 1 else "unknown"
                source_context = self._line_contexts.get(index + 1)
                record = next((item for item in self.config.tunnel_groups if item.name == name and item.source_context == source_context), None)
                if record is None:
                    record = CiscoTunnelGroup(name=name, raw_lines=[])
                    self.config.tunnel_groups.append(self._with_source_context(record, index + 1))
                record.raw_lines.extend([sanitize_raw_text(line), *map(sanitize_raw_text, children)])
                record.source_attributes.setdefault("raw_commands", []).append(line)
                if len(parts) > 2 and parts[2].lower() == "type":
                    record.group_type = parts[3] if len(parts) > 3 else None
                section = " ".join(parts[2:]).lower() if len(parts) > 2 and parts[2].lower() in {"general-attributes", "ipsec-attributes", "webvpn-attributes"} else None
                for child in children:
                    child_parts = child.split()
                    if child.lower() in {"general-attributes", "ipsec-attributes", "webvpn-attributes"}:
                        section = child.lower()
                        continue
                    attrs = (record.general_attributes if section == "general-attributes" else
                             record.ipsec_attributes if section == "ipsec-attributes" else record.webvpn_attributes)
                    if "pre-shared-key" in child_parts:
                        record.ikev1_psk_present = True
                        attrs["has_pre_shared_key"] = True
                        attrs.setdefault("raw_subcommands", []).append(re.sub(r"(?i)(pre-shared-key)\s+\S+", r"\1 [REDACTED]", child))
                    elif child_parts and child_parts[0].lower() == "default-group-policy" and len(child_parts) > 1:
                        record.default_group_policy = child_parts[1]
                        _mark_explicit(record, "default_group_policy")
                    elif child_parts and child_parts[0].lower() == "address-pool":
                        self._append_unique(record.address_pools, child_parts[1:])
                        _mark_explicit(record, "address_pools")
                    elif child_parts and child_parts[0].lower() == "authentication-server-group" and len(child_parts) > 1:
                        record.authentication_method = " ".join(child_parts[1:])
                        record.general_attributes["authentication_server_group"] = child_parts[1]
                        _mark_explicit(record, "general_attributes")
                    elif child_parts and child_parts[0].lower() == "trust-point" and len(child_parts) > 1:
                        record.trustpoint = child_parts[1]
                    elif child_parts and child_parts[0].lower() in {"ikev1", "ikev2"} and len(child_parts) > 2:
                        setattr(record, f"{child_parts[0].lower()}_{child_parts[1].lower().replace('-', '_')}", " ".join(child_parts[2:]))
                    elif child_parts and child_parts[0].lower() in {"authentication", "ikev1-authentication", "ikev2-authentication"}:
                        record.authentication_method = " ".join(child_parts[1:])
                        if section == "webvpn-attributes":
                            record.webvpn_attributes[child_parts[0].lower()] = " ".join(child_parts[1:])
                            _mark_explicit(record, "webvpn_attributes")
                    elif child_parts:
                        attrs.setdefault("raw_subcommands", []).append(sanitize_raw_text(child))
                        _mark_explicit(record, "webvpn_attributes" if section == "webvpn-attributes" else "general_attributes" if section == "general-attributes" else "ipsec_attributes")
                if record.raw_lines:
                    record.extraction_status = "PARTIAL"
            elif lower.startswith("group-policy "):
                try:
                    parts = shlex.split(line)
                except ValueError:
                    parts = line.split()
                name = parts[1] if len(parts) > 1 else "unknown"
                source_context = self._line_contexts.get(index + 1)
                record = next((item for item in self.config.group_policies if item.name == name and item.source_context == source_context), None)
                if record is None:
                    record = CiscoGroupPolicy(name=name, raw_lines=[], source_attributes={"raw_command": line, "subcommands": []})
                    self.config.group_policies.append(self._with_source_context(record, index + 1))
                if len(parts) > 2 and parts[2].lower() in {"internal", "external"}:
                    record.policy_type = parts[2].lower()
                if len(parts) > 4 and parts[3].lower() == "from":
                    record.parent = parts[4]
                    _mark_explicit(record, "parent")
                record.raw_lines.extend([sanitize_raw_text(line), *map(sanitize_raw_text, children)])
                record.source_attributes["subcommands"].extend(map(sanitize_raw_text, children))
                in_webvpn = False
                for child in children:
                    child_parts = child.split()
                    if child_parts and child_parts[0].lower() == "webvpn":
                        in_webvpn = True
                        record.webvpn_attributes.setdefault("raw_subcommands", []).append(sanitize_raw_text(child))
                        _mark_explicit(record, "webvpn_attributes")
                        continue
                    if len(child_parts) < 2:
                        record.raw_attributes.setdefault("unmodeled_lines", []).append(sanitize_raw_text(child))
                        continue
                    key, values = child_parts[0].lower(), child_parts[1:]
                    if key == "address-pools": self._append_unique(record.address_pools, values[1:] if values[0].lower() == "value" else values); _mark_explicit(record, "address_pools")
                    elif key == "dns-server": self._append_unique(record.dns_servers, values[1:] if values[0].lower() == "value" else values); _mark_explicit(record, "dns_servers")
                    elif key == "split-tunnel-policy": record.split_tunnel_policy = values[0]; _mark_explicit(record, "split_tunnel_policy")
                    elif key == "split-tunnel-network-list":
                        record.split_tunnel_acl = values[-1]
                        _mark_explicit(record, "split_tunnel_acl")
                        self._record_acl_consumer(record.split_tunnel_acl, "vpn-split-tunnel", index + 1, child)
                    elif key == "vpn-tunnel-protocol": self._append_unique(record.vpn_protocols, values); _mark_explicit(record, "vpn_protocols")
                    elif key == "vpn-idle-timeout": record.idle_timeout = " ".join(values)
                    elif key == "vpn-session-timeout": record.session_timeout = " ".join(values)
                    elif key == "default-domain": record.default_domain = " ".join(values); _mark_explicit(record, "default_domain")
                    elif key == "vpn-access-hours": record.vpn_access_hours = values[-1]; _mark_explicit(record, "vpn_access_hours")
                    elif key == "vpn-filter":
                        record.vpn_filter_acl = values[-1]
                        _mark_explicit(record, "vpn_filter_acl")
                        self._record_acl_consumer(record.vpn_filter_acl, "vpn-filter", index + 1, child)
                    elif key == "vpn-simultaneous-logins" and values and values[-1].isdigit():
                        record.vpn_simultaneous_logins = int(values[-1])
                        _mark_explicit(record, "vpn_simultaneous_logins")
                    elif key == "wins-server":
                        self._append_unique(record.wins_servers, values[1:] if values[0].lower() == "value" else values)
                        _mark_explicit(record, "wins_servers")
                    elif key == "group-policy": record.parent = values[-1]
                    elif child_parts[0].lower() in {"group-alias", "group-url", "anyconnect", "url-entry", "customization", "activex", "activex-relay", "keep-installer", "port-forward", "tunnel-group-list"}:
                        record.webvpn_attributes.setdefault(child_parts[0].lower(), []).append(" ".join(values))
                    elif in_webvpn:
                        record.webvpn_attributes.setdefault("raw_subcommands", []).append(sanitize_raw_text(child))
                        _mark_explicit(record, "webvpn_attributes")
                    else:
                        record.raw_attributes.setdefault("unmodeled_lines", []).append(sanitize_raw_text(child))
                        record.extraction_status = "PARTIAL"
                record.extraction_status = "PARTIAL"
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
        record.extraction_status = "PARTIAL"
        record.requires_manual_review = True
        if reason not in record.review_reasons:
            record.review_reasons.append(reason)

    def _mpf_parse_error(self, record: Any, line_number: int, line: str, section: str, reason: str) -> None:
        record.extraction_status = "PARSE_ERROR"
        record.requires_manual_review = True
        if hasattr(record, "review_reasons") and reason not in record.review_reasons:
            record.review_reasons.append(reason)
        self._record_diagnostic(line_number, line, reason, section, getattr(record, "name", None))





    @staticmethod
    def _valid_timeout(value: str) -> bool:
        return bool(re.fullmatch(r"\d{1,2}:\d{2}:\d{2}", value)) and int(value.split(":", 1)[0]) >= 0 and int(value.split(":")[1]) < 60 and int(value.rsplit(":", 1)[1]) < 60

    def _parse_global_conn(self, line: str, line_number: int) -> CiscoConnectionControl:
        safe = sanitize_raw_text(line)
        return CiscoConnectionControl(
            name=f"unverified-global-connection:{line_number}",
            setting=line.split()[0].lower() if line.split() else "connection",
            control_type="unverified_global_connection",
            raw_lines=[safe], source_order=line_number,
            source_attributes={"raw_command": safe, "unmodeled_tokens": line.split()[1:]},
            extraction_status="UNSUPPORTED", requires_manual_review=True,
            review_reasons=["Standalone conn-prefixed syntax is not modeled as a global equivalent of MPF set connection"],
        )

    def _parse_timeout_command(self, line: str, line_number: int) -> CiscoConnectionControl:
        parts = line.split()
        item = CiscoConnectionControl(
            name="timeout", setting="timeout", values=parts[1:], control_type="timeout",
            raw_lines=[line], source_order=line_number, source_attributes={"raw_command": line},
            extraction_status="PARTIAL", requires_manual_review=False,
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
            item.extraction_status = "PARSE_ERROR"
            item.requires_manual_review = True
            item.review_reasons.append("Malformed ASA timeout duration")
            self._record_diagnostic(line_number, line, "Malformed timeout duration", "timeout")
            return item
        setattr(item, fields[key], value)
        return item


    @staticmethod
    def _ip(value: str) -> bool:
        try:
            return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
        except ValueError:
            return False

    def _dhcp_server(self, interface: str, line_number: int) -> CiscoDHCPServer:
        source_context = self._line_contexts.get(line_number)
        scoped = [server for server in self.config.dhcp_servers if server.source_context == source_context]
        key = interface
        item = next((server for server in scoped if server.name == f"dhcpd:{key}"), None)
        if item is None:
            item = CiscoDHCPServer(
                name=f"dhcpd:{key}", interface=interface, source_order=line_number,
                extraction_status="PARTIAL", requires_manual_review=False,
            )
            self.config.dhcp_servers.append(self._with_source_context(item, line_number))
        return item


    def _parse_dhcprelay_command(self, line: str, line_number: int) -> None:
        parts = line.split()
        command = parts[1].lower() if len(parts) > 1 else ""
        relay = next((item for item in self.config.dhcp_relays if item.name == "dhcprelay"), None)
        if relay is None:
            relay = CiscoDHCPRelay(name="dhcprelay", extraction_status="PARTIAL", requires_manual_review=False)
            self.config.dhcp_relays.append(relay)
        relay.raw_lines.append(line)
        relay.source_attributes.setdefault("raw_commands", []).append(line)
        relay.source_order = relay.source_order or line_number
        if command == "server" and len(parts) >= 3:
            server = parts[2]
            interface = parts[3] if len(parts) > 3 else None
            entry = CiscoDHCPRelayServer(
                server=server, interface=interface, raw=sanitize_raw_text(line), source_order=line_number,
                explicit_fields={"server", "interface"} if interface else {"server"},
            )
            relay.server_entries.append(entry)
            relay.servers.append(server)
            relay.server = relay.server or server
            relay.interface = relay.interface or interface
            if not self._ip(server):
                relay.extraction_status = "PARSE_ERROR"
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




    def _parse_network_object(self, name: str, block: List[str]) -> CiscoNetworkObject:
        obj = CiscoNetworkObject(name=name, raw_lines=list(block))
        defined = False
        for sub in block:
            parts = sub.split()
            lower = sub.lower()
            if lower.startswith(("host ", "subnet ", "range ", "fqdn ")):
                obj.source_attributes.setdefault("address_definitions", []).append(sub)
            if lower.startswith("host ") and len(parts) == 2:
                try:
                    address = ipaddress.ip_address(parts[1])
                    value = str(address)
                    if defined and (obj.type, obj.value) != ("host", value):
                        obj.source_attributes.setdefault("conflicting_definitions", []).append(sub)
                        obj.extraction_status = "PARSE_ERROR"
                        obj.requires_manual_review = True
                    elif not defined:
                        obj.type, obj.value = "host", value
                        obj.address_family = f"ipv{address.version}"
                        defined = True
                except ValueError:
                    obj.source_attributes["invalid_host"] = parts[1]
                    obj.extraction_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
            elif lower.startswith("host "):
                obj.extraction_status = "PARSE_ERROR"
                obj.requires_manual_review = True
                obj.source_attributes.setdefault("invalid_definitions", []).append(sub)
            elif lower.startswith("subnet ") and len(parts) >= 2:
                if len(parts) not in {2, 3} or (len(parts) == 3 and ":" in parts[1]):
                    obj.extraction_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
                    obj.source_attributes.setdefault("invalid_definitions", []).append(sub)
                    continue
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
                    obj.extraction_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
                    obj.source_attributes["invalid_subnet"] = " ".join(parts[1:])
                else:
                    if defined and (obj.type, obj.value) != ("subnet", value):
                        obj.source_attributes.setdefault("conflicting_definitions", []).append(sub)
                        obj.extraction_status = "PARSE_ERROR"
                        obj.requires_manual_review = True
                    elif not defined:
                        obj.type, obj.value = "subnet", value
                        defined = True
            elif lower.startswith("subnet "):
                obj.extraction_status = "PARSE_ERROR"
                obj.requires_manual_review = True
                obj.source_attributes.setdefault("invalid_definitions", []).append(sub)
            elif lower.startswith("range ") and len(parts) == 3:
                try:
                    start, end = ipaddress.ip_address(parts[1]), ipaddress.ip_address(parts[2])
                    if start.version != end.version or int(start) > int(end):
                        raise ValueError
                    value = f"{start}-{end}"
                    if defined and (obj.type, obj.value) != ("range", value):
                        obj.source_attributes.setdefault("conflicting_definitions", []).append(sub)
                        obj.extraction_status = "PARSE_ERROR"
                        obj.requires_manual_review = True
                    elif not defined:
                        obj.type, obj.value = "range", value
                        obj.address_family = f"ipv{start.version}"
                        defined = True
                except ValueError:
                    obj.extraction_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
                    obj.source_attributes["invalid_range"] = " ".join(parts[1:3])
            elif lower.startswith("range "):
                obj.extraction_status = "PARSE_ERROR"
                obj.requires_manual_review = True
                obj.source_attributes.setdefault("invalid_definitions", []).append(sub)
            elif lower.startswith("fqdn "):
                values = parts[1:]
                if len(values) not in {1, 2} or len(values) == 2 and values[0].lower() not in {"v4", "v6"}:
                    obj.extraction_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
                    obj.source_attributes.setdefault("invalid_definitions", []).append(sub)
                    continue
                if values and values[0].lower() in {"v4", "v6"}:
                    family = values.pop(0).lower()
                    obj.address_family = "ipv4" if family == "v4" else "ipv6"
                    obj.source_attributes["address_family"] = obj.address_family
                if values:
                    value = " ".join(values)
                    if defined and (obj.type, obj.value) != ("fqdn", value):
                        obj.source_attributes.setdefault("conflicting_definitions", []).append(sub)
                        obj.extraction_status = "PARSE_ERROR"
                        obj.requires_manual_review = True
                    elif not defined:
                        obj.type, obj.value = "fqdn", value
                        defined = True
            elif lower == "description" or lower.startswith("description "):
                if len(parts) < 2:
                    obj.extraction_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
                    obj.source_attributes.setdefault("invalid_definitions", []).append(sub)
                    continue
                obj.description = sub.split(maxsplit=1)[1]
                _mark_explicit(obj, "description")
            elif lower.startswith("nat "):
                obj.nat_lines.append(sub)
            else:
                obj.raw_extra.setdefault("unmodeled_lines", []).append(sanitize_raw_text(sub))
        if obj.type is not None:
            _mark_explicit(obj, "type")
        if obj.value is not None:
            _mark_explicit(obj, "value")
        if obj.type is None or obj.value is None:
            obj.extraction_status = "PARSE_ERROR"
            obj.requires_manual_review = True
        elif obj.raw_extra.get("unmodeled_lines"):
            obj.extraction_status = "PARTIAL"
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
        pending_global_mtu: List[Dict[str, Any]] = []
        i = 0
        while i < len(lines):
            raw = lines[i]
            line = raw.strip()
            line_number = i + 1
            admin_match = re.fullmatch(r"admin-context\s+(\S+)", line, re.I)
            if admin_match:
                system = self.config.multi_context_system
                system.admin_context_name = admin_match.group(1)
                system.raw_lines.append(sanitize_raw_text(line))
                i += 1
                continue
            if re.fullmatch(r"no\s+admin-context(?:\s+\S+)?", line, re.I):
                self.config.multi_context_system.admin_context_name = None
                self.config.multi_context_system.raw_lines.append(sanitize_raw_text(line))
                i += 1
                continue
            if not line or line.startswith((":", "!")):
                i += 1
                continue
            if line.lower().startswith("hostname "):
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    self.config.hostname = parts[1]
                    self.config.system_settings.hostname = parts[1]
                    _mark_explicit(self.config, "hostname")
                    _mark_explicit(self.config.system_settings, "hostname")
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
                if line.lower().startswith("no service-policy "):
                    record = self._with_source_context(self._parse_service_policy_line(line, line_number), line_number)
                    self.config.service_policies.append(record)
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
            if re.match(r"^icmp\s+(?:permit|deny)\s+", line, re.IGNORECASE):
                self._parse_icmp_management_command(line, line_number)
                i += 1
                continue
            if re.match(r"^dns-group\s+\S+$", line, re.I):
                self.config.dns_settings.default_server_group = line.split()[1]
                self.config.dns_settings.command_history.append(sanitize_raw_text(line))
                i += 1
                continue
            if re.match(r"^crypto\s+ca\s+trustpoint\s+\S+", line, re.I):
                from .parser_mpf import _parse_trustpoint_block
                i = _parse_trustpoint_block(self, lines, i)
                continue
            certificate = re.fullmatch(r"crypto\s+ca\s+certificate\s+chain\s+(\S+)", line, re.I)
            if certificate:
                name = certificate.group(1)
                record = next((item for item in self.config.trustpoint_records
                               if item.name == name and item.source_context == self._line_contexts.get(line_number)), None)
                if record is None:
                    record = CiscoTrustpointRecord(name=name, source_context=self._line_contexts.get(line_number),
                                                   extraction_status="SOURCE_ONLY", requires_manual_review=True)
                    record.review_reasons.append("Certificate chain has no preceding trustpoint definition")
                    self.config.trustpoint_records.append(record)
                record.certificate_present = True
                record.certificate_references.append(sanitize_raw_text(line))
                record.raw_lines.append(sanitize_raw_text(line))
                i += 1
                while i < len(lines) and lines[i][:1].isspace() and lines[i].strip() and not lines[i].strip().startswith("!"):
                    # Certificate bodies are intentionally not retained.
                    i += 1
                continue
            zone_match = re.match(r"^zone(?:\s+name)?\s+(\S+)$", line, re.IGNORECASE)
            if zone_match:
                zone = CiscoTrafficZone(
                    name=zone_match.group(1), raw_lines=[line],
                    source_attributes={"raw_command": line},
                )
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    child = lines[i].strip()
                    zone.raw_lines.append(child)
                    child_match = re.match(r"^(?:zone-member|interface)\s+(\S+)$", child, re.IGNORECASE)
                    if child_match:
                        if child_match.group(1) not in zone.members:
                            zone.members.append(child_match.group(1))
                    else:
                        zone.raw_extra.setdefault("unmodeled_lines", []).append(child)
                    i += 1
                self.config.traffic_zones.append(self._with_source_context(zone, line_number))
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
                            context.allocated_interface_entries.append(CiscoAllocatedInterface(
                                physical_interface=parts[1], mapped_name=parts[2] if len(parts) > 2 else None,
                                range_expression=parts[1] if "-" in parts[1] else None,
                                source_order=line_number, raw=sanitize_raw_text(line),
                                explicit_fields={"physical_interface", "mapped_name"} if len(parts) > 2 else {"physical_interface"},
                            ))
                        else:
                            context.extraction_status = "PARSE_ERROR"
                            context.requires_manual_review = True
                            context.review_reasons.append("Malformed allocate-interface command")
                            self._record_diagnostic(line_number, line, "Malformed allocate-interface command", "context", context.name)
                    elif lower == "config-url" or lower.startswith("config-url "):
                        parts = line.split(maxsplit=1)
                        if len(parts) > 1:
                            context.config_url = parts[1]
                        else:
                            context.extraction_status = "PARSE_ERROR"
                            context.requires_manual_review = True
                            context.review_reasons.append("Malformed config-url command")
                            self._record_diagnostic(line_number, line, "Malformed config-url command", "context", context.name)
                    elif lower == "resource-class" or lower.startswith("resource-class "):
                        parts = line.split(maxsplit=1)
                        if len(parts) > 1:
                            context.resource_class = parts[1]
                        else:
                            context.extraction_status = "PARSE_ERROR"
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

            header = _parse_interface_header(line)
            if header:
                interface = CiscoInterface(name=header["name"], source_context=self._line_contexts.get(line_number))
                for field in ("interface_type", "parent_interface", "interface_suffix_vlan_id", "bvi_id", "port_channel_id", "vlan_id"):
                    setattr(interface, field, header[field])
                _mark_explicit(interface, "interface_type", "parent_interface", "interface_suffix_vlan_id", "bvi_id", "port_channel_id", "vlan_id")
                interface.source_attributes.update({"source_line_number": line_number, "raw_header": line})
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
                        _mark_explicit(interface, "nameif")
                    elif lower == "no nameif":
                        interface.nameif = None
                        _mark_explicit(interface, "nameif")
                        interface.source_attributes.setdefault("negated_commands", []).append(sub)
                    elif lower.startswith("security-level "):
                        _mark_explicit(interface, "security_level")
                        if interface.security_level is not None:
                            interface.source_attributes.setdefault("security_level_history", []).append(interface.security_level)
                        try:
                            interface.security_level = int(parts[1])
                        except (IndexError, ValueError):
                            interface.extraction_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                    elif lower == "no security-level":
                        interface.security_level = None
                        _mark_explicit(interface, "security_level")
                        interface.source_attributes.setdefault("negated_commands", []).append(sub)
                    elif lower.startswith("vlan "):
                        _mark_explicit(interface, "vlan_id")
                        if len(parts) > 2 and parts[2].lower() == "secondary":
                            _mark_explicit(interface, "secondary_vlan_ids", "secondary_vlan_ranges")
                        try:
                            explicit_vlan = int(parts[1])
                            interface.source_attributes["explicit_vlan_id"] = explicit_vlan
                            interface.vlan_id = explicit_vlan
                            if len(parts) > 2 and parts[2].lower() == "secondary":
                                for value in re.split(r"[\s,]+", " ".join(parts[3:]).strip()):
                                    value = value.strip()
                                    if re.fullmatch(r"\d+", value):
                                        interface.secondary_vlan_ids.append(int(value))
                                    elif re.fullmatch(r"\d+-\d+", value):
                                        interface.secondary_vlan_ranges.append(value)
                                    elif value:
                                        raise ValueError
                                _mark_explicit(interface, "secondary_vlan_ids", "secondary_vlan_ranges")
                            interface.interface_type = "subinterface"
                        except (IndexError, ValueError):
                            interface.extraction_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                            interface.raw_extra.setdefault("invalid_interface_settings", []).append(sanitize_raw_text(sub))
                    elif lower.startswith("channel-group "):
                        _mark_explicit(interface, "channel_group", "channel_group_mode")
                        try:
                            interface.channel_group = int(parts[1])
                            interface.channel_group_mode = parts[3] if len(parts) >= 4 and parts[2].lower() == "mode" else None
                            _mark_explicit(interface, "channel_group", "channel_group_mode")
                        except (IndexError, ValueError):
                            interface.extraction_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                            interface.raw_extra.setdefault("invalid_interface_settings", []).append(sanitize_raw_text(sub))
                    elif lower.startswith("member-interface "):
                        _mark_explicit(interface, "redundant_interface_members")
                        interface.redundant_interface_members.append(parts[1])
                        interface.interface_type = "redundant"
                    elif lower.startswith("bridge-group "):
                        _mark_explicit(interface, "bridge_group")
                        try:
                            interface.bridge_group = int(parts[1])
                            if interface.interface_type == "physical":
                                interface.interface_type = "bridge-member"
                        except (IndexError, ValueError):
                            interface.extraction_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                            interface.raw_extra.setdefault("invalid_interface_settings", []).append(sanitize_raw_text(sub))
                    elif lower.startswith("mtu "):
                        _mark_explicit(interface, "mtu")
                        try:
                            if interface.mtu is not None:
                                interface.source_attributes.setdefault("mtu_history", []).append(interface.mtu)
                            interface.mtu = int(parts[1])
                        except (IndexError, ValueError):
                            interface.extraction_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                            interface.raw_extra.setdefault("invalid_interface_settings", []).append(sanitize_raw_text(sub))
                    elif lower.startswith(("routing-context ", "vrf forwarding ")):
                        _mark_explicit(interface, "vrf" if lower.startswith("vrf forwarding ") else "routing_context")
                        if len(parts) != 2:
                            interface.extraction_status = "PARSE_ERROR"
                            interface.requires_manual_review = True
                            interface.raw_extra.setdefault("invalid_interface_settings", []).append(sanitize_raw_text(sub))
                            i += 1
                            continue
                        _, value = sub.split(maxsplit=1)
                        if lower.startswith("vrf forwarding "):
                            interface.vrf = value
                        else:
                            interface.routing_context = value
                    elif lower.startswith("ip address "):
                        _mark_explicit(interface, "ip_mode", "ip", "mask", "standby_ip", "dhcp_setroute")
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
                                interface.raw_extra.setdefault("unmodeled_ip_address_tokens", []).extend(map(sanitize_raw_text, parts[4:]))
                    elif lower.startswith("ipv6 address "):
                        _mark_explicit(interface, "ipv6_autoconfig", "ipv6_dhcp", "ipv6_dhcp_setroute", "ipv6_addresses")
                        args = parts[2:]
                        if args and args[0].lower() == "autoconfig":
                            interface.ipv6_autoconfig = True
                            _mark_explicit(interface, "ipv6_autoconfig")
                        elif args and args[0].lower() == "dhcp":
                            interface.ipv6_dhcp = True
                            interface.ipv6_dhcp_setroute = "setroute" in {p.lower() for p in args[1:]}
                            _mark_explicit(interface, "ipv6_dhcp", "ipv6_dhcp_setroute")
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
                                _mark_explicit(interface, "ipv6_addresses")
                            except (ValueError, IndexError):
                                interface.extraction_status = "PARSE_ERROR"
                                interface.requires_manual_review = True
                                interface.raw_extra.setdefault("invalid_ipv6_addresses", []).append(sanitize_raw_text(sub))
                    elif lower.startswith("tunnel source ") and len(parts) >= 3:
                        _mark_explicit(interface, "tunnel_source")
                        interface.tunnel_source = " ".join(parts[2:])
                    elif lower.startswith("tunnel destination ") and len(parts) >= 3:
                        _mark_explicit(interface, "tunnel_destination")
                        interface.tunnel_destination = parts[2]
                    elif lower.startswith("tunnel protection ipsec profile ") and len(parts) >= 5:
                        _mark_explicit(interface, "ipsec_profile")
                        interface.ipsec_profile = parts[4]
                        interface.source_attributes["route_based_vpn"] = True
                        interface.extraction_status = "PARTIAL"
                        interface.requires_manual_review = True
                    elif lower.startswith("tunnel protection ipsec policy ") and len(parts) >= 5:
                        interface.ipsec_policy_acl = parts[4]
                        _mark_explicit(interface, "ipsec_policy_acl")
                    elif lower.startswith("dhcprelay server "):
                        address = parts[2] if len(parts) == 3 else ""
                        relay = next((item for item in self.config.dhcp_relays if item.name == "dhcprelay"), None)
                        if relay is None:
                            relay = CiscoDHCPRelay(name="dhcprelay", extraction_status="PARTIAL", requires_manual_review=False)
                            self.config.dhcp_relays.append(relay)
                        if address:
                            entry = CiscoDHCPRelayServer(server=address, interface=interface.name,
                                                         raw=sanitize_raw_text(sub), source_order=i + 1,
                                                         explicit_fields={"server", "interface"})
                            relay.server_entries.append(entry)
                            relay.servers.append(address)
                            relay.server = relay.server or address
                            relay.interface = relay.interface or interface.name
                            try:
                                ipaddress.ip_address(address)
                            except ValueError:
                                relay.extraction_status = "PARSE_ERROR"
                                relay.requires_manual_review = True
                                relay.review_reasons.append("DHCP relay server must be an IP address")
                                self._record_diagnostic(i + 1, sub, "Malformed DHCP relay server", "dhcprelay")
                        else:
                            self._record_diagnostic(i + 1, sub, "Malformed DHCP relay server", "dhcprelay")
                    elif lower.startswith("dhcprelay information "):
                        relay = next((item for item in self.config.dhcp_relays if item.name == "dhcprelay"), None)
                        if relay is None:
                            relay = CiscoDHCPRelay(name="dhcprelay", extraction_status="PARTIAL", requires_manual_review=False)
                            self.config.dhcp_relays.append(relay)
                        relay.options.append(f"{interface.name}: information {' '.join(parts[2:])}")
                    elif lower == "management-only":
                        interface.management_only = True
                        _mark_explicit(interface, "management_only")
                    elif lower.startswith("description "):
                        interface.description = sub.split(maxsplit=1)[1]
                        _mark_explicit(interface, "description")
                    elif lower.startswith("policy-route route-map "):
                        _mark_explicit(interface, "policy_route_maps")
                        parts = sub.split()
                        if len(parts) == 3:
                            interface.policy_route_maps.append(parts[2])
                            _mark_explicit(interface, "policy_route_maps")
                        else:
                            interface.raw_extra.setdefault("invalid_routing_settings", []).append(sanitize_raw_text(sub))
                    elif lower.startswith("policy-route cost "):
                        parts = sub.split()
                        if len(parts) == 3 and re.fullmatch(r"\d+", parts[2]):
                            interface.policy_route_cost = parts[2]
                            _mark_explicit(interface, "policy_route_cost")
                        else:
                            interface.raw_extra.setdefault("unmodeled_lines", []).append(sanitize_raw_text(sub))
                    elif lower.startswith("policy-route path-monitoring"):
                        parts = sub.split()
                        mode = parts[2].lower() if len(parts) == 3 else ""
                        known = {"auto", "auto4", "auto6"}
                        peer = None
                        if len(parts) == 3 and mode not in known:
                            peer = parts[2]
                            mode = "peer"
                        if mode:
                            interface.policy_route_path_monitors.append(CiscoPolicyRoutePathMonitor(
                                mode=mode, peer=peer, raw=sanitize_raw_text(sub), source_order=i + 1,
                                explicit_fields={"mode", *(('peer',) if peer else ())},
                            ))
                            _mark_explicit(interface, "policy_route_path_monitors")
                        else:
                            interface.raw_extra.setdefault("unmodeled_lines", []).append(sanitize_raw_text(sub))
                    elif lower.startswith("zone-member "):
                        _mark_explicit(interface, "traffic_zone_members")
                        if len(parts) == 2:
                            if parts[1] not in interface.traffic_zone_members:
                                interface.traffic_zone_members.append(parts[1])
                            _mark_explicit(interface, "traffic_zone_members")
                        else:
                            interface.raw_extra.setdefault("invalid_interface_settings", []).append(sanitize_raw_text(sub))
                    elif lower == "shutdown":
                        interface.shutdown = True
                        interface.administrative_state = "down"
                        _mark_explicit(interface, "shutdown", "administrative_state")
                    elif lower == "no shutdown":
                        interface.shutdown = False
                        interface.administrative_state = "up"
                        _mark_explicit(interface, "shutdown", "administrative_state")
                    elif lower == "no ip address":
                        interface.ip = interface.mask = interface.ip_mode = interface.standby_ip = None
                        _mark_explicit(interface, "ip", "mask", "ip_mode", "standby_ip")
                        interface.source_attributes.setdefault("negated_commands", []).append(sub)
                    else:
                        interface.raw_extra.setdefault("unmodeled_lines", []).append(sanitize_raw_text(sub))
                    i += 1
                if interface.ip_mode == "static" and normalize_ipv4_network(interface.ip or "", interface.mask or "") is None:
                    interface.extraction_status = "PARSE_ERROR"
                    interface.requires_manual_review = True
                    interface.source_attributes["invalid_ip_address"] = f"{interface.ip or ''} {interface.mask or ''}".strip()
                    self._record_diagnostic(line_number, line, "Invalid interface IPv4 address/netmask", "interface", interface.name)
                if interface.raw_extra.get("unmodeled_lines"):
                    interface.requires_manual_review = True
                    interface.extraction_status = "PARTIAL"
                if interface.dhcp_setroute or interface.ipv6_dhcp_setroute or interface.management_only or interface.ipv6_addresses:
                    interface.requires_manual_review = True
                    if interface.extraction_status == "EXTRACTED":
                        interface.extraction_status = "PARTIAL"
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
                if obj.extraction_status == "PARSE_ERROR":
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
                                    raw=sub,
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
                                    raw=sub,
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
                                            raw=sub,
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
                        group.extraction_status = "PARTIAL"
                        group.requires_manual_review = True
                        group.raw_extra.setdefault("unmodeled_lines", []).append(sanitize_raw_text(sub))
                    if member is not None:
                        _mark_explicit(member, "type", "value")
                        if member.address_family:
                            _mark_explicit(member, "address_family")
                        group.member_entries.append(member)
                    if error:
                        group.extraction_status = "PARSE_ERROR"
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
                                    type="protocol", value=parts[1], raw=sub,
                                ))
                            elif parts[0].lower() == "group-object" and len(parts) == 2:
                                group.member_entries.append(CiscoNamedGroupMember(
                                    type="protocol_group", value=parts[1], raw=sub,
                                ))
                            else:
                                group.extraction_status = "PARSE_ERROR"
                                group.review_reasons.append("Malformed protocol-group member syntax")
                        elif group_type == "icmp-type" and parts:
                            if parts[0].lower() == "icmp-object" and len(parts) == 2:
                                group.member_entries.append(CiscoNamedGroupMember(
                                    type="icmp_type", value=parts[1], raw=sub,
                                ))
                            elif parts[0].lower() == "group-object" and len(parts) == 2:
                                group.member_entries.append(CiscoNamedGroupMember(
                                    type="icmp_group", value=parts[1], raw=sub,
                                ))
                            else:
                                group.extraction_status = "PARSE_ERROR"
                                group.review_reasons.append("Malformed ICMP-type-group member syntax")
                    i += 1
                target = {
                    "protocol": self.config.protocol_groups,
                    "icmp-type": self.config.icmp_type_groups,
                    "user": self.config.user_groups,
                    "security": self.config.security_groups,
                }[group_type]
                for member in group.member_entries:
                    _mark_explicit(member, "type", "value")
                target.append(self._with_source_context(group, line_number))
                continue

            match = re.match(r"^object\s+service\s+(\S+)", line, re.IGNORECASE)
            if match:
                obj = CiscoServiceObject(name=match.group(1))
                service_definitions = []
                i += 1
                while i < len(lines) and bool(lines[i][:1].isspace()) and not lines[i].strip().startswith("!"):
                    sub = lines[i].strip()
                    obj.raw_lines.append(sub)
                    if sub.lower().startswith("service "):
                        ports, error = parse_service_clause(sub.split()[1:])
                        if service_definitions:
                            obj.raw_extra.setdefault("superseded_service_commands", []).append(
                                sanitize_raw_text(service_definitions[-1])
                            )
                            obj.extraction_status = "PARTIAL"
                            obj.requires_manual_review = True
                            obj.review_reasons.append("Multiple service specifications were configured; the last command is authoritative")
                            self._record_diagnostic(i + 1, sub, "Multiple service specifications in one service object", "object service", obj.name, extraction_effect="PARTIAL")
                        service_definitions.append(sub)
                        obj.ports = ports
                        if error:
                            obj.extraction_status = "PARSE_ERROR"
                            obj.requires_manual_review = True
                    elif sub.lower().startswith("description "):
                        obj.description = sub.split(maxsplit=1)[1]
                    else:
                        obj.extraction_status = "PARTIAL"
                        obj.requires_manual_review = True
                    i += 1
                if not obj.ports:
                    obj.extraction_status = "PARSE_ERROR"
                    obj.requires_manual_review = True
                obj.source_attributes["raw_lines"] = obj.raw_lines
                self.config.service_objects.append(self._with_source_context(obj, line_number))
                if obj.extraction_status == "PARSE_ERROR":
                    self._record_diagnostic(line_number, line, "Service object contains malformed or missing service syntax", "object service", obj.name)
                continue

            match = re.match(r"^object-group\s+service\s+(\S+)(?:\s+(\S+))?", line, re.IGNORECASE)
            if match:
                group = CiscoServiceGroup(
                    name=match.group(1),
                    protocol=match.group(2).lower() if match.group(2) else None,
                )
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
                            group.extraction_status = "PARSE_ERROR"
                            group.requires_manual_review = True
                            group.review_reasons.append(error)
                    elif lower.startswith("port-object "):
                        if not group.protocol:
                            group.extraction_status = "PARTIAL"
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
                                group.extraction_status = "PARSE_ERROR"
                                group.requires_manual_review = True
                                group.review_reasons.append(error)
                    elif lower.startswith("description "):
                        group.description = sub.split(maxsplit=1)[1]
                    else:
                        group.extraction_status = "PARTIAL"
                        group.requires_manual_review = True
                    i += 1
                for member in group.member_entries:
                    _mark_explicit(member, "type")
                    for field in ("value", "protocol", "source", "destination", "icmp_type", "icmp_code"):
                        if getattr(member, field) is not None:
                            _mark_explicit(member, field)
                self.config.service_groups.append(self._with_source_context(group, line_number))
                if group.extraction_status == "PARSE_ERROR":
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
                            schedule.extraction_status = "PARSE_ERROR"
                            schedule.requires_manual_review = True
                            schedule.review_reasons.append(error)
                    elif lower_parts and lower_parts[0] == "periodic":
                        clause, error = self._parse_time_range_periodic_clause(sub, len(schedule.clauses) + 1)
                        schedule.clauses.append(clause)
                        if error:
                            schedule.extraction_status = "PARSE_ERROR"
                            schedule.requires_manual_review = True
                            schedule.review_reasons.append(error)
                    else:
                        schedule.extraction_status = "PARTIAL"
                        schedule.requires_manual_review = True
                        schedule.review_reasons.append(f"Unmodeled time-range clause: {sub}")
                        schedule.raw_extra.setdefault("unmodeled_lines", []).append(sanitize_raw_text(sub))
                    i += 1
                schedule.source_attributes["clauses"] = [item.model_dump() for item in schedule.clauses]
                self.config.time_ranges.append(self._with_source_context(schedule, line_number))
                if schedule.extraction_status == "PARSE_ERROR":
                    self._record_diagnostic(line_number, line, "; ".join(schedule.review_reasons), "time-range", schedule.name)
                continue

            if line.lower().startswith("access-list "):
                parts = line.split()
                remark_index = 2 + (2 if len(parts) > 4 and parts[2].lower() == "line" and parts[3].isdigit() else 0)
                if len(parts) > remark_index and parts[remark_index].lower() == "remark":
                    acl_name = parts[1]
                    sequence = int(parts[3]) if remark_index == 4 else None
                    remark = CiscoACLRemark(name=f"{acl_name}:{line_number}", acl_name=acl_name,
                                             sequence=sequence, source_order=line_number,
                                             remark=" ".join(parts[remark_index + 1:]), raw_line=sanitize_raw_text(line),
                                             explicit_fields={"acl_name", "remark", "source_order"} | ({"sequence"} if sequence is not None else set()))
                    self.config.acl_remarks.append(self._with_source_context(remark, line_number))
                    i += 1
                    continue
                rule, error = parse_acl_line(line, line_number, remarks)
                if rule:
                    self.config.access_rules.append(self._with_source_context(rule, line_number))
                    if rule.extraction_status == "PARSE_ERROR":
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
                    match_acl = re.match(r"^match\s+(?:ip\s+address|access-list)\s+(.+)$", sub, re.IGNORECASE)
                    next_hop = re.match(r"^set\s+ip\s+next-hop(?:\s+verify-availability)?\s+(.+)$", sub, re.IGNORECASE)
                    set_interface = re.match(r"^set\s+interface\s+(.+)$", sub, re.IGNORECASE)
                    if match_acl:
                        rule.match_acls.extend(
                            value for value in match_acl.group(1).split()
                            if value not in rule.match_acls
                        )
                        rule.match_acl = rule.match_acls[0] if rule.match_acls else None
                    elif next_hop:
                        candidates = [
                            token for token in next_hop.group(1).split()
                            if _valid_ip(token)
                        ]
                        if candidates:
                            rule.next_hops.extend(value for value in candidates if value not in rule.next_hops)
                            rule.set_next_hop = rule.next_hops[0] if rule.next_hops else None
                            rule.source_attributes["next_hops"] = candidates
                            if len(candidates) > 1 or "verify-availability" in sub.lower():
                                rule.source_attributes["next_hop_options"] = sub
                        else:
                            tokens = next_hop.group(1).split()
                            rule.next_hops.extend(value for value in tokens if value not in rule.next_hops)
                            rule.set_next_hop = rule.next_hops[0] if rule.next_hops else None
                            rule.raw_options.append(sub)
                    elif set_interface:
                        rule.output_interfaces.extend(
                            value for value in set_interface.group(1).split()
                            if value not in rule.output_interfaces
                        )
                        rule.set_interface = rule.output_interfaces[0] if rule.output_interfaces else None
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
                for acl_name in rule.match_acls:
                    self._record_acl_consumer(acl_name, "route-map", line_number, line)
                continue
            global_mtu = re.fullmatch(r"mtu\s+(\S+)\s+(\d+)", line, re.I) if not raw[:1].isspace() else None
            if global_mtu:
                pending_global_mtu.append({
                    "target": global_mtu.group(1), "value": int(global_mtu.group(2)),
                    "line_number": line_number, "raw_command": sanitize_raw_text(line),
                    "source_context": self._line_contexts.get(line_number),
                })
                i += 1
                continue
            if not raw[:1].isspace() and re.match(r"^(?:class-map|policy-map|tcp-map)\b", line, re.IGNORECASE):
                i += 1
                while i < len(lines) and lines[i][:1].isspace() and not lines[i].strip().startswith("!"):
                    i += 1
                continue
            if not raw[:1].isspace() and line.lower().startswith("service-policy"):
                i += 1
                continue
            if not raw[:1].isspace() and re.match(r"^(?:router\s+\S+|sla\s+monitor\s+\d+)\b", line, re.IGNORECASE):
                i += 1
                while i < len(lines) and lines[i][:1].isspace() and not lines[i].strip().startswith("!"):
                    i += 1
                continue
            self._record_unsupported(line_number, line, "No Cisco ASA extraction handler")
            i += 1
        self._parse_source_only_records(lines)
        handled = set()
        in_webvpn = False
        for raw in lines:
            line = raw.strip().lower()
            if line == "webvpn":
                in_webvpn = True
                handled.add(line)
            elif raw[:1].isspace() and in_webvpn:
                handled.add(line)
            else:
                in_webvpn = False
                if line.startswith(("vpn-addr-assign ", "no vpn-addr-assign ", "privilege ")):
                    handled.add(line)
        self.config.unsupported_commands = [item for item in self.config.unsupported_commands
            if not (item.get("reason") == "No Cisco ASA extraction handler" and item.get("raw_line", "").lower() in handled)]
        for command in pending_global_mtu:
            candidates = [item for item in self.config.interfaces
                          if getattr(item, "source_context", None) == command["source_context"]
                          and command["target"].casefold() in {item.name.casefold(), (item.nameif or "").casefold()}]
            if len(candidates) == 1:
                interface = candidates[0]
                if interface.mtu is not None and interface.mtu != command["value"]:
                    interface.source_attributes.setdefault("mtu_history", []).append(interface.mtu)
                interface.mtu = command["value"]
                interface.source_attributes.setdefault("global_mtu_commands", []).append(command["raw_command"])
                _mark_explicit(interface, "mtu")
                interface.source_attributes.setdefault("mtu_source_history", []).append(command)
            else:
                self._record_unsupported(command["line_number"], command["raw_command"], "Global MTU target is unresolved or ambiguous")
        return self.config

    @staticmethod
    def _build_context_ownership(lines: List[str]) -> Dict[int, Optional[str]]:
        from .parser_mpf import _build_context_ownership
        return _build_context_ownership(lines)

    def _parse_class_map_block(self, lines: List[str], index: int) -> CiscoClassMap:
        from .parser_mpf import _parse_class_map_block
        return _parse_class_map_block(self, lines, index)

    def _parse_policy_map_block(self, lines: List[str], index: int) -> CiscoPolicyMap:
        from .parser_mpf import _parse_policy_map_block
        return _parse_policy_map_block(self, lines, index)

    def _parse_mpf_action(self, section: CiscoPolicyMapClass, line: str, line_number: int) -> None:
        from .parser_mpf import _parse_mpf_action
        return _parse_mpf_action(self, section, line, line_number)

    def _parse_connection_action(self, section: Any, line: str, line_number: int) -> CiscoMPFConnectionAction:
        from .parser_mpf import _parse_connection_action
        return _parse_connection_action(self, section, line, line_number)

    def _parse_police_action(self, section: Any, line: str, line_number: int) -> CiscoMPFPoliceAction:
        from .parser_mpf import _parse_police_action
        return _parse_police_action(self, section, line, line_number)

    def _parse_tcp_map_block(self, lines: List[str], index: int) -> CiscoTCPMap:
        from .parser_mpf import _parse_tcp_map_block
        return _parse_tcp_map_block(self, lines, index)

    def _parse_service_policy_line(self, line: str, line_number: int) -> CiscoServicePolicy:
        from .parser_mpf import _parse_service_policy_line
        return _parse_service_policy_line(self, line, line_number)

    def _parse_threat_detection(self, line: str, line_number: int) -> CiscoConnectionControl:
        from .parser_mpf import _parse_threat_detection
        return _parse_threat_detection(self, line, line_number)

    def _parse_dhcpd_command(self, line: str, line_number: int) -> None:
        from .parser_mpf import _parse_dhcpd_command
        return _parse_dhcpd_command(self, line, line_number)

    def _parse_management_command(self, line: str, line_number: int) -> None:
        from .parser_mpf import _parse_management_command
        return _parse_management_command(self, line, line_number)

    def _parse_route_line(self, line: str) -> Tuple[Optional[CiscoStaticRoute], Optional[str]]:
        tokens = line.split()
        ipv6 = len(tokens) >= 2 and tokens[0].lower() == "ipv6" and tokens[1].lower() == "route"
        index = 2 if ipv6 else 1
        interface = tokens[index] if len(tokens) > index else None
        null_route = not ipv6 and interface and interface.lower() == "null0"
        required = 3
        if len(tokens) - index < required:
            return CiscoStaticRoute(interface=interface, address_family="ipv6" if ipv6 else "ipv4", raw_line=line,
                                    extraction_status="PARSE_ERROR", requires_manual_review=True,
                                    explicit_fields={"interface", "address_family"}), "Incomplete static route statement"
        if ipv6:
            destination, mask, gateway = tokens[index + 1], None, tokens[index + 2]
            index += 3
            try:
                ipaddress.IPv6Network(destination, strict=False)
                ipaddress.IPv6Address(gateway)
            except ValueError:
                return CiscoStaticRoute(
                    interface=interface, destination=destination, gateway=gateway,
                    address_family="ipv6", raw_line=line, extraction_status="PARSE_ERROR",
                    requires_manual_review=True, explicit_fields={"interface", "destination", "gateway", "address_family"},
                ), "Invalid IPv6 route prefix or next hop"
        elif null_route:
            destination, mask = tokens[index + 1:index + 3]
            gateway = None
            index += 3
        else:
            destination, mask = tokens[index + 1:index + 3]
            index += 3
            gateway = None
            if index < len(tokens):
                try:
                    ipaddress.IPv4Address(tokens[index])
                except ValueError:
                    if not tokens[index].isdigit() and tokens[index].lower() not in {"track", "tunneled"}:
                        return CiscoStaticRoute(
                            interface=interface, destination=destination, mask=mask, gateway=tokens[index],
                            address_family="ipv4", raw_line=line, extraction_status="PARSE_ERROR",
                            requires_manual_review=True,
                            explicit_fields={"interface", "destination", "mask", "gateway", "address_family"},
                        ), "Invalid IPv4 route next hop"
                else:
                    gateway = tokens[index]
                    index += 1
        route = CiscoStaticRoute(
            interface=interface, destination=destination, mask=mask, gateway=gateway,
            address_family="ipv6" if ipv6 else "ipv4", raw_line=line,
            explicit_fields={"interface", "destination", "address_family"} | ({"gateway"} if gateway is not None else set()) | (set() if ipv6 else {"mask"}),
        )
        if not ipv6 and normalize_ipv4_network(destination, mask or "") is None:
            route.extraction_status = "PARSE_ERROR"
            route.requires_manual_review = True
            return route, "Invalid IPv4 route destination/netmask"
        optional_tokens = tokens[index:]
        if not ipv6 and not null_route and gateway is None:
            route.extraction_status = "PARTIAL"
            route.requires_manual_review = True
            route.review_reasons.append("Gateway-absent route validity depends on transparent-mode context")
        while index < len(tokens):
            token = tokens[index].lower()
            if token.isdigit() and route.administrative_distance is None:
                distance = int(token)
                if not 1 <= distance <= 255:
                    route.extraction_status = "PARSE_ERROR"
                    route.requires_manual_review = True
                    route.review_reasons.append("Route administrative distance must be between 1 and 255")
                else:
                    route.administrative_distance = distance
                    _mark_explicit(route, "administrative_distance")
                index += 1
            elif token == "track" and index + 1 < len(tokens) and tokens[index + 1].isdigit():
                route.track_id = int(tokens[index + 1])
                _mark_explicit(route, "track_id")
                index += 2
            elif token == "tunneled":
                route.tunneled = True
                _mark_explicit(route, "tunneled")
                index += 1
            else:
                route.raw_options.append(tokens[index])
                route.raw_extra.setdefault("unparsed_options", []).append(sanitize_raw_text(tokens[index]))
                index += 1
        route.source_attributes.update({"source_line": line, "optional_tokens": optional_tokens})
        if route.track_id is not None:
            route.review_reasons.append("Route tracking dependency requires target review")
        if route.tunneled:
            route.review_reasons.append("ASA tunneled route semantics require target review")
        if route.raw_options:
            route.review_reasons.append(f"Unparsed route options: {' '.join(route.raw_options)}")
        if route.review_reasons and route.extraction_status != "PARSE_ERROR":
            route.extraction_status = "PARTIAL"
            route.requires_manual_review = True
        return route, None

    def _parse_nat_line(self, line: str, line_number: int, owning_object: Optional[str] = None) -> None:
        legacy = re.fullmatch(r"nat\s+\(([^,)]+)\)\s+0\s+access-list\s+(\S+)(?:\s+(.*))?", line.strip(), re.I)
        if legacy and owning_object is None:
            interface_name, acl_name, remainder = legacy.groups()
            self._nat_section_counts["manual"] = self._nat_section_counts.get("manual", 0) + 1
            extras = remainder.split() if remainder else []
            rule = CiscoNATRule(
                name=f"nat_legacy_exemption_{line_number}", source_interface=interface_name.strip(),
                section="manual", section_order=1, syntax_family="legacy-exemption", sequence=0,
                source_sequence=0, source_order=line_number,
                source_order_within_section=self._nat_section_counts["manual"], access_list=acl_name,
                identity_nat=True, nat_exemption=True, raw_line=line, raw_options=extras,
                extraction_status="SOURCE_ONLY", requires_manual_review=True,
                review_reasons=["ASA legacy NAT exemption is preserved as source-only access-list semantics"],
                source_attributes={"raw_command": sanitize_raw_text(line), "legacy_nat": True},
                explicit_fields={"source_interface", "section", "section_order", "syntax_family", "sequence", "source_sequence", "source_order", "source_order_within_section", "access_list", "identity_nat", "nat_exemption"},
                raw_extra={"unparsed_tokens": [sanitize_raw_text(token) for token in extras]} if extras else {},
            )
            self.config.nat_rules.append(self._with_source_context(rule, line_number))
            self._record_acl_consumer(acl_name, "nat-exemption", line_number, line)
            return
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
            section=section, syntax_family="object" if owning_object else "manual", sequence=sequence, source_sequence=sequence, owning_object=owning_object,
            source_order=line_number, source_order_within_section=within, section_order=section_order,
            raw_line=line,
            source_attributes={"raw_command": line},
        )
        _mark_explicit(rule, "section", "syntax_family", "source_order", "source_order_within_section", "section_order")
        if src_if is not None or match.group(1) is not None:
            _mark_explicit(rule, "source_interface", "destination_interface")
        if sequence is not None:
            _mark_explicit(rule, "sequence", "source_sequence")
        index = 0

        def parse_mapped_source(position: int) -> int:
            if position >= len(tail):
                return position
            token = tail[position]
            lower = token.lower()
            if lower == "interface":
                rule.mapped_source_mode = "interface"
                rule.mapped_source = "interface"
                _mark_explicit(rule, "mapped_source_mode", "mapped_source")
                position += 1
                if position < len(tail) and tail[position].lower() == "ipv6":
                    rule.mapped_source_address_family = "ipv6"
                    _mark_explicit(rule, "mapped_source_address_family")
                    position += 1
                return position
            if lower == "pat-pool":
                rule.mapped_source_mode = "pat_pool"
                _mark_explicit(rule, "mapped_source_mode", "pat_pool", "mapped_source")
                if position + 1 < len(tail):
                    rule.pat_pool = tail[position + 1]
                    rule.mapped_source = rule.pat_pool
                    position += 2
                    while position < len(tail) and tail[position].lower() in {
                        "round-robin", "extended", "flat", "include-reserve", "block-allocation"
                    }:
                        rule.pat_pool_options.append(tail[position])
                        _mark_explicit(rule, "pat_pool_options")
                        position += 1
                return position
            rule.mapped_source_mode = rule.source_mode
            rule.mapped_source = token
            _mark_explicit(rule, "mapped_source_mode", "mapped_source")
            return position + 1

        if owning_object:
            if index < len(tail) and tail[index].lower() in {"static", "dynamic"}:
                rule.source_mode = tail[index].lower()
                rule.real_source = owning_object
                _mark_explicit(rule, "source_mode", "real_source", "owning_object")
                index = parse_mapped_source(index + 1)
            else:
                rule.review_reasons.append("Object NAT is missing static/dynamic translation mode")
        elif index < len(tail) and tail[index].lower() == "source":
            if index + 2 < len(tail):
                rule.source_mode = tail[index + 1].lower()
                rule.real_source = tail[index + 2]
                _mark_explicit(rule, "source_mode", "real_source")
                if rule.source_mode not in {"static", "dynamic"}:
                    rule.extraction_status = "PARSE_ERROR"
                    rule.review_reasons.append(f"Unsupported twice-NAT source mode: {rule.source_mode}")
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
                _mark_explicit(rule, "destination_mode", "mapped_destination", "real_destination")
                if rule.destination_mode != "static":
                    rule.extraction_status = "PARSE_ERROR"
                    rule.review_reasons.append(f"Unsupported twice-NAT destination mode: {rule.destination_mode}")
                index += 4
            else:
                rule.review_reasons.append("Incomplete NAT destination clause")
                index = len(tail)

        if index < len(tail) and tail[index].lower() == "service":
            if owning_object and index + 3 < len(tail):
                rule.service_protocol = tail[index + 1].lower()
                rule.original_service = tail[index + 2]
                rule.translated_service = tail[index + 3]
                _mark_explicit(rule, "service_protocol", "original_service", "translated_service")
                index += 4
            elif not owning_object and index + 2 < len(tail):
                rule.service_operand_1, rule.service_operand_2 = tail[index + 1:index + 3]
                _mark_explicit(rule, "service_operand_1", "service_operand_2")
                index += 3
            else:
                tokens = tail[index:]
                rule.raw_options.extend(tokens)
                rule.raw_extra.setdefault("unparsed_tokens", []).extend(sanitize_raw_text(token) for token in tokens)
                rule.extraction_status = "PARSE_ERROR"
                rule.requires_manual_review = True
                rule.review_reasons.append("NAT service clause does not match object NAT or twice NAT grammar")
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
                _mark_explicit(rule, "description")
                index = len(tail)
            elif lower in option_names:
                rule.options.append(lower)
                _mark_explicit(rule, "options")
                option_field = {"dns": "dns", "no-proxy-arp": "no_proxy_arp", "route-lookup": "route_lookup",
                                "unidirectional": "unidirectional", "inactive": "inactive", "net-to-net": "net_to_net"}.get(lower)
                if option_field:
                    _mark_explicit(rule, option_field)
                elif lower in {"round-robin", "extended", "flat", "include-reserve", "block-allocation"}:
                    _mark_explicit(rule, "pat_pool_options")
                if lower in {"round-robin", "extended", "flat", "include-reserve", "block-allocation"}:
                    rule.pat_pool_options.append(lower)
                    _mark_explicit(rule, "pat_pool_options")
                index += 1
            else:
                rule.raw_options.append(token)
                rule.raw_extra.setdefault("unparsed_tokens", []).append(sanitize_raw_text(token))
                index += 1

        rule.dns = "dns" in rule.options
        rule.no_proxy_arp = "no-proxy-arp" in rule.options
        rule.route_lookup = "route-lookup" in rule.options
        rule.unidirectional = "unidirectional" in rule.options
        rule.inactive = "inactive" in rule.options
        rule.net_to_net = "net-to-net" in rule.options

        if not owning_object:
            for field in ("real_source", "mapped_source", "mapped_destination", "real_destination"):
                value = getattr(rule, field)
                if not value or value.lower() in {"any", "interface", "original", "translated"}:
                    continue
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
                rule.extraction_status = "PARSE_ERROR"
                rule.requires_manual_review = True
                rule.review_reasons.append(f"Inline IP address is not supported for manual NAT operand {field}")
                rule.raw_extra.setdefault("unsupported_inline_addresses", []).append(value)
                break

        if sequence == 0 and len(tail) >= 2 and tail[0].lower() == "access-list":
            rule.access_list = tail[1]
            rule.identity_nat = rule.nat_exemption = True
            _mark_explicit(rule, "access_list", "identity_nat", "nat_exemption")
            rule.syntax_family = "legacy-exemption"
            rule.extraction_status = "SOURCE_ONLY"
            rule.requires_manual_review = True
            rule.review_reasons.append("ASA NAT exemption is preserved as source-only access-list semantics")
        elif rule.source_mode == "static" and rule.real_source == rule.mapped_source:
            rule.identity_nat = True
        elif not rule.real_source or not rule.mapped_source:
            rule.extraction_status = "PARSE_ERROR"
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
        if partial_details and rule.extraction_status != "PARSE_ERROR":
            rule.extraction_status = "PARTIAL"
            rule.requires_manual_review = True
            rule.review_reasons.extend(partial_details)
        if rule.nat_exemption:
            rule.extraction_status = "SOURCE_ONLY"
        if rule.extraction_status == "PARSE_ERROR":
            self._record_diagnostic(line_number, line, "; ".join(rule.review_reasons), "nat", owning_object)
        self.config.nat_rules.append(self._with_source_context(rule, line_number))
        if rule.access_list:
            self._record_acl_consumer(rule.access_list, "nat-exemption", line_number, line)

    @staticmethod
    def _validate_time_range_clock(value: str) -> bool:
        return bool(re.fullmatch(r"(?:\d|[01]\d|2[0-3]):[0-5]\d", value))

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
        if not parts or parts[0].lower() != "absolute":
            return clause, "Malformed absolute time-range clause"
        months = {name.lower(): number for number, name in enumerate(
            ("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"), 1
        )}
        def timestamp(tokens: List[str]) -> Optional[str]:
            if len(tokens) != 4 or not cls._validate_time_range_clock(tokens[0]): return None
            if not tokens[1].isdigit() or tokens[2].lower() not in months or not tokens[3].isdigit(): return None
            year = int(tokens[3])
            if not 1993 <= year <= 2035: return None
            try: date(year, months[tokens[2].lower()], int(tokens[1]))
            except ValueError: return None
            return " ".join(tokens)
        index, seen = 1, set()
        while index < len(parts):
            key = parts[index].lower()
            if key not in {"start", "end"} or key in seen: return clause, "Malformed absolute time-range clause"
            value = timestamp(parts[index + 1:index + 5])
            if value is None: return clause, f"Malformed absolute {key} value"
            setattr(clause, key, value)
            seen.add(key); index += 5
        return clause, None

    @classmethod
    def _parse_time_range_periodic_clause(cls, raw: str, source_order: int) -> Tuple[CiscoTimeRangeClause, Optional[str]]:
        parts = raw.split()
        clause = CiscoTimeRangeClause(clause_type="periodic", raw=raw, source_order=source_order)
        if len(parts) < 5 or parts[0].lower() != "periodic":
            return clause, "Malformed periodic time-range clause"
        to_positions = [index for index, value in enumerate(parts) if value.lower() == "to"]
        to_index = to_positions[0] if len(to_positions) == 1 else -1
        if to_index < 3 or to_index == len(parts) - 1:
            return clause, "Malformed periodic time-range clause"
        start_days = cls._normalize_time_range_days(parts[1:to_index - 1])
        end_tokens = parts[to_index + 1:-1]
        end_days = cls._normalize_time_range_days(end_tokens) if end_tokens else []
        if start_days is None or end_days is None:
            return clause, "Invalid periodic day selector"
        if not cls._validate_time_range_clock(parts[to_index - 1]) or not cls._validate_time_range_clock(parts[-1]):
            return clause, "Invalid periodic clock value"
        if end_days and (len(start_days) != 1 or len(end_days) != 1):
            return clause, "Invalid periodic day range"
        clause.days, clause.end_days = start_days, end_days
        clause.start, clause.end = parts[to_index - 1], parts[-1]
        return clause, None


