from __future__ import annotations

import ipaddress
import re

from datetime import date
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fwmigrate.vendors.cisco_asa.acl_parser import parse_acl_binding, parse_acl_line
from fwmigrate.vendors.cisco_asa.model.acl import CiscoACLRemark
from fwmigrate.vendors.cisco_asa.model.address import CiscoNetworkGroup, CiscoNetworkGroupMember, CiscoNetworkObject

from fwmigrate.vendors.cisco_asa.model.context import CiscoMultiContextSystem
from fwmigrate.vendors.cisco_asa.model.dhcp import CiscoDHCPRelay, CiscoDHCPRelayServer, CiscoDHCPServer
from fwmigrate.vendors.cisco_asa.model.diagnostics import CiscoDiagnostic
from fwmigrate.vendors.cisco_asa.model.failover import CiscoFailoverConfig, CiscoFailoverGroup, CiscoFailoverInterfaceIP, CiscoFailoverMACAddress, CiscoFailoverSetting
from fwmigrate.vendors.cisco_asa.model.groups import CiscoNamedGroup, CiscoNamedGroupMember


from fwmigrate.vendors.cisco_asa.model.management import CiscoConnectionControl, CiscoDNSServerGroup, CiscoDNSSettings, CiscoHTTPServerConfig, CiscoSystemSettings
from fwmigrate.vendors.cisco_asa.model.mpf import CiscoClassMap, CiscoMPFConnectionAction, CiscoMPFPoliceAction, CiscoPolicyMap, CiscoPolicyMapClass, CiscoServicePolicy, CiscoTCPMap


from fwmigrate.vendors.cisco_asa.model.schedule import CiscoTimeRange, CiscoTimeRangeClause
from fwmigrate.vendors.cisco_asa.model.service import CiscoNetworkServiceObject, CiscoServiceGroup, CiscoServiceGroupMember, CiscoServiceObject
from fwmigrate.vendors.cisco_asa.model.source import CiscoASAConfig

from fwmigrate.vendors.cisco_asa.model.zone import CiscoTrafficZone
from fwmigrate.vendors.cisco_asa.net_utils import normalize_ipv4_network
from fwmigrate.vendors.cisco_asa.service_parser import parse_service_clause
from fwmigrate.extraction.sanitize import sanitize_raw_text
from .evaluators import _mark_explicit
from .evaluators.management import ManagementEvaluator
from .evaluators.routing import RoutingEvaluator
from .evaluators.nat import NATEvaluator
from .evaluators.identity import IdentityEvaluator
from .evaluators.vpn import VPNEvaluator
from .evaluators.contexts import ContextsEvaluator
from .evaluators.interfaces import InterfaceEvaluator, _parse_interface_header


class CiscoASAParser(InterfaceEvaluator, ManagementEvaluator, RoutingEvaluator, NATEvaluator, IdentityEvaluator, VPNEvaluator, ContextsEvaluator):
    """Deterministic offline parser for Cisco ASA running configuration."""

    def __init__(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        self.raw_lines = content.splitlines()
        self.zone_mapping = zone_mapping or {}
        self.config = CiscoASAConfig()
        self._nat_section_counts: Dict[str, int] = {}
        self._line_contexts: Dict[int, Optional[str]] = {}

    def _ensure_dns_settings(self) -> CiscoDNSSettings:
        if self.config.dns_settings is None:
            self.config.dns_settings = CiscoDNSSettings(name="system-dns")
        return self.config.dns_settings

    def _ensure_system_settings(self) -> CiscoSystemSettings:
        if self.config.system_settings is None:
            self.config.system_settings = CiscoSystemSettings(name="system")
        return self.config.system_settings

    def _ensure_failover_config(self) -> CiscoFailoverConfig:
        if self.config.failover_config is None:
            self.config.failover_config = CiscoFailoverConfig(name="failover")
        return self.config.failover_config

    def _ensure_http_server(self) -> CiscoHTTPServerConfig:
        if self.config.http_server is None:
            self.config.http_server = CiscoHTTPServerConfig()
        return self.config.http_server

    def _ensure_multi_context_system(self) -> CiscoMultiContextSystem:
        if self.config.multi_context_system is None:
            self.config.multi_context_system = CiscoMultiContextSystem()
        return self.config.multi_context_system


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
            {
                "line_number": line_number,
                "raw_line": sanitize_raw_text(line),
                "reason": reason,
                "source_context": self._line_contexts.get(line_number),
            }
        )

    def _record_diagnostic(
        self, line_number: int, line: str, reason: str, section: str,
        object_name: Optional[str] = None, extraction_effect: str = "PARSE_ERROR",
    ) -> None:
        diagnostic = CiscoDiagnostic(
            line_number=line_number, section=section, object_name=object_name,
            source_context=self._line_contexts.get(line_number),
            raw_line=sanitize_raw_text(line), reason=reason, extraction_effect=extraction_effect,
            severity="error" if extraction_effect == "PARSE_ERROR" else "warning",
        )
        self.config.diagnostics.append(diagnostic)
        if extraction_effect == "PARSE_ERROR":
            self.config.parse_errors.append(diagnostic.model_dump())





    def _parse_failover_command(self, line: str, line_number: int, children: Optional[List[str]] = None) -> None:
        parts = line.split(); lower = line.lower(); cfg = self._ensure_failover_config()
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
                system = self._ensure_multi_context_system()
                system.admin_context_name = admin_match.group(1)
                system.raw_lines.append(sanitize_raw_text(line))
                i += 1
                continue
            if re.fullmatch(r"no\s+admin-context(?:\s+\S+)?", line, re.I):
                system = self._ensure_multi_context_system()
                system.admin_context_name = None
                system.raw_lines.append(sanitize_raw_text(line))
                i += 1
                continue
            if not line or line.startswith((":", "!")):
                i += 1
                continue
            if line.lower().startswith("hostname "):
                self._parse_hostname_line(line)
                i += 1
                continue

            # no is stateful Cisco syntax, not a textual inverse. Only forms
            # with an unambiguous final-state meaning are applied here.
            if line.lower().startswith("no "):
                if line.lower().startswith("no vpn-addr-assign "):
                    # Parsed in the source-only VPN pass below. Do not also
                    # classify a supported explicit negation as unsupported.
                    i += 1
                    continue
                if line.lower() == "no sysopt connection permit-vpn":
                    self._parse_sysopt_permit_vpn(line, line_number, False)
                    i += 1
                    continue
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
                    self._parse_no_http_server(line, line_number)
                    i += 1
                    continue
                if line.lower().startswith((
                    "no ntp authenticate",
                    "no ntp trusted-key ",
                    "no ntp authentication-key ",
                )):
                    self._parse_management_command(line, line_number)
                    i += 1
                    continue
                if line.lower() == "no monitor-interface" or line.lower().startswith("no monitor-interface "):
                    parts = line.split()
                    name = parts[2] if len(parts) > 2 else ""
                    if name:
                        self._ensure_failover_config().interface_monitoring[name] = False
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

            if line.lower() == "sysopt connection permit-vpn":
                self._parse_sysopt_permit_vpn(line, line_number, True)
                i += 1
                continue

            dns_group = re.match(r"^dns\s+server-group\s+(\S+)", line, re.IGNORECASE)
            if dns_group:
                i = self._parse_dns_server_group(lines, i, line_number, line, dns_group)
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
            if lower.startswith(("clock timezone ", "ntp ", "ssh ", "http ", "telnet ",
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
                self._parse_dns_group_selection(line)
                i += 1
                continue
            if re.match(r"^crypto\s+ca\s+trustpoint\s+\S+", line, re.I):
                i = self._parse_trustpoint_block(lines, i)
                continue
            certificate = re.fullmatch(r"crypto\s+ca\s+certificate\s+chain\s+(\S+)", line, re.I)
            if certificate:
                i = self._parse_certificate_chain(lines, i, line, line_number, certificate)
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
                    failover = self._ensure_failover_config()
                    failover.interface_monitoring[name] = enabled
                    failover.raw_lines.append(sanitize_raw_text(line))
                    failover.source_attributes.setdefault("raw_commands", []).append(sanitize_raw_text(line))
                i += 1
                continue
            if lower.startswith(("dhcpd ", "dhcprelay ", "dns ", "timezone ",
                                 "context ", "admin-context ", "admin-context",
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
                        dns_settings = self._ensure_dns_settings()
                        dns_settings.lookup_interfaces.append(parts[2])
                        dns_settings.raw_lines.append(line)
                        dns_settings.source_attributes.setdefault("raw_commands", []).append(line)
                        i += 1
                        continue
                    group = parts[1] if len(parts) > 1 else "default"
                    record = next((item for item in self.config.dns_server_groups if item.name == group), None)
                    if record is None:
                        record = CiscoDNSServerGroup(name=group, raw_lines=[], source_attributes={"raw_commands": []})
                        self.config.dns_server_groups.append(record)
                    record.raw_lines.append(line)
                    record.source_attributes.setdefault("raw_commands", []).append(line)
                elif lower.startswith("context ") or lower == "admin-context" or lower in {"allocate-interface", "config-url", "resource-class"} or lower.startswith(("allocate-interface ", "config-url ", "admin-context ", "resource-class ")):
                    self._parse_context_command(line, line_number)
                else:
                    self.config.connection_controls.append(CiscoConnectionControl(name=line.split()[0], setting=line.split()[0], values=line.split()[1:], raw_lines=[line], source_attributes=attrs))
                i += 1
                continue

            header = _parse_interface_header(line)
            if header:
                i = self._parse_interface_block(header, lines, i, line_number, line)
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
                i = self._parse_route_map_block(lines, i, line_number, line, route_map_match)
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
        handled_line_numbers = set()
        in_webvpn = False
        for handled_line_number, raw in enumerate(lines, start=1):
            line = raw.strip().lower()
            if line == "webvpn":
                in_webvpn = True
                handled_line_numbers.add(handled_line_number)
            elif raw[:1].isspace() and in_webvpn:
                handled_line_numbers.add(handled_line_number)
            else:
                in_webvpn = False
                if line.startswith(("vpn-addr-assign ", "no vpn-addr-assign ", "privilege ")):
                    handled_line_numbers.add(handled_line_number)
        self.config.unsupported_commands = [item for item in self.config.unsupported_commands
            if not (item.get("reason") == "No Cisco ASA extraction handler"
                    and item.get("line_number") in handled_line_numbers)]
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


