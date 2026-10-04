"""ASA vpn command evaluation."""

from __future__ import annotations

import ipaddress
import re
import shlex
from typing import List

from fwmigrate.vendors.cisco_asa.model.identity import CiscoCommandPrivilege

from fwmigrate.vendors.cisco_asa.model.vpn import CiscoTrustpointRecord, CiscoCryptoMap, CiscoGroupPolicy, CiscoIKEPolicy, CiscoIKEv2Proposal, CiscoIPsecProfile, CiscoIPsecTransformSet, CiscoTunnelGroup, CiscoVPNAddressAssignment, CiscoVPNAddressPool, CiscoWebVPNConfig
from fwmigrate.extraction.sanitize import sanitize_raw_text
from . import _mark_explicit


class VPNEvaluator:

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
                _mark_explicit(record, "map_name", "source_order")
                self.config.crypto_maps.append(self._with_source_context(record, line_number))
            record.interface_attachment = interface
            _mark_explicit(record, "interface_attachment")
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
            _mark_explicit(record, "map_name", "sequence", "is_dynamic", "map_type", "source_order")
            self.config.crypto_maps.append(self._with_source_context(record, line_number))
        safe_line = sanitize_raw_text(line)
        record.raw_lines.append(safe_line)
        tokens = parts[offset + 2:]
        lowered = [token.lower() for token in tokens]
        if len(tokens) >= 3 and lowered[:2] == ["match", "address"]:
            record.acl_name = tokens[2]
            _mark_explicit(record, "acl_name")
        elif lowered[:2] == ["set", "peer"] and len(tokens) >= 3:
            self._append_unique(record.peers, [tokens[2]])
            record.peer = tokens[2]
            _mark_explicit(record, "peers", "peer")
        elif lowered[:2] == ["set", "transform-set"]:
            self._append_unique(record.transform_sets, tokens[2:])
            _mark_explicit(record, "transform_sets")
        elif lowered[:2] == ["set", "ikev2"] and len(tokens) >= 4 and lowered[2] in {"ipsec-proposal", "ipsec-proposals"}:
            self._append_unique(record.ikev2_proposals, tokens[3:])
            _mark_explicit(record, "ikev2_proposals")
        elif lowered[:2] == ["set", "pfs"] and len(tokens) >= 3:
            record.pfs_group = tokens[2] if tokens[2].lower() != "none" else None
            _mark_explicit(record, "pfs_group")
        elif lowered[:3] == ["set", "security-association", "lifetime"]:
            if len(tokens) >= 5 and lowered[3] in {"seconds", "kilobytes"} and tokens[4].isdigit():
                field_name = f"security_association_lifetime_{lowered[3]}"
                setattr(record, field_name, int(tokens[4]))
                _mark_explicit(record, field_name)
            else:
                record.raw_options.append(safe_line)
                record.extraction_status = "PARSE_ERROR"
                record.requires_manual_review = True
        elif lowered[:2] == ["set", "connection-type"] and len(tokens) >= 3:
            record.raw_options.append(safe_line)
        elif lowered[:1] == ["interface"] and len(tokens) >= 2:
            record.interface_attachment = tokens[1]
            _mark_explicit(record, "interface_attachment")
        else:
            lowered = [token.lower() for token in tokens]
            if "dynamic" in lowered and lowered.index("dynamic") + 1 < len(tokens):
                record.dynamic_map = tokens[lowered.index("dynamic") + 1]
                _mark_explicit(record, "dynamic_map")
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
                _mark_explicit(record, target)
                list_target = {
                    "encryption": record.encryption_algorithms,
                    "hash": record.hash_algorithms,
                    "integrity": record.integrity_algorithms,
                    "prf": record.prf_algorithms,
                }.get(key)
                if list_target is not None:
                    self._append_unique(list_target, values)
                    _mark_explicit(record, {
                        "encryption": "encryption_algorithms",
                        "hash": "hash_algorithms",
                        "integrity": "integrity_algorithms",
                        "prf": "prf_algorithms",
                    }[key])
            elif key == "group":
                record.dh_group = value
                self._append_unique(record.dh_groups, values)
                _mark_explicit(record, "dh_group", "dh_groups")
            elif key == "lifetime" and len(parts) == 2 and parts[1].isdigit():
                record.lifetime_seconds = int(parts[1])
                _mark_explicit(record, "lifetime_seconds")
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
            elif (re.match(r"^track\s+\d+\s+", lower) or re.match(r"^sla\s+monitor\s+\d+\b", lower)
                  or re.match(r"^router\s+\S+", lower)):
                self._parse_routing_source_only(line, index, children)
            elif re.match(r"^crypto\s+ikev[12]\s+policy\s+\d+", lower):
                match = re.match(r"^crypto\s+(ikev[12])\s+policy\s+(\d+)", line, re.IGNORECASE)
                self.config.ike_policies.append(self._with_source_context(CiscoIKEPolicy(
                    name=f"{match.group(1)}:{match.group(2)}", version=match.group(1),
                    number=int(match.group(2)), raw_lines=[line, *children],
                    explicit_fields={"version", "number"},
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
                            _mark_explicit(record, {
                                "encryption": "encryption_algorithms",
                                "integrity": "integrity_algorithms",
                                "prf": "prf_algorithms",
                            }[parts[pos].lower()])
                        if positions:
                            continue
                    if parts and parts[0].lower() == "group" and len(parts) > 1:
                        self._append_unique(record.dh_groups, parts[1:])
                        _mark_explicit(record, "dh_groups")
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
                    raw_lines=[sanitize_raw_text(line)],
                    explicit_fields=({"encryption"} if values else set()) | ({"authentication"} if len(values) > 1 else set()),
                    source_attributes={"raw_command": line}), index + 1))
                record = self.config.ipsec_transform_sets[-1]
                for child in children:
                    if child.lower().startswith("mode "):
                        record.mode = child.split(maxsplit=1)[1]
                        _mark_explicit(record, "mode")
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
                    _mark_explicit(record, "start", "end")
                    if len(parts) == 7 and parts[5].lower() == "mask":
                        record.mask = parts[6]
                        _mark_explicit(record, "mask")
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
                    _mark_explicit(record, "group_type")
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
                        _mark_explicit(record, "ikev1_psk_present")
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
                        _mark_explicit(record, "trustpoint")
                    elif child_parts and child_parts[0].lower() in {"ikev1", "ikev2"} and len(child_parts) > 2:
                        setattr(record, f"{child_parts[0].lower()}_{child_parts[1].lower().replace('-', '_')}", " ".join(child_parts[2:]))
                    elif child_parts and child_parts[0].lower() in {"authentication", "ikev1-authentication", "ikev2-authentication"}:
                        record.authentication_method = " ".join(child_parts[1:])
                        _mark_explicit(record, "authentication_method")
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
                    _mark_explicit(record, "policy_type")
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
                    elif key == "vpn-tunnel-protocol": self._append_unique(record.vpn_protocols, values); _mark_explicit(record, "vpn_protocols")
                    elif key == "vpn-idle-timeout": record.idle_timeout = " ".join(values); _mark_explicit(record, "idle_timeout")
                    elif key == "vpn-session-timeout": record.session_timeout = " ".join(values); _mark_explicit(record, "session_timeout")
                    elif key == "default-domain": record.default_domain = " ".join(values); _mark_explicit(record, "default_domain")
                    elif key == "vpn-access-hours": record.vpn_access_hours = values[-1]; _mark_explicit(record, "vpn_access_hours")
                    elif key == "vpn-filter":
                        record.vpn_filter_acl = values[-1]
                        _mark_explicit(record, "vpn_filter_acl")
                    elif key == "vpn-simultaneous-logins" and values and values[-1].isdigit():
                        record.vpn_simultaneous_logins = int(values[-1])
                        _mark_explicit(record, "vpn_simultaneous_logins")
                    elif key == "wins-server":
                        self._append_unique(record.wins_servers, values[1:] if values[0].lower() == "value" else values)
                        _mark_explicit(record, "wins_servers")
                    elif key == "group-policy": record.parent = values[-1]; _mark_explicit(record, "parent")
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

    def _parse_trustpoint_block(self, lines, i):
        from ..parser_mpf import _parse_trustpoint_block
        return _parse_trustpoint_block(self, lines, i)

    def _parse_certificate_chain(self, lines, i, line, line_number, certificate):
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
        return i
