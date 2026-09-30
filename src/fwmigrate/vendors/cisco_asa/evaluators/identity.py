"""ASA identity command evaluation."""

from __future__ import annotations

import re
from typing import List, Optional
from fwmigrate.vendors.cisco_asa.model.identity import CiscoAAAAccountingRule, CiscoAAAAuthenticationRule, CiscoAAAAuthorizationRule, CiscoAAARecord, CiscoAAAServerGroup, CiscoAAAServerHost, CiscoLocalUser
from fwmigrate.extraction.sanitize import sanitize_raw_text
from . import _mark_explicit


class IdentityEvaluator:

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
