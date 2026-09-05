"""Handler for Junos system and version configuration hierarchy."""

from __future__ import annotations

from typing import Sequence

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import (
    sanitize_source_attributes,
    sanitize_tokens,
)
from fwmigrate.parsers.juniper_srx.model import (
    JuniperAdminUser,
    JuniperLoginClass,
    JuniperNTPServer,
    JuniperSRXConfig,
    JuniperSourceHierarchyItem,
)
from fwmigrate.parsers.juniper_srx.provenance import record_scalar_candidate, record_list_candidate
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_system_command(cmd: JunosCommand, config: JuniperSRXConfig) -> bool:
    """
    Handle 'set version ...' and 'set system ...' hierarchy commands.
    Returns True if handled.
    """
    toks = cmd.tokens
    if len(toks) < 2:
        return False

    first = toks[1].lower()

    if first == "version":
        if len(toks) >= 3:
            config.version = toks[2]
            cmd.consumed = True
            cmd.handler = "system"
            cmd.extraction_status = ExtractionStatus.NORMALIZED
            return True

    if first == "system":
        if len(toks) >= 4 and toks[2].lower() == "services" and toks[3].lower() == "rpm":
            return False
        cmd.consumed = True
        cmd.handler = "system"

        if len(toks) >= 3:
            sub = toks[2].lower()
            if sub == "authentication-order" and len(toks) >= 4:
                config.authentication_order.extend(extract_value_list(toks[3:]))
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            if sub in {"login", "radius-server", "tacplus-server"} and len(toks) >= 4:
                is_login = sub == "login" and toks[3].lower() in {"class", "user"}
                if sub == "login" and toks[3].lower() == "class" and len(toks) >= 5:
                    name, store = toks[4], config.login_classes
                    item = store.setdefault(name, JuniperLoginClass(name=name))
                elif sub == "login" and toks[3].lower() == "user" and len(toks) >= 5:
                    name, store = toks[4], config.admin_users
                    item = store.setdefault(name, JuniperAdminUser(name=name))
                    config.local_users[name] = item
                    if len(toks) >= 7 and toks[5].lower() == "class":
                        item.login_class = toks[6]
                        if len(toks) == 7:
                            cmd.extraction_status = ExtractionStatus.NORMALIZED
                            return True
                if is_login and toks[3].lower() == "class" and len(toks) >= 7 and toks[5].lower() == "permissions":
                    item.settings["permissions"] = extract_value_list(toks[6:])
                    cmd.extraction_status = ExtractionStatus.NORMALIZED
                    return True
                elif not is_login:
                    name = toks[3]
                    store = config.radius_servers if sub == "radius-server" else config.tacplus_servers
                    item = store.setdefault(name, JuniperSourceHierarchyItem(name=name))
                key = "_".join(sanitize_tokens(toks[3 if sub == "login" else 4:]))
                item.settings[key] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
                cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
                return True
            if sub == "host-name" and len(toks) >= 4:
                config.hostname = toks[3]
                record_scalar_candidate(config.field_provenance, config.field_candidate_history, "hostname", config.hostname, cmd)
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            elif sub == "time-zone" and len(toks) >= 4:
                config.time_zone = toks[3]
                record_scalar_candidate(config.field_provenance, config.field_candidate_history, "timezone", config.time_zone, cmd)
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            elif sub == "name-server" and len(toks) >= 4:
                values = extract_value_list(toks[3:])
                server = values[0]
                routing_instance = values[2] if len(values) >= 3 and values[1].lower() == "routing-instance" else None
                if not any(ns.server == server and ns.routing_instance == routing_instance for ns in config.name_servers):
                    from fwmigrate.parsers.juniper_srx.model import JuniperDNSNameServer
                    config.name_servers.append(JuniperDNSNameServer(server=server, routing_instance=routing_instance))
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            elif sub == "domain-name" and len(toks) >= 4:
                config.domain_name = toks[3]
                record_scalar_candidate(config.field_provenance, config.field_candidate_history, "domain_name", config.domain_name, cmd)
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            elif sub == "domain-search" and len(toks) >= 4:
                for value in extract_value_list(toks[3:]):
                    if value not in config.domain_search:
                        config.domain_search.append(value)
                    record_list_candidate(config.field_candidate_history, "domain_search", value, cmd)
                cmd.extraction_status = ExtractionStatus.NORMALIZED
                return True
            elif sub == "ntp" and len(toks) >= 4:
                return _handle_ntp(toks[3:], config, cmd)
            elif sub == "services" and len(toks) >= 4:
                return _handle_services(toks[3:], config, cmd)
            elif sub == "syslog" and len(toks) >= 4:
                return _handle_syslog(toks[3:], config, cmd)

        # Other system attributes (e.g. login, ntp, syslog) -> EXTRACT_ONLY
        root_ctx = config.get_context("root")
        safe_toks = sanitize_tokens(toks)
        key = " ".join(safe_toks[2:]) if len(safe_toks) > 2 else "system"
        root_ctx.source_attributes[f"system_{key.replace(' ', '_')}"] = sanitize_source_attributes(
            {"raw": cmd.raw_sanitized}
        )
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True

    return False


def _handle_ntp(toks: list[str], config: JuniperSRXConfig, cmd: JunosCommand) -> bool:
    kind = toks[0].lower()
    ntp = config.ntp
    if kind in {"server", "peer"} and len(toks) >= 2:
        address = toks[1]
        values = toks[2:]
        routing_instance = next((values[i + 1] for i, value in enumerate(values[:-1])
                                 if value.lower() == "routing-instance"), None)
        preferred = "prefer" in {v.lower() for v in values}
        key = next((values[i + 1] for i, v in enumerate(values[:-1]) if v.lower() in {"key", "authentication-key"}), None)
        ntp.servers.append(JuniperNTPServer(address=address, role=kind, preferred=preferred,
                                             routing_instance=routing_instance,
                                             authentication_key_reference=key))
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    if kind in {"source-address", "source-interface", "routing-instance"} and len(toks) >= 2:
        setattr(ntp, kind.replace("-", "_"), toks[1])
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    if kind == "authentication-key" and len(toks) >= 2:
        ntp.authentication_keys.append(toks[1])
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True
    return _store_system_extract(ntp.source_attributes, toks, cmd)


def _handle_services(toks: list[str], config: JuniperSRXConfig, cmd: JunosCommand) -> bool:
    service = toks[0].lower()
    if service == "ssh":
        config.ssh.enabled = True
        target = config.ssh
        toks = toks[1:]
    elif service == "netconf" and len(toks) >= 2 and toks[1].lower() == "ssh":
        config.netconf.enabled = True
        target = config.netconf
        toks = toks[2:]
    elif service == "web-management":
        return _handle_web(toks[1:], config, cmd)
    elif service == "dhcp-service":
        config.services.setdefault(service, {})["_".join(sanitize_tokens(toks[1:])) or "configured"] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True
    else:
        return _store_system_extract(config.get_context("root").source_attributes, toks, cmd)
    if toks:
        target.options["_".join(sanitize_tokens(toks))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.extraction_status = ExtractionStatus.NORMALIZED
    return True


def _handle_web(toks: list[str], config: JuniperSRXConfig, cmd: JunosCommand) -> bool:
    web = config.web_management
    if not toks:
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
        return True
    kind = toks[0].lower()
    target = web.http_options if kind == "http" else web.https_options if kind == "https" else web.source_attributes
    if kind == "http": web.http_enabled = True
    elif kind == "https": web.https_enabled = True
    if len(toks) >= 3 and toks[1].lower() == "interface" and toks[2] not in web.interfaces:
        web.interfaces.append(toks[2])
    if len(toks) >= 2 and toks[1].lower() in {"certificate", "local-certificate", "system-generated-certificate"}:
        web.certificate_references.append(toks[-1])
    target["_".join(sanitize_tokens(toks[1:])) or "enabled"] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True


def _handle_syslog(toks: list[str], config: JuniperSRXConfig, cmd: JunosCommand) -> bool:
    log = config.syslog
    kind = toks[0].lower()
    if kind in {"host", "host-name"} and len(toks) >= 2:
        log.destinations.setdefault(toks[1], {})["_".join(sanitize_tokens(toks[2:])) or "configured"] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    elif kind == "file" and len(toks) >= 2:
        log.files.setdefault(toks[1], {})["_".join(sanitize_tokens(toks[2:])) or "configured"] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    elif kind in {"source-address", "source-interface", "routing-instance"} and len(toks) >= 2:
        setattr(log, kind.replace("-", "_"), toks[1])
    else:
        log.source_attributes["_".join(sanitize_tokens(toks))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True


def _store_system_extract(target: dict, toks: list[str], cmd: JunosCommand) -> bool:
    target["_".join(sanitize_tokens(toks))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
