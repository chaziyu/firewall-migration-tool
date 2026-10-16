"""Check Point Management API and optional Gaia SSH collection."""

import json
import re
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version

from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes
from fwmigrate.vendors.checkpoint.models import (
    CheckPointExportBundle, CheckPointResponse, CollectionCompletenessRecord,
    CollectionStatus as CPStatus, collection_status_is_success,
)
from fwmigrate.vendors.checkpoint.r81_commands import R81_COMMAND_REGISTRY
from fwmigrate.vendors.checkpoint.loader import validate_pagination

from .contracts import CollectedSource, CollectionError, CollectionPart, CollectionStatus, validate_connection


_GAIA_EVIDENCE_COMMANDS = (
    ("gaia/show-route-static-all", "show route static all"),
    ("gaia/show-ipv6-route-static-all", "show ipv6 route static all"),
    ("gaia/show-dhcp-server-all", "show dhcp server all"),
    ("gaia/show-dhcp-server-status", "show dhcp server status"),
    ("gaia/show-dhcp-server-subnets", "show dhcp server subnets"),
    ("gaia/show-users", "show users"),
    ("gaia/show-rba-all", "show rba all"),
    ("gaia/show-rba-roles", "show rba roles"),
    ("gaia/show-rba-users", "show rba users"),
    ("gaia/show-vpn-tunnels", "show vpn tunnels"),
)


class CheckPointCollector:
    vendor_id = "checkpoint"
    method = "management-api"
    fields = (
        {"name": "host", "label": "Management HTTPS host", "type": "text", "required": True},
        {"name": "port", "label": "HTTPS port", "type": "number", "required": True, "default": 443},
        {"name": "username", "label": "Username", "type": "text", "required": True},
        {"name": "password", "label": "Password", "type": "password", "required": True},
        {"name": "domain", "label": "Domain", "type": "text", "required": False},
        {"name": "package", "label": "Policy package", "type": "text", "required": False},
        {"name": "layer", "label": "Access layer", "type": "text", "required": False},
        {"name": "gateway", "label": "Gateway", "type": "text", "required": False},
        {"name": "gaia_host", "label": "Gaia SSH host (optional)", "type": "text", "required": False},
        {"name": "gaia_port", "label": "Gaia SSH port", "type": "number", "required": False, "default": 22},
        {"name": "gaia_username", "label": "Gaia username", "type": "text", "required": False},
        {"name": "gaia_password", "label": "Gaia password", "type": "password", "required": False},
    )

    def __init__(self, api_session_factory=None, gaia_connection_factory=None, command_registry=None):
        self.api_session_factory = _default_api_session_factory if api_session_factory is None else api_session_factory
        self.gaia_connection_factory = _default_gaia_connection_factory if gaia_connection_factory is None else gaia_connection_factory
        self.command_registry = R81_COMMAND_REGISTRY if command_registry is None else command_registry

    def validate_options(self, connection):
        options = validate_connection(connection, port=443, optional=("domain", "package", "layer", "gateway", "gaia_host", "gaia_username", "gaia_password"))
        options["verify_tls"] = connection.get("verify_tls", True)
        if not isinstance(options["verify_tls"], bool):
            raise ValueError("verify_tls must be a boolean.")
        if not options["verify_tls"]:
            raise ValueError("TLS certificate verification cannot be disabled.")
        try:
            options["gaia_port"] = int(connection.get("gaia_port", 22))
        except (TypeError, ValueError) as exc:
            raise ValueError("Gaia SSH port must be between 1 and 65535.") from exc
        if options["gaia_host"] and (not options["gaia_username"] or not options["gaia_password"] or not 1 <= options["gaia_port"] <= 65535):
            raise ValueError("Gaia SSH host, username, password, and valid port are required together.")
        if any(character in options["gaia_host"] for character in "/@?#\\"):
            raise ValueError("Gaia SSH host must be a hostname or IP address.")
        return options

    def _open(self, options):
        session = self.api_session_factory()
        session.verify = True
        base = f'https://{options["host"]}:{options["port"]}/web_api/'
        payload = {"user": options["username"], "password": options["password"]}
        if options["domain"]:
            payload["domain"] = options["domain"]
        try:
            response = session.post(base + "login", json=payload, timeout=(15, 60), allow_redirects=False)
            response.raise_for_status()
            login_data = response.json()
            sid = login_data.get("sid")
            if not sid:
                raise CollectionError("Check Point login did not return a session ID.")
            session.headers["X-chkp-sid"] = sid
            session._fwmigrate_api_version = login_data.get("api-server-version")
            return session, base
        except Exception as exc:
            session.close()
            raise CollectionError("Check Point authentication failed.") from exc

    @staticmethod
    def _close(session, base):
        try:
            session.post(base + "logout", json={}, timeout=(15, 30), allow_redirects=False)
        except Exception:
            pass
        finally:
            session.close()

    def test_connection(self, options):
        session, base = self._open(options)
        self._close(session, base)

    def collect(self, options):
        session, base = self._open(options)
        bundle = CheckPointExportBundle(selected_domain=options["domain"] or None,
                                       selected_package=options["package"] or None,
                                       selected_access_layer=options["layer"] or None,
                                       selected_gateway=options["gateway"] or None,
                                       management_server=options["host"],
                                       api_version=getattr(session, "_fwmigrate_api_version", None),
                                       collector_version=_collector_version(),
                                       collection_timestamp=datetime.now(timezone.utc).isoformat(),
                                       requested_scope={key: options[key] or None for key in ("domain", "package", "layer", "gateway")})
        parts = []
        layer_states = {}
        try:
            for command, spec in self.command_registry.items():
                selectors = self._plan_selectors(command, spec, bundle, options)
                if not selectors and spec.required:
                    scope = self._response_scope(spec, options)
                    bundle.collection_completeness[self._operation_key(command, scope)] = CollectionCompletenessRecord(
                        command=command, status=CPStatus.NOT_ATTEMPTED, complete=False,
                        error_message="Required operation could not be scheduled because its selector was unavailable.",
                        **scope,
                    )
                    parts.append(CollectionPart(command, CPStatus.NOT_ATTEMPTED.value, False))
                for selector in selectors:
                    self._collect_command(session, base, command, spec, selector, bundle, parts, options, layer_states)
                if command == "show-domains" and not options["domain"]:
                    domains = _discovered_domains(bundle)
                    if len(domains) > 1:
                        raise CollectionError(
                            "Multiple Check Point management Domains were discovered. "
                            "Select a Domain explicitly before collection."
                        )
                    if len(domains) == 1:
                        resolved_options = dict(options)
                        resolved_options["domain"] = domains[0]
                        self._close(session, base)
                        session, base = self._open(resolved_options)
                        options = resolved_options
                        bundle.selected_domain = domains[0]
            if options["gaia_host"]:
                self._collect_gaia(options, bundle, parts)
        finally:
            self._close(session, base)
        stats = _collection_stats(bundle)
        bundle.successful_command_count = stats["successful"]
        bundle.failed_command_count = stats["failed"]
        bundle.unsupported_command_count = stats["unsupported"]
        bundle.permission_denied_count = stats["permission_denied"]

        usable = any(part.count for part in parts)
        failed = any(not part.complete and self.command_registry.get(part.name, None) and self.command_registry[part.name].required for part in parts)
        failed = failed or any(part.status in (
            CPStatus.API_ERROR.value,
            CPStatus.PERMISSION_DENIED.value,
            CPStatus.TRANSPORT_ERROR.value,
            CPStatus.UNSUPPORTED_COMMAND.value,
        ) for part in parts)
        status = CollectionStatus.PARTIAL if failed and usable else CollectionStatus.FAILED if failed else CollectionStatus.SUCCESS
        if status == CollectionStatus.FAILED:
            raise CollectionError("Check Point returned no usable source configuration.")
        safe = sanitize_source_attributes(bundle.model_dump(mode="json", by_alias=True))
        return CollectedSource(self.vendor_id, json.dumps(safe), "live-checkpoint.json",
                               "management-api+ssh" if options["gaia_host"] else self.method, status,
                               {"domain": options["domain"], "package": options["package"]}, tuple(parts),
                               tuple(f"{part.name}: collection incomplete" for part in parts if not part.complete)[:30])

    @staticmethod
    def _plan_selectors(command, spec, bundle, options):
        if spec.scope_type == "PACKAGE":
            selected = options["package"]
            inventory_command, selector_key = "show-packages", "package"
        elif spec.scope_type == "ACCESS_LAYER":
            selected = options["layer"]
            inventory_command, selector_key = "show-access-layers", "name"
        else:
            return [None]
        if selected:
            return [(selector_key, selected)]
        if spec.scope_type == "ACCESS_LAYER" and options["package"]:
            package = next((item for response in bundle.responses if response.command == "show-packages"
                            for item in response.data.get("objects", [])
                            if isinstance(item, dict) and item.get("name") == options["package"]
                            and (not options["domain"] or response.domain == options["domain"])), None)
            references = package.get("access-layers", package.get("access_layers", [])) if package else []
            layers = [item for response in bundle.responses if response.command == "show-access-layers"
                      for item in response.data.get("objects", []) if isinstance(item, dict)]
            by_uid = {item.get("uid"): item.get("name") for item in layers if item.get("uid") and item.get("name")}
            selectors = []
            complete = bool(references)
            for reference in references if isinstance(references, list) else []:
                if isinstance(reference, dict):
                    name = reference.get("name") or by_uid.get(reference.get("uid"))
                else:
                    name = reference if any(item.get("name") == reference for item in layers) else by_uid.get(reference)
                if name and (selector_key, name) not in selectors:
                    selectors.append((selector_key, name))
                elif not name:
                    complete = False
            if selectors and complete:
                return selectors
            return []
        return [
            (selector_key, item["name"])
            for response in bundle.responses if response.command == inventory_command
            for item in response.data.get("objects", [])
            if isinstance(item, dict) and item.get("name")
        ]

    def _collect_command(self, session, base, command, spec, selector, bundle, parts, options, layer_states,
                         parent_layer_uid=None, parent_rule_uid=None, seen_inline=None):
        offset = 0
        scope = self._response_scope(spec, options, selector)
        operation_key = self._operation_key(command, scope)
        page_records = []
        inline_entries = []
        seen_inline = set() if seen_inline is None else seen_inline
        if command == "show-access-rulebase" and selector:
            identity = self._layer_identity(scope.get("domain"), selector[1], bundle)
            if identity:
                layer_states[identity] = "in_progress"
        for page in range(100):
            payload = {"limit": 500, "offset": offset} if spec.pagination_required else {}
            if spec.details_level_full:
                payload["details-level"] = "full"
            if selector:
                payload[selector[0]] = selector[1]
            try:
                response = session.post(base + command, json=payload, timeout=(15, 60), allow_redirects=False)
                response.raise_for_status()
                if len(response.content) > 10_000_000:
                    raise CollectionError("Check Point response exceeds the size limit.")
                data = response.json()
                if not isinstance(data, dict) or spec.expected_response_shape not in data:
                    raise CollectionError("Check Point returned an unexpected response shape.")
                items = data[spec.expected_response_shape]
                if not isinstance(items, list):
                    raise CollectionError("Check Point returned an unexpected item list.")
                status = CPStatus.SUCCESS_WITH_DATA if items else CPStatus.SUCCESS_EMPTY
                total = data.get("total", len(items))
                record = CheckPointResponse(command=command, data=sanitize_source_attributes(data), **scope,
                                            scope_type=spec.scope_type.lower(),
                                            parent_layer_uid=parent_layer_uid, parent_rule_uid=parent_rule_uid,
                                            collection_status=status, object_count=len(items),
                                            from_index=data.get("from", offset + 1), to_index=data.get("to", offset + len(items)), total=total)
                bundle.responses.append(record)
                page_records.append(record)
                inline_entries.extend(items)
                parts.append(CollectionPart(command, status.value, True, len(items)))
                to_index = data.get("to", offset + len(items))
                bundle.collection_completeness[operation_key] = CollectionCompletenessRecord(command=command, status=status, complete=True, object_count=to_index, **scope)
                if not spec.pagination_required or to_index >= total:
                    valid, _ = validate_pagination(page_records)
                    if not valid:
                        bundle.collection_completeness[operation_key].complete = False
                        bundle.collection_completeness[operation_key].status = CPStatus.API_ERROR
                        bundle.collection_completeness[operation_key].error_message = "Pagination metadata is inconsistent."
                        parts.append(CollectionPart(command, CPStatus.API_ERROR.value, False))
                    elif command == "show-access-rulebase":
                        root_uid = next((item.data.get("uid") for item in page_records if item.data.get("uid")), None)
                        for rule in self._inline_references(inline_entries):
                            reference = rule.get("inline-layer")
                            child = self._inline_layer(reference, bundle, scope.get("domain"))
                            parent = (root_uid, rule.get("uid"))
                            if child is None:
                                self._record_unresolved_inline(command, spec, reference, parent, scope, bundle, parts)
                                continue
                            child_uid, child_name = child
                            child_identity = self._layer_identity(scope.get("domain"), child_uid or child_name, bundle)
                            encoded_parent = f"inline-parent:{root_uid or ''}:{rule.get('uid') or ''}"
                            for item in bundle.responses:
                                if item.command == command and item.layer == child_name and encoded_parent not in item.collection_warnings:
                                    item.collection_warnings.append(encoded_parent)
                            if child_identity:
                                state = layer_states.get(child_identity)
                                if state in {"in_progress", "complete"}:
                                    continue
                                layer_states[child_identity] = "in_progress"
                            if not child_name:
                                self._record_unresolved_inline(command, spec, reference, parent, scope, bundle, parts)
                                continue
                            before = len(bundle.responses)
                            self._collect_command(session, base, command, spec, ("name", child_name), bundle, parts, options, layer_states,
                                                  parent_layer_uid=root_uid, parent_rule_uid=rule.get("uid"), seen_inline=seen_inline)
                            if child_identity:
                                child_records = [item for item in bundle.responses[before:] if item.command == command]
                                layer_states[child_identity] = "complete" if child_records and all(
                                    collection_status_is_success(item.collection_status) for item in child_records
                                ) else "failed"
                            # The original response keeps the first parent; every parent edge is
                            # retained in collection_warnings without duplicate pagination pages.
                            if child_identity:
                                encoded_parent = f"inline-parent:{root_uid or ''}:{rule.get('uid') or ''}"
                                for item in bundle.responses:
                                    if item.command == command and item.layer == child_name and encoded_parent not in item.collection_warnings:
                                        item.collection_warnings.append(encoded_parent)
                            # Response pages remain unique by layer for pagination grouping.
                            # Keep every shared-layer parent edge in the existing evidence field.
                    return
                if not items:
                    raise CollectionError("Check Point pagination stopped early.")
                offset = to_index
            except Exception as exc:
                status = _classify_management_error(exc)
                error_code = _management_error_code(exc)
                bundle.responses.append(CheckPointResponse(
                    command=command, data={}, collection_status=status,
                    collection_error_code=error_code,
                    error="Collection request failed.", **scope,
                ))
                parts.append(CollectionPart(command, status.value, False))
                bundle.collection_completeness[operation_key] = CollectionCompletenessRecord(
                    command=command, status=status, complete=False,
                    error_code=error_code, error_message="Collection request failed.", **scope,
                )
                if command == "show-access-rulebase" and selector:
                    identity = self._layer_identity(scope.get("domain"), selector[1], bundle)
                    if identity:
                        layer_states[identity] = "failed"
                return
        parts.append(CollectionPart(command, CPStatus.API_ERROR.value, False))
        bundle.collection_completeness[operation_key] = CollectionCompletenessRecord(command=command, status=CPStatus.API_ERROR, complete=False, error_message="Pagination page limit exceeded.", **scope)

    @staticmethod
    def _response_scope(spec, options, selector=None):
        scope = {}
        if spec.scope_type != "GLOBAL":
            scope["domain"] = options["domain"] or None
        if spec.scope_type == "PACKAGE":
            scope["package"] = (selector[1] if selector else options["package"]) or None
        elif spec.scope_type == "ACCESS_LAYER":
            scope["layer"] = (selector[1] if selector else options["layer"]) or None
        return scope

    @staticmethod
    def _operation_key(command, scope):
        identity = "|".join(f"{key}={scope[key]}" for key in ("domain", "package", "layer", "gateway") if scope.get(key))
        return f"{command}|{identity}" if identity else command

    @staticmethod
    def _inline_references(rulebase):
        result = []
        def walk(value):
            if isinstance(value, dict):
                if str(value.get("type", "")).lower() == "access-rule" and value.get("inline-layer"):
                    result.append(value)
                for child in value.values():
                    if isinstance(child, (dict, list)): walk(child)
            elif isinstance(value, list):
                for child in value: walk(child)
        walk(rulebase)
        return result


    @staticmethod
    def _inline_layer(reference, bundle, domain=None):
        if isinstance(reference, dict):
            if reference.get("name"):
                return str(reference.get("uid") or ""), str(reference["name"])
            uid = reference.get("uid")
        else:
            uid = reference if reference else None
        key = uid
        if not key:
            return None
        matches = []
        for response in bundle.responses:
            if response.command == "show-access-layers":
                for layer in response.data.get("objects", []):
                    if (isinstance(layer, dict) and (layer.get("uid") == key or layer.get("name") == key)
                            and (domain is None or response.domain in (None, domain))):
                        matches.append((str(layer.get("uid") or ""), str(layer.get("name") or "") or None))
        unique = list(dict.fromkeys(matches))
        return unique[0] if len(unique) == 1 else None

    @staticmethod
    def _layer_identity(domain, reference, bundle):
        resolved = CheckPointCollector._inline_layer(reference, bundle, domain)
        if resolved and resolved[0]:
            return (domain or "global", "uid", resolved[0])
        if isinstance(reference, dict):
            uid, name = reference.get("uid"), reference.get("name")
        else:
            uid, name = None, reference
        value = uid or name or reference
        return (domain or "global", "name", str(value).casefold()) if value else None

    def _record_unresolved_inline(self, command, spec, reference, parent, scope, bundle, parts):
        label = reference.get("uid") if isinstance(reference, dict) else reference
        operation_scope = dict(scope)
        operation_scope["layer"] = f"unresolved-inline:{label or 'unknown'}"
        key = self._operation_key(command, operation_scope)
        message = "Inline access layer could not be resolved from the scoped access-layer inventory."
        bundle.collection_completeness[key] = CollectionCompletenessRecord(
            command=command, status=CPStatus.NOT_ATTEMPTED, complete=False,
            error_message=message, **operation_scope,
        )
        parts.append(CollectionPart(command, CPStatus.NOT_ATTEMPTED.value, False))

    def _collect_gaia(self, options, bundle, parts):
        connection = None
        try:
            connection = self.gaia_connection_factory(
                device_type="checkpoint_gaia",
                host=options["gaia_host"],
                port=options["gaia_port"],
                username=options["gaia_username"],
                password=options["gaia_password"],
                conn_timeout=15,
                auth_timeout=15,
                banner_timeout=15,
                ssh_strict=True,
                system_host_keys=True,
            )
        except Exception:
            bundle.gaia_responses.append({
                "command": "gaia/show-configuration",
                "data": {"cli_text": ""},
                "gateway": options["gateway"] or None,
                "collection_status": CPStatus.TRANSPORT_ERROR.value,
                "error": "Gaia SSH collection failed.",
            })
            parts.append(CollectionPart("gaia/show-configuration", CPStatus.TRANSPORT_ERROR.value, False))
            return

        try:
            self._collect_gaia_command(
                connection, "gaia/show-configuration", "show configuration",
                bundle, parts, options, data_key="cli_text",
            )
            for source_command, cli_command in _GAIA_EVIDENCE_COMMANDS:
                self._collect_gaia_command(
                    connection, source_command, cli_command,
                    bundle, parts, options, data_key="command_output",
                )
        finally:
            connection.disconnect()

    @staticmethod
    def _collect_gaia_command(
        connection, source_command, cli_command, bundle, parts, options, *, data_key,
    ):
        try:
            content = connection.send_command(cli_command, read_timeout=60)
            if len(content.encode("utf-8")) > 25_000_000:
                raise CollectionError("Gaia command output exceeds the size limit.")
            safe_content = sanitize_raw_text(content)
            failure_status = _classify_gaia_output(safe_content)
            if failure_status is not None:
                bundle.gaia_responses.append({
                    "command": source_command,
                    "data": {data_key: ""},
                    "gateway": options["gateway"] or None,
                    "scope_type": "gateway",
                    "parser_consumer": "gaia-config" if data_key == "cli_text" else "source-inventory",
                    "expected_response_shape": data_key,
                    "collection_status": failure_status.value,
                    "source_response": safe_content[:2000],
                    "error": "Gaia command returned an error response.",
                })
                parts.append(CollectionPart(source_command, failure_status.value, False))
                return
            status = CPStatus.SUCCESS_WITH_DATA if safe_content.strip() else CPStatus.SUCCESS_EMPTY
            bundle.gaia_responses.append({
                "command": source_command,
                "data": {data_key: safe_content},
                "gateway": options["gateway"] or None,
                "scope_type": "gateway",
                "parser_consumer": "gaia-config" if data_key == "cli_text" else "source-inventory",
                "expected_response_shape": data_key,
                "collection_status": status.value,
                "object_count": 1 if safe_content.strip() else 0,
            })
            parts.append(CollectionPart(
                source_command, status.value, True, 1 if safe_content.strip() else 0,
            ))
            return
        except Exception:
            bundle.gaia_responses.append({
                "command": source_command,
                "data": {data_key: ""},
                "gateway": options["gateway"] or None,
                "scope_type": "gateway",
                "parser_consumer": "gaia-config" if data_key == "cli_text" else "source-inventory",
                "expected_response_shape": data_key,
                "collection_status": CPStatus.TRANSPORT_ERROR.value,
                "error": "Gaia command collection failed.",
            })
            parts.append(CollectionPart(source_command, CPStatus.TRANSPORT_ERROR.value, False))
            return


def _classify_gaia_output(content):
    if not content:
        return None
    if re.search(r"(?im)^\s*(?:permission denied|not authorized|authorization failed)\b", content):
        return CPStatus.PERMISSION_DENIED
    if re.search(
        r"(?im)^\s*(?:unknown command|invalid command|command not found|unsupported command|"
        r"command is not supported)\b",
        content,
    ):
        return CPStatus.UNSUPPORTED_COMMAND
    if re.search(r"(?im)^\s*(?:CLINFR\d+|ERROR\s*:|ERROR\s+-)", content):
        return CPStatus.API_ERROR
    return None


def _default_api_session_factory():
    try:
        import requests
    except ImportError as exc:
        raise CollectionError("Live collection requires the collection extra (requests).") from exc
    return requests.Session()


def _default_gaia_connection_factory(**kwargs):
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise CollectionError("Live Gaia collection requires the collection extra (netmiko).") from exc
    return ConnectHandler(**kwargs)


def _collector_version():
    try:
        return version("firewall-migration-tool")
    except PackageNotFoundError:
        return None


def _collection_stats(bundle):
    management = tuple(bundle.collection_completeness.values())
    gaia = tuple(bundle.gaia_responses)
    statuses = [item.status for item in management]
    statuses.extend(item.get("collection_status") for item in gaia)
    normalized = []
    for status in statuses:
        try:
            normalized.append(CPStatus(status))
        except (TypeError, ValueError):
            continue
    return {
        "successful": sum(collection_status_is_success(status) for status in normalized),
        "failed": sum(status in {
            CPStatus.API_ERROR, CPStatus.TRANSPORT_ERROR, CPStatus.ERROR, CPStatus.NOT_ATTEMPTED,
        } for status in normalized),
        "unsupported": sum(status == CPStatus.UNSUPPORTED_COMMAND for status in normalized),
        "permission_denied": sum(status == CPStatus.PERMISSION_DENIED for status in normalized),
    }


def _discovered_domains(bundle):
    result = []
    for response in bundle.responses:
        if response.command != "show-domains":
            continue
        for item in response.data.get("objects", []):
            if not isinstance(item, dict):
                continue
            identity = item.get("name") or item.get("uid")
            if identity and identity not in result:
                result.append(str(identity))
    return tuple(result)


def _management_error_payload(error):
    response = getattr(error, "response", None)
    if response is None:
        return {}
    try:
        payload = response.json()
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _management_error_code(error):
    payload = _management_error_payload(error)
    value = payload.get("code")
    return sanitize_raw_text(str(value)) if value is not None else None


def _classify_management_error(error):
    response = getattr(error, "response", None)
    code = getattr(response, "status_code", None)
    if code == 403:
        return CPStatus.PERMISSION_DENIED

    payload = _management_error_payload(error)
    capability_evidence = " ".join(
        str(payload.get(key) or "") for key in ("code", "message")
    ).lower().replace("-", "_").replace(" ", "_")
    if any(token in capability_evidence for token in (
        "command_not_found", "unknown_command", "unsupported_command",
        "command_is_not_supported", "not_supported",
    )):
        return CPStatus.UNSUPPORTED_COMMAND

    if code is not None or isinstance(error, (CollectionError, ValueError, TypeError)):
        return CPStatus.API_ERROR
    return CPStatus.TRANSPORT_ERROR
