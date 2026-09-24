"""Check Point Management API and optional Gaia SSH collection."""

import json

from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes
from fwmigrate.vendors.checkpoint.models import (
    CheckPointExportBundle, CheckPointResponse, CollectionCompletenessRecord,
    CollectionStatus as CPStatus,
)
from fwmigrate.vendors.checkpoint.r81_commands import R81_COMMAND_REGISTRY
from fwmigrate.vendors.checkpoint.loader import validate_pagination

from .contracts import CollectedSource, CollectionError, CollectionPart, CollectionStatus, validate_connection


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
        {"name": "verify_tls", "label": "Verify TLS certificate", "type": "checkbox", "default": True},
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
        session.verify = options["verify_tls"]
        base = f'https://{options["host"]}:{options["port"]}/web_api/'
        payload = {"user": options["username"], "password": options["password"]}
        if options["domain"]:
            payload["domain"] = options["domain"]
        try:
            response = session.post(base + "login", json=payload, timeout=(15, 60), allow_redirects=False)
            response.raise_for_status()
            sid = response.json().get("sid")
            if not sid:
                raise CollectionError("Check Point login did not return a session ID.")
            session.headers["X-chkp-sid"] = sid
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
                                       requested_scope={key: options[key] or None for key in ("domain", "package", "layer", "gateway")})
        parts = []
        try:
            for command, spec in self.command_registry.items():
                selectors = self._plan_selectors(command, spec, bundle, options)
                for selector in selectors:
                    self._collect_command(session, base, command, spec, selector, bundle, parts, options)
            if options["gaia_host"]:
                self._collect_gaia(options, bundle, parts)
        finally:
            self._close(session, base)
        usable = any(part.count for part in parts)
        failed = any(not part.complete and self.command_registry.get(part.name, None) and self.command_registry[part.name].required for part in parts)
        failed = failed or any(part.status in (CPStatus.API_ERROR.value, CPStatus.PERMISSION_DENIED.value, CPStatus.TRANSPORT_ERROR.value) for part in parts)
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
                            if isinstance(item, dict) and item.get("name") == options["package"]), None)
            references = package.get("access-layers", package.get("access_layers", [])) if package else []
            layers = [item for response in bundle.responses if response.command == "show-access-layers"
                      for item in response.data.get("objects", []) if isinstance(item, dict)]
            by_uid = {item.get("uid"): item.get("name") for item in layers if item.get("uid") and item.get("name")}
            selectors = []
            for reference in references if isinstance(references, list) else []:
                if isinstance(reference, dict):
                    name = reference.get("name") or by_uid.get(reference.get("uid"))
                else:
                    name = reference if any(item.get("name") == reference for item in layers) else by_uid.get(reference)
                if name and (selector_key, name) not in selectors:
                    selectors.append((selector_key, name))
            if selectors:
                return selectors
        return [
            (selector_key, item["name"])
            for response in bundle.responses if response.command == inventory_command
            for item in response.data.get("objects", [])
            if isinstance(item, dict) and item.get("name")
        ]

    def _collect_command(self, session, base, command, spec, selector, bundle, parts, options,
                         parent_layer_uid=None, parent_rule_uid=None, seen_inline=None):
        offset = 0
        scope = self._response_scope(spec, options, selector)
        operation_key = self._operation_key(command, scope)
        page_records = []
        inline_entries = []
        seen_inline = set() if seen_inline is None else seen_inline
        if command == "show-access-rulebase" and selector:
            seen_inline.add(str(selector[1]).casefold())
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
                            child_name = self._inline_layer_name(reference, bundle)
                            if not child_name or child_name.casefold() in seen_inline:
                                continue
                            seen_inline.add(child_name.casefold())
                            self._collect_command(session, base, command, spec, ("name", child_name), bundle, parts, options,
                                                  parent_layer_uid=root_uid, parent_rule_uid=rule.get("uid"), seen_inline=seen_inline)
                    return
                if not items:
                    raise CollectionError("Check Point pagination stopped early.")
                offset = to_index
            except Exception as exc:
                status = _classify_management_error(exc)
                bundle.responses.append(CheckPointResponse(command=command, data={}, collection_status=status,
                                                            error="Collection request failed.", **scope))
                parts.append(CollectionPart(command, status.value, False))
                bundle.collection_completeness[operation_key] = CollectionCompletenessRecord(command=command, status=status, complete=False, error_message="Collection request failed.", **scope)
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
    def _inline_layer_name(reference, bundle):
        if isinstance(reference, dict):
            if reference.get("name"):
                return str(reference["name"])
            uid = reference.get("uid")
        else:
            uid = None
        key = uid or reference
        for response in bundle.responses:
            if response.command == "show-access-layers":
                for layer in response.data.get("objects", []):
                    if isinstance(layer, dict) and (layer.get("uid") == key or layer.get("name") == key):
                        return str(layer.get("name") or "") or None
        return str(reference) if not isinstance(reference, dict) and reference else None

    def _collect_gaia(self, options, bundle, parts):
        connection = None
        try:
            connection = self.gaia_connection_factory(device_type="checkpoint_gaia", host=options["gaia_host"], port=options["gaia_port"],
                                        username=options["gaia_username"], password=options["gaia_password"],
                                        conn_timeout=15, auth_timeout=15, banner_timeout=15,
                                        ssh_strict=True, system_host_keys=True)
            content = connection.send_command("show configuration", read_timeout=60)
            if len(content.encode("utf-8")) > 25_000_000:
                raise CollectionError("Gaia configuration exceeds the size limit.")
            bundle.gaia_responses.append({"command": "gaia/show-configuration", "data": {"cli_text": sanitize_raw_text(content)},
                                          "gateway": options["gateway"] or None,
                                          "collection_status": CPStatus.SUCCESS_WITH_DATA.value if content.strip() else CPStatus.SUCCESS_EMPTY.value})
            parts.append(CollectionPart("gaia/show-configuration", "SUCCESS" if content.strip() else "EMPTY", True, 1 if content.strip() else 0))
        except Exception:
            bundle.gaia_responses.append({"command": "gaia/show-configuration", "data": {"cli_text": ""},
                                          "gateway": options["gateway"] or None,
                                          "collection_status": CPStatus.TRANSPORT_ERROR.value,
                                          "error": "Gaia SSH collection failed."})
            parts.append(CollectionPart("gaia/show-configuration", CPStatus.TRANSPORT_ERROR.value, False))
        finally:
            if connection is not None:
                connection.disconnect()


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


def _classify_management_error(error):
    code = getattr(getattr(error, "response", None), "status_code", None)
    if code == 403:
        return CPStatus.PERMISSION_DENIED
    if code is not None or isinstance(error, (CollectionError, ValueError, TypeError)):
        return CPStatus.API_ERROR
    return CPStatus.TRANSPORT_ERROR
