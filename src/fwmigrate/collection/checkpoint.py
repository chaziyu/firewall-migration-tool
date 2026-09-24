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
        try:
            import requests
        except ImportError as exc:
            raise CollectionError("Live collection requires the collection extra (requests).") from exc
        session = requests.Session()
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
                                       selected_gateway=options["gateway"] or None)
        parts = []
        try:
            for command, spec in R81_COMMAND_REGISTRY.items():
                selector = {"ACCESS_LAYER": ("name", options["layer"]), "PACKAGE": ("package", options["package"])}.get(spec.scope_type)
                if selector and not selector[1]:
                    status = CPStatus.UNSUPPORTED_COMMAND if not spec.required else CPStatus.API_ERROR
                    response = CheckPointResponse(command=command, data={}, collection_status=status, error="Scope selector required",
                                                  domain=options["domain"] or None, package=options["package"] or None,
                                                  layer=options["layer"] or None, gateway=options["gateway"] or None)
                    bundle.responses.append(response)
                    parts.append(CollectionPart(command, status.value, False))
                    bundle.collection_completeness[command] = CollectionCompletenessRecord(command=command, status=status, complete=False,
                                                                                           domain=options["domain"] or None, package=options["package"] or None,
                                                                                           layer=options["layer"] or None, gateway=options["gateway"] or None,
                                                                                           error_message="Scope selector required")
                    continue
                self._collect_command(session, base, command, spec, selector, bundle, parts, options)
            if options["gaia_host"]:
                self._collect_gaia(options, bundle, parts)
        finally:
            self._close(session, base)
        usable = any(part.count for part in parts)
        failed = any(not part.complete and R81_COMMAND_REGISTRY.get(part.name, None) and R81_COMMAND_REGISTRY[part.name].required for part in parts)
        failed = failed or any(part.status in (CPStatus.API_ERROR.value, CPStatus.PERMISSION_DENIED.value, CPStatus.TRANSPORT_ERROR.value) for part in parts)
        status = CollectionStatus.PARTIAL if failed and usable else CollectionStatus.FAILED if failed else CollectionStatus.SUCCESS
        if status == CollectionStatus.FAILED:
            raise CollectionError("Check Point returned no usable source configuration.")
        safe = sanitize_source_attributes(bundle.model_dump(mode="json", by_alias=True))
        return CollectedSource(self.vendor_id, json.dumps(safe), "live-checkpoint.json",
                               "management-api+ssh" if options["gaia_host"] else self.method, status,
                               {"domain": options["domain"], "package": options["package"]}, tuple(parts),
                               tuple(f"{part.name}: collection incomplete" for part in parts if not part.complete)[:30])

    def _collect_command(self, session, base, command, spec, selector, bundle, parts, options):
        offset = 0
        scope = {"domain": options["domain"] or None, "package": options["package"] or None,
                 "layer": options["layer"] or None, "gateway": options["gateway"] or None}
        for page in range(100):
            payload = {"limit": 500, "offset": offset} if spec.pagination_required else {}
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
                record = CheckPointResponse(command=command, data=sanitize_source_attributes(data),
                                            domain=options["domain"] or None, package=options["package"] or None,
                                            layer=options["layer"] or None, gateway=options["gateway"] or None,
                                            collection_status=status, object_count=len(items),
                                            from_index=data.get("from", offset + 1), to_index=data.get("to", offset + len(items)), total=total)
                bundle.responses.append(record)
                parts.append(CollectionPart(command, status.value, True, len(items)))
                to_index = data.get("to", offset + len(items))
                bundle.collection_completeness[command] = CollectionCompletenessRecord(command=command, status=status, complete=True, object_count=to_index, **scope)
                if not spec.pagination_required or to_index >= total:
                    pages = [item for item in bundle.responses if item.command == command]
                    valid, _ = validate_pagination(pages)
                    if not valid:
                        bundle.collection_completeness[command].complete = False
                        bundle.collection_completeness[command].status = CPStatus.API_ERROR
                        bundle.collection_completeness[command].error_message = "Pagination metadata is inconsistent."
                        parts.append(CollectionPart(command, CPStatus.API_ERROR.value, False))
                    return
                if not items:
                    raise CollectionError("Check Point pagination stopped early.")
                offset = to_index
            except Exception as exc:
                code = getattr(getattr(exc, "response", None), "status_code", None)
                status = (CPStatus.PERMISSION_DENIED if code == 403 else
                          CPStatus.API_ERROR if code or isinstance(exc, (CollectionError, ValueError, TypeError)) else
                          CPStatus.TRANSPORT_ERROR)
                bundle.responses.append(CheckPointResponse(command=command, data={}, collection_status=status,
                                                            error="Collection request failed.", **scope))
                parts.append(CollectionPart(command, status.value, False))
                bundle.collection_completeness[command] = CollectionCompletenessRecord(command=command, status=status, complete=False, error_message="Collection request failed.", **scope)
                return
        parts.append(CollectionPart(command, CPStatus.API_ERROR.value, False))
        bundle.collection_completeness[command] = CollectionCompletenessRecord(command=command, status=CPStatus.API_ERROR, complete=False, error_message="Pagination page limit exceeded.", **scope)

    def _collect_gaia(self, options, bundle, parts):
        connection = None
        try:
            from netmiko import ConnectHandler
            connection = ConnectHandler(device_type="checkpoint_gaia", host=options["gaia_host"], port=options["gaia_port"],
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
