"""Common FortiGate edit-section preparation."""

from fwmigrate.parsers.fortigate import parser as parser_module

globals().update({
    name: getattr(parser_module, name)
    for name in dir(parser_module)
    if not name.startswith("__")
})

def prepare_section(self: Any, section_path: str, attributes: Dict[str, Any]) -> bool:
    spec = get_section_spec(section_path)
    if section_path == "authentication scheme":
        timeout = attributes.get("saml_timeout")
        if timeout is not None and not 30 <= timeout <= 1200:
            attributes["unparsed_saml_timeout"] = attributes.pop("saml_timeout")
        methods = attributes.get("method", [])
        invalid_methods = [value for value in methods if value not in AUTHENTICATION_METHODS]
        if invalid_methods:
            attributes["method"] = [value for value in methods if value in AUTHENTICATION_METHODS]
            attributes["unparsed_method"] = invalid_methods
        for field in AUTHENTICATION_SWITCH_FIELDS:
            value = attributes.get(field)
            if value is not None and value not in {"enable", "disable"}:
                attributes[f"unparsed_{field}"] = attributes.pop(field)
        for field, limit in AUTHENTICATION_STRING_LIMITS.items():
            value = attributes.get(field)
            if value is not None and (not isinstance(value, str) or len(value) > limit):
                attributes[f"unparsed_{field}"] = attributes.pop(field)
        databases = attributes.get("user_database", [])
        invalid_databases = [value for value in databases if not isinstance(value, str) or len(value) > 79]
        if invalid_databases:
            attributes["user_database"] = [value for value in databases if value not in invalid_databases]
            attributes["unparsed_user_database"] = invalid_databases
    elif section_path == "firewall service custom":
        raw_timeout = attributes.get("session_ttl")
        if raw_timeout is not None and not (
            isinstance(raw_timeout, str) and raw_timeout.lower() == "never"
        ):
            self._normalize_optional_int(attributes, "session_ttl")
    elif section_path == "system session-ttl port":
        timeout = attributes.get("timeout")
        if timeout is not None and not (
            isinstance(timeout, str) and timeout.lower() == "never"
        ):
            self._normalize_optional_int(attributes, "timeout")
    if section_path in {
        "firewall address6",
        "firewall multicast-address",
        "firewall multicast-address6",
    }:
        _apply_address_defaults(section_path, attributes)
    if section_path in {"firewall addrgrp", "firewall addrgrp6"}:
        if "filter" in attributes:
            attributes["dynamic_filter"] = attributes["filter"]
    if section_path in CONTEXTUAL_MODEL_SECTIONS:
        attributes.setdefault("source_context", self.current_context)
    if section_path in {
        "firewall internet-service-custom",
        "firewall internet-service-custom-group",
        "firewall internet-service-addition",
        "firewall internet-service-append",
        "firewall internet-service-extension",
        "firewall internet-service-group",
    }:
        attributes.setdefault("source_context", self.current_context)
    if section_path in STANDARD_SECTION_PATHS:
        attributes["extra_settings"] = _extract_extra_settings(
            attributes, set(spec.model.model_fields)
        )
        getattr(self.config, spec.destination_collection).append(spec.model(**attributes))
        return

    return False
