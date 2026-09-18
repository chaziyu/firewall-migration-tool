"""Common FortiGate edit-section preparation."""

from fwmigrate.parsers.fortigate import parser as parser_module
from fwmigrate.parsers.fortigate.section_registry import get_section_spec

def prepare_section(self: Any, section_path: str, attributes: Dict[str, Any]) -> bool:
    spec = get_section_spec(section_path)
    if section_path == "firewall service custom":
        raw_timeout = attributes.get("session_ttl")
        if raw_timeout is not None and not (
            isinstance(raw_timeout, str) and raw_timeout.lower() == "never"
        ):
            self._normalize_optional_int(attributes, "session_ttl")
    if section_path in {
        "firewall address6",
        "firewall multicast-address",
        "firewall multicast-address6",
    }:
        parser_module._apply_address_defaults(section_path, attributes)
    if section_path in parser_module.CONTEXTUAL_MODEL_SECTIONS:
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
    if section_path in parser_module.STANDARD_SECTION_PATHS:
        attributes["extra_settings"] = parser_module._extract_extra_settings(
            attributes, set(spec.model.model_fields)
        )
        getattr(self.config, spec.destination_collection).append(spec.model(**attributes))
        return

    return False
