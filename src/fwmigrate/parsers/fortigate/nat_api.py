"""Live NAT ingestion using the same typed models and accounting as file input."""

from pydantic import ValidationError

from fwmigrate.extraction.models import SourceObjectResult, SourceSectionResult, ExtractionStatus
from fwmigrate.parsers.fortigate.extraction import sanitize_source_attributes
from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer


def extract_nat_inventory(client, config):
    parser = FortiGateParser(FortiGateTokenizer(""))
    parser.config = config
    for section in (
        "system settings", "firewall ippool", "firewall vip", "firewall vipgrp",
        "firewall policy", "firewall central-snat-map", "firewall ippool6", "firewall vip6",
        "firewall vipgrp6", "firewall policy6",
    ):
        endpoint = "cmdb/" + section.replace(" ", "/")
        evidence = SourceSectionResult(path=section, scope=client.vdom)
        config.extraction.sections.append(evidence)
        try:
            data = client.get(endpoint)
        except (KeyError, ValueError):
            evidence.present = False
            evidence.source_count = None
            evidence.notes.append("API endpoint unavailable or incomplete; this is not evidence of an empty section.")
            config.extraction.blocking_issues.append(f"NAT coverage unknown for {endpoint} in scope {client.vdom}.")
            if section == "system settings":
                config.settings_by_scope[client.vdom] = {"central_nat": "unknown"}
            continue
        evidence.source_count = len(data)
        if section == "system settings" and len(data) != 1:
            config.settings_by_scope[client.vdom] = {"central_nat": "unknown"}
            config.extraction.blocking_issues.append("Live central NAT mode was not returned unambiguously.")
        for sequence, raw in enumerate(data, 1):
            numeric = section in {"firewall policy", "firewall central-snat-map"}
            native_id = raw.get("policyid", raw.get("q_origin_key")) if numeric else raw.get("name")
            if section == "system settings":
                native_id = "system settings"
            record = SourceObjectResult(
                id=f"{client.vdom}:{section}:{native_id}:api:{sequence}", section=section,
                name=str(native_id) if native_id is not None else "[MISSING ID]",
                scope=client.vdom, api_path=endpoint, sequence=sequence,
                attributes=sanitize_source_attributes({k: v for k, v in raw.items() if k != "q_origin_key"}),
            )
            config.extraction.objects.append(record)
            if section.endswith("6"):
                record.status = ExtractionStatus.UNSUPPORTED
                record.blocking = True
                record.notes.append("IPv6 NAT source settings retained; normalization is not implemented.")
                continue
            if section == "firewall vip" and raw.get("type", "static-nat") != "static-nat":
                record.status = ExtractionStatus.UNSUPPORTED
                record.blocking = True
                record.notes.append("Non-static VIP type retained, including nested settings; canonical mapping is not implemented.")
                continue
            attrs = {"source_record": record}
            if native_id is None:
                record.status, record.parsed, record.blocking = ExtractionStatus.PARSE_ERROR, False, True
                record.notes.append("API object is missing its native ID/name; no placeholder rule was fabricated.")
                continue
            if numeric:
                attrs["id"] = native_id
            else:
                attrs["name"] = str(native_id)
            for key, value in raw.items():
                if key in {"q_origin_key", "policyid"} or value is None:
                    continue
                items = value if isinstance(value, list) else [value]
                if any(isinstance(v, dict) and not ("name" in v or "q_origin_key" in v) for v in items):
                    continue  # Nested data remains in the structured source inventory.
                values = [str(v.get("name", v.get("q_origin_key"))) if isinstance(v, dict) else str(v) for v in items]
                parser.apply_attribute(attrs, key, values, section)
            if section == "system settings":
                if len(data) == 1:
                    config.settings_by_scope[client.vdom] = {k: v for k, v in attrs.items() if k not in {"source_record", "name"}}
                continue
            try:
                parser.build_model(section, attrs)
            except (ValidationError, ValueError):
                record.status, record.parsed, record.blocking = ExtractionStatus.PARSE_ERROR, False, True
                record.notes.append("API object has invalid/missing model fields; source values remain in inventory.")
