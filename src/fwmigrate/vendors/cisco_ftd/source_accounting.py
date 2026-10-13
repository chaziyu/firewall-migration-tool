"""Cisco FTD CLI correlation and collection accounting."""

from fwmigrate.extraction.models import ExtractionStatus, SourceSectionResult
from .cli.coverage import classify_cisco_ftd_coverage
from .cli.section_scanner import scan_cisco_ftd_sections
from .source_inventory import build_ftd_source_inventory


def source_count(config):
    return len(build_ftd_source_inventory(config))


def account_cli_sections(text, config):
    sections = scan_cisco_ftd_sections(text)
    classify_cisco_ftd_coverage(sections)
    interfaces = {item.source_attributes.get("source_line_number"): item for item in config.interfaces}
    routes = {item.source_attributes.get("source_line_number"): item for item in config.static_routes}
    management = {item.source_attributes.get("source_line_number"): item for item in config.management_settings}
    for section in sections:
        line = section.line_start
        if section.path == "interfaces":
            parsed = interfaces.get(line)
            section.object_count_parsed = int(parsed is not None)
            section.object_count_extracted = section.object_count_parsed
            if parsed is None:
                section.status = ExtractionStatus.PARSE_ERROR
                section.object_count_parse_error = 1
                section.notes.append("Interface section was not parsed into Cisco FTD source state.")
        elif section.path == "routes":
            parsed = routes.get(line)
            malformed = parsed is not None and any(
                item.get("source_name") == parsed.name and item.get("source_path") == "ftd-cli/routes"
                for item in config.unsupported_evidence
            )
            section.object_count_parsed = int(parsed is not None and not malformed)
            section.object_count_extracted = int(parsed is not None and not malformed)
            if malformed:
                section.status = ExtractionStatus.PARSE_ERROR
                section.object_count_parse_error = 1
                section.notes.append("Malformed FTD static route was preserved as source evidence.")
            elif parsed is None:
                section.status = ExtractionStatus.PARSE_ERROR
                section.object_count_parse_error = 1
                section.notes.append("Route section was not parsed into Cisco FTD source state.")
        elif section.path == "management":
            section.object_count_parsed = int(line in management)
            section.object_count_extracted = 0
        else:
            section.object_count_parsed = 0
            section.object_count_extracted = 0
    return sections


def project_collection_completeness(config, sections):
    collection = config.collection_metadata
    if config.source_plane == "fmc-rest-bundle" and collection.status in {"PARTIAL", "FAILED"}:
        sections.append(SourceSectionResult(path="fmc/collection", status=ExtractionStatus.PARTIAL,
            source_context=config.source_metadata.get("domain_name"), object_count_source=len(collection.parts),
            object_count_parsed=len(collection.parts), object_count_extracted=sum(part.complete for part in collection.parts),
            collection_errors=[f"{part.name}: {part.status}" for part in collection.parts if not part.complete]))

