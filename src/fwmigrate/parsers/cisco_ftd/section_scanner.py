from fwmigrate.extraction.models import ExtractionStatus, SourceSectionResult


def scan_cisco_ftd_sections(text: str) -> list[SourceSectionResult]:
    sections = []
    current = None
    current_indent = 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("!", ":", "#")):
            current = None
            continue
        indent = len(raw) - len(raw.lstrip())
        if current is not None and indent > current_indent:
            current.line_end = number
            current.object_count_source = (current.object_count_source or 0) + 1
            continue
        if current is not None:
            current.line_end = number - 1
        first = line.split()[0].lower()
        path = "management" if first in {"configure", "management", "show-network-style"} else "other"
        current = SourceSectionResult(
            path=path, line_start=number, line_end=number,
            object_count_source=1, status=ExtractionStatus.EXTRACT_ONLY,
            parser_handler="CiscoFTDParser.parse",
        )
        sections.append(current)
        current_indent = indent
    if current is not None:
        current.line_end = len(text.splitlines())
    return sections
