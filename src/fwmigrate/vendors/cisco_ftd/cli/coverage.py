from fwmigrate.extraction.models import ExtractionStatus, SourceSectionResult


def classify_cisco_ftd_coverage(sections: list[SourceSectionResult]) -> None:
    for section in sections:
        if section.path in {"interfaces", "routes"}:
            section.status = ExtractionStatus.EXTRACTED
            noun = "interface" if section.path == "interfaces" else "route"
            section.notes.append(f"FTD syntax was parsed into Cisco FTD source {noun} state.")
        elif section.path == "management":
            section.status = ExtractionStatus.PARTIAL
            section.notes.append("FTD management syntax is retained as source-oriented data.")
        else:
            section.status = ExtractionStatus.UNSUPPORTED
            section.notes.append("FTD syntax is preserved pending an official input-format reference.")
