from fwmigrate.extraction.models import ExtractionStatus, SourceSectionResult


def classify_cisco_ftd_coverage(sections: list[SourceSectionResult]) -> None:
    for section in sections:
        if section.path == "management":
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.notes.append("FTD management syntax is retained as source-oriented data.")
        else:
            section.status = ExtractionStatus.UNSUPPORTED
            section.notes.append("FTD syntax is preserved pending an official input-format reference.")
