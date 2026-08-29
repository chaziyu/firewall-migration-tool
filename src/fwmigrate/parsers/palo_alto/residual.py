import xml.etree.ElementTree as ET
from fwmigrate.extraction.models import SourceInventoryItem, ExtractionStatus
from .source_model import PANScope

class PANResidualExtractor:
    # Known subtrees that are parsed or handled explicitly
    PROCESSED_TAGS = {
        "zone", "address", "address-group", "service", "service-group", "schedule",
        "rulebase", "pre-rulebase", "post-rulebase", "virtual-router",
        "application", "application-group", "application-filter",
        "import", "tag"
    }

    @staticmethod
    def extract_residual_scope(scope: PANScope, search_root: ET.Element, extraction):
        # Depending on scope, we check immediate children of the root
        # that are not in PROCESSED_TAGS
        
        for child in search_root:
            tag = child.tag
            if tag in PANResidualExtractor.PROCESSED_TAGS:
                continue
                
            # If it's a known non-migration relevant thing, we can skip or mark as VENDOR_EXTENSION
            if tag in ["property", "setting", "log-settings", "reports"]:
                status = ExtractionStatus.VENDOR_EXTENSION
            else:
                status = ExtractionStatus.UNSUPPORTED
                
            # For each entry in this unhandled subtree, or just the subtree itself
            # We record a single inventory item for the whole subtree to avoid spamming
            
            # If it has entries, we can log each entry
            entries = child.findall("./entry")
            if entries:
                for entry in entries:
                    name = entry.get("name") or "<unnamed>"
                    extraction.inventory_items.append(SourceInventoryItem(
                        domain=tag,
                        source_path=f"{scope.kind}[@name='{scope.name}']/{tag}/entry[@name='{name}']",
                        name=name,
                        status=status,
                        notes=[f"Unhandled PAN-OS feature: {tag}"]
                    ))
            else:
                extraction.inventory_items.append(SourceInventoryItem(
                    domain=tag,
                    source_path=f"{scope.kind}[@name='{scope.name}']/{tag}",
                    name=tag,
                    status=status,
                    notes=[f"Unhandled PAN-OS feature subtree: {tag}"]
                ))
