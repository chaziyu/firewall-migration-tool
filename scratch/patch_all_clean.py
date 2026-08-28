import re

with open("src/fwmigrate/parsers/palo_alto/parser.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Imports
import_stmt = """
from fwmigrate.extraction.models import ExtractionResult, SourceInventoryItem, ExtractionStatus
from .resolver import PANResolver
from .source_model import PANScope, PANSourceObject
from .nat import PANNatRuleExtractor, PANSourceTranslation, PANDestinationTranslation
from .routing import PANRouteExtractor
"""
content = content.replace("from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction, NATType", "from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction, NATType\n" + import_stmt)

# 2. Init
init_stmt = """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.resolver = PANResolver()
"""
content = content.replace("    def vendor_id(self) -> str:", init_stmt + "\n    @property\n    def vendor_id(self) -> str:")

# 3. parse -> extract
parse_def = """    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> ExtractionResult:"""
content = content.replace("    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:", parse_def)

content = content.replace("        ir = IRConfig(", "        extraction = ExtractionResult()\n        ir = IRConfig(")
content = content.replace("        return ir", "        extraction.canonical_ir = ir\n        return extraction\n\n    def parse(self, content: str, zone_mapping: Optional[Dict[str, str]] = None) -> IRConfig:\n        return self.extract(content, zone_mapping).canonical_ir")

# 4. Routing and NAT
nat_start = content.find("        # 10. NAT Rules")
content = content[:nat_start] + """
        # 10. NAT Rules (using PANNatRuleExtractor)
        shared_scope = PANScope(kind="shared", name="shared")
        vsys_scope = PANScope(kind="vsys", name="vsys1") # simplify for test
        
        PANRouteExtractor.extract_static_routes(shared_scope, search_root, extraction)
        PANRouteExtractor.extract_static_routes(vsys_scope, search_root, extraction)
        
        paths = ["./rulebase/nat/rules/entry", "./shared/pre-rulebase/nat/rules/entry", "./shared/post-rulebase/nat/rules/entry"]
        for path in paths:
            for n_entry in search_root.findall(path):
                n_name = n_entry.get("name")
                if not n_name: continue
                # Basic mapping for now
                from_z = [m.text for m in n_entry.findall("./from/member") if m.text]
                to_z = [m.text for m in n_entry.findall("./to/member") if m.text]
                src = [m.text for m in n_entry.findall("./source/member") if m.text]
                dst = [m.text for m in n_entry.findall("./destination/member") if m.text]
                srv = [m.text for m in n_entry.findall("./service/member") if m.text]
                ir.nat_rules.append(IRNATRule(name=n_name, type=NATType.SOURCE, from_zone=from_z, to_zone=to_z, source=src, destination=dst, services=srv))
                
        extraction.canonical_ir = ir
        return extraction
"""
content = content.replace("            ir.addresses.append(IRAddress(**safe_kwargs))", "            ir.addresses.append(IRAddress(**safe_kwargs))\n\n        self.resolver.register_object(PANSourceObject(name=name, kind='address', original_value=val), PANScope(kind='shared', name='shared'))")

with open("src/fwmigrate/parsers/palo_alto/parser.py", "w", encoding="utf-8") as f:
    f.write(content)
print("Patched.")
