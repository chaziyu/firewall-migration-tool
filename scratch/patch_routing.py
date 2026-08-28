import re

with open("src/fwmigrate/parsers/palo_alto/parser.py", "r", encoding="utf-8") as f:
    content = f.read()

import_stmt = "from .routing import PANRouteExtractor\n"
if "PANRouteExtractor" not in content:
    content = content.replace("from .nat import PANNatRuleExtractor, PANSourceTranslation, PANDestinationTranslation", "from .nat import PANNatRuleExtractor\n" + import_stmt)

new_routes = '''    def _parse_routes(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):
        PANRouteExtractor.extract_static_routes(scope, search_root, extraction)'''

content = re.sub(r'    def _parse_routes\(self, scope: PANScope, search_root: ET\.Element, extraction: ExtractionResult\):.*?$', new_routes, content, flags=re.DOTALL)

with open("src/fwmigrate/parsers/palo_alto/parser.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Patched routing")
