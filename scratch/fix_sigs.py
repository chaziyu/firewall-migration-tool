import re

with open("src/fwmigrate/parsers/palo_alto/parser.py", "r", encoding="utf-8") as f:
    content = f.read()

def replacer(match):
    func_name = match.group(1)
    return f"def {func_name}(self, scope: PANScope, search_root: ET.Element, extraction: ExtractionResult):\n        ir = extraction.canonical_ir"

content = re.sub(
    r"def (_parse_[a-zA-Z0-9_]+)\(self, scope: PANScope, search_root: ET\.Element, ir: IRConfig\):",
    replacer,
    content
)

with open("src/fwmigrate/parsers/palo_alto/parser.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Fixed signatures")
