import re

with open('scratch/patch_nat.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('open("src/fwmigrate/parsers/palo_alto/parser.py", "r")', 'open("src/fwmigrate/parsers/palo_alto/parser.py", "r", encoding="utf-8")')
text = text.replace('open("src/fwmigrate/parsers/palo_alto/parser.py", "w")', 'open("src/fwmigrate/parsers/palo_alto/parser.py", "w", encoding="utf-8")')

with open('scratch/patch_nat.py', 'w', encoding='utf-8') as f:
    f.write(text)

with open('scratch/patch_routing.py', 'r', encoding='utf-8') as f:
    text2 = f.read()

text2 = text2.replace('open("src/fwmigrate/parsers/palo_alto/parser.py", "r")', 'open("src/fwmigrate/parsers/palo_alto/parser.py", "r", encoding="utf-8")')
text2 = text2.replace('open("src/fwmigrate/parsers/palo_alto/parser.py", "w")', 'open("src/fwmigrate/parsers/palo_alto/parser.py", "w", encoding="utf-8")')
text2 = text2.replace('content.replace("from .nat import PANNatRuleExtractor",', 'content.replace("from .nat import PANNatRuleExtractor, PANSourceTranslation, PANDestinationTranslation",')

with open('scratch/patch_routing.py', 'w', encoding='utf-8') as f:
    f.write(text2)

print("Fixed patch scripts")
