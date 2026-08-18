import xml.etree.ElementTree as ET
import json
from collections import defaultdict

def build_schema(element, path=""):
    # simplify path to avoid too many duplicate entry nodes
    tag = element.tag
    if tag == "entry" and path:
        # don't append entry if it's just a list item, or maybe keep it
        pass
    full_path = path + " -> " + tag if path else tag
    children_tags = set([child.tag for child in element])
    
    if children_tags:
        schema[full_path].update(children_tags)
    for child in element:
        build_schema(child, full_path)

tree = ET.parse('c:\\Users\\ziyu.cha-c\\Documents\\GitHub\\fortigate-to-palo\\Backup06082026')
root = tree.getroot()
schema = defaultdict(set)
build_schema(root)

schema_dict = {k: sorted(list(v)) for k, v in schema.items()}
with open('c:\\Users\\ziyu.cha-c\\Documents\\GitHub\\fortigate-to-palo\\pa_schema.json', 'w') as f:
    json.dump(schema_dict, f, indent=2)

print("Generated pa_schema.json")
