import json
import glob
import os

# Start with a clean checkout of parser.py
os.system("git restore src/fwmigrate/parsers/palo_alto/parser.py")

with open("src/fwmigrate/parsers/palo_alto/parser.py", "r", encoding="utf-8") as f:
    content = f.read()

def apply_chunk(text, target, replacement):
    # exact string replacement
    return text.replace(target, replacement)

dumps = sorted(glob.glob("scratch/transcript_dumps/dump_*.json"), key=lambda x: int(x.split('_')[2].split('.')[0]))

# I will apply up to the point just before my own tool calls today.
# My tool calls today were fixing NAT and Routing. So I'll apply the first ones that modify parser.py.
for dump in dumps:
    with open(dump, "r", encoding="utf-8") as f:
        tc = json.load(f)
    
    args = tc.get("args", {})
    tf = args.get("TargetFile", "") or args.get("target_file", "")
    if "parser.py" not in tf:
        continue
        
    print(f"Applying {dump}: {tc['name']}")
    
    if tc["name"] == "replace_file_content":
        target = args.get("TargetContent", "")
        repl = args.get("ReplacementContent", "")
        content = apply_chunk(content, target, repl)
    elif tc["name"] == "multi_replace_file_content":
        chunks = args.get("ReplacementChunks", [])
        for chunk in chunks:
            target = chunk.get("TargetContent", "")
            repl = chunk.get("ReplacementContent", "")
            content = apply_chunk(content, target, repl)

with open("src/fwmigrate/parsers/palo_alto/parser.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Done recovering parser.py")
