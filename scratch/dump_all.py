import json
import os

transcript_path = r'C:\Users\ziyu.cha-c\.gemini\antigravity-ide\brain\54ca61b6-9f20-44f4-9a86-1dbf090b6464\.system_generated\logs\transcript_full.jsonl'
output_dir = 'scratch/transcript_dumps'
os.makedirs(output_dir, exist_ok=True)

counter = 0
with open(transcript_path, 'r', encoding='utf-8') as f:
    for line in f:
        if 'parser.py' in line and ('replace_file_content' in line or 'write_to_file' in line):
            try:
                data = json.loads(line)
                if 'tool_calls' in data:
                    for tc in data['tool_calls']:
                        if tc['name'] in ['multi_replace_file_content', 'replace_file_content', 'write_to_file']:
                            counter += 1
                            with open(f'{output_dir}/dump_{counter}.json', 'w', encoding='utf-8') as out:
                                json.dump(tc, out, indent=2)
            except Exception as e:
                pass

print(f"Dumped {counter} tool calls.")
