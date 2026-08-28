import json
import os

transcript_path = r'C:\Users\ziyu.cha-c\.gemini\antigravity-ide\brain\54ca61b6-9f20-44f4-9a86-1dbf090b6464\.system_generated\logs\transcript_full.jsonl'
output_dir = 'scratch/transcript_dumps'
os.makedirs(output_dir, exist_ok=True)

counter = 0
with open(transcript_path, 'r', encoding='utf-8') as f:
    for line in f:
        try:
            data = json.loads(line)
            if 'tool_calls' in data:
                for tc in data['tool_calls']:
                    if tc['name'] in ['multi_replace_file_content', 'replace_file_content', 'write_to_file']:
                        args = tc.get('arguments', {})
                        tf = args.get('TargetFile', '') or args.get('target_file', '')
                        if 'parser.py' in tf:
                            counter += 1
                            with open(f'{output_dir}/dump_{counter}.json', 'w', encoding='utf-8') as out:
                                json.dump(args, out, indent=2)
        except Exception:
            pass

print(f"Dumped {counter} tool calls targeting parser.py")
