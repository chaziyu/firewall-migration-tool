import json

with open('scratch/parser_history.jsonl', 'r', encoding='utf-8') as f:
    lines = f.readlines()

latest_content = None
for line in lines:
    try:
        data = json.loads(line)
        # Handle tool calls
        if 'tool_calls' in data:
            for tc in data['tool_calls']:
                args = tc.get('arguments', {})
                tf = args.get('TargetFile', '') or args.get('target_file', '')
                if 'parser.py' in tf:
                    if tc['name'] == 'write_to_file':
                        latest_content = args.get('CodeContent', '')
    except Exception as e:
        pass

if latest_content:
    with open('scratch/recovered_parser.py', 'w', encoding='utf-8') as out:
        out.write(latest_content)
    print("Recovered parser.py to scratch/recovered_parser.py")
else:
    print("Could not find full write_to_file for parser.py")
