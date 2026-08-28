import json

with open('scratch/transcript_parser.jsonl', 'r', encoding='utf-8') as f:
    for line in f:
        data = json.loads(line)
        if 'tool_calls' in data:
            for tc in data['tool_calls']:
                if tc['name'] in ['multi_replace_file_content', 'replace_file_content', 'write_to_file']:
                    args = tc.get('arguments', {})
                    tf = args.get('TargetFile', '')
                    if 'parser.py' in tf:
                        print("Found tool call targeting parser.py")
                        with open('scratch/recover_parser.py', 'w', encoding='utf-8') as out:
                            out.write(json.dumps(args, indent=2))
