"""Render reviewed FMC REST API operations as an offline curl shell script."""

import json
import re


def render_fmc_curl_commands(operations):
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "# Usage: bash cisco_fmc_curl.sh <FMC_HOST> <AUTH_TOKEN>",
        "# Executes reviewed Cisco FMC REST API operations in dependency order.",
        "# Requires curl and jq. Does not authenticate, deploy, or assign interfaces.",
        'FMC_HOST=${1:?Provide the FMC hostname or IP}',
        'AUTH_TOKEN=${2:?Provide the FMC X-auth-access-token}',
        "command -v curl >/dev/null",
        "command -v jq >/dev/null",
    ]
    bindings = {}

    for index, operation in enumerate(operations):
        variable = f"fmc_id_{index}"
        binding = operation.get("response_binding")
        if binding:
            bindings[binding["binding_id"]] = variable

        # Resolve path response bindings
        path = operation["path"]
        for bind_id, var_name in bindings.items():
            pattern = r"\{\$response_binding:\s*" + re.escape(bind_id) + r"\}"
            path = re.sub(pattern, f"${{{var_name}}}", path)

        # Build body with resolved response bindings
        def resolve_body_bindings(val):
            if isinstance(val, dict):
                if set(val) == {"$response_binding"}:
                    var = bindings.get(val["$response_binding"])
                    return f"__BINDING_VAR__{var}__"
                return {k: resolve_body_bindings(v) for k, v in val.items()}
            if isinstance(val, (tuple, list)):
                return [resolve_body_bindings(item) for item in val]
            return val

        resolved_body = resolve_body_bindings(operation["request_body_template"])
        body_json = json.dumps(resolved_body, ensure_ascii=False)
        # Substitute __BINDING_VAR__var__ with $var in JSON string
        body_json_shell = re.sub(r'"__BINDING_VAR__([a-zA-Z0-9_]+)__"', r'"$\1"', body_json)

        lines.append(
            f'{variable}=$(curl -k -s -S -X POST "https://${{FMC_HOST}}{path}" '
            f'-H "X-auth-access-token: ${{AUTH_TOKEN}}" '
            f'-H "Content-Type: application/json" '
            f"-d '{body_json_shell}' | jq -er '(.id // .items[0].id) | select(type == \"string\" and length > 0)')"
        )

    return "\n".join(lines) + "\n"
