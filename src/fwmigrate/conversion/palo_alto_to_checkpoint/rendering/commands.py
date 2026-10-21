"""Render new-package operations for an existing, manually opened API session."""

import shlex


def render_management_commands(operations):
    lines = ["#!/usr/bin/env bash", "set -euo pipefail",
             '# Usage: bash checkpoint_management.sh /path/to/existing-session.json',
             '# Log in to the intended Management Domain first. Requires mgmt_cli and jq.',
             '# Stops on errors. Does not log in, publish, install policy, or save Gaia configuration.',
             'session_file=${1:?Provide the existing Management API session file}',
             'command -v mgmt_cli >/dev/null', 'command -v jq >/dev/null']
    bindings = {}

    def parameters(value, prefix=""):
        if isinstance(value, dict):
            if set(value) == {"$response_binding"}:
                variable = bindings[value["$response_binding"]]
                return [shlex.quote(prefix), f'"${{{variable}}}"']
            return [word for key, child in value.items()
                    for word in parameters(child, f"{prefix}.{key}" if prefix else key)]
        if isinstance(value, list):
            return [word for index, child in enumerate(value, 1)
                    for word in parameters(child, f"{prefix}.{index}")]
        text = str(value).lower() if isinstance(value, bool) else str(value)
        return [shlex.quote(prefix), shlex.quote(text)]

    for index, operation in enumerate(operations):
        command = operation["path"].removeprefix("/web_api/").replace("add-", "add ", 1).replace("set-", "set ", 1)
        words = parameters(operation["request_body_template"])
        invocation = 'mgmt_cli -s "$session_file" --version 1.8.1 --format json ' + command + " " + " ".join(words)
        binding = operation["response_binding"]
        if binding["json_pointer"] == "/access-layers/0/uid":
            query = '.["access-layers"] | if length == 1 then .[0].uid else error("Expected one new access layer") end'
        elif binding["json_pointer"] == "/uid":
            query = ".uid"
        else:
            raise ValueError("Unverified Check Point command response binding")
        query += ' | select(type == "string" and length > 0)'
        variable = f"cp_uid_{index}"
        lines.append(f"{variable}=$({invocation} | jq -er {shlex.quote(query)})")
        bindings[binding["binding_id"]] = variable
    return "\n".join(lines) + "\n"
