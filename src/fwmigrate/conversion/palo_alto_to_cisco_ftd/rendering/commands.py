"""Render a target-bound offline application script with structured HTTPS requests."""

import json


# Keep the historical shell filename; Python handles JSON and response bindings.
# No source or target text is interpolated into shell commands or Python code.
_RUNNER = r'''
import getpass
import json
from pathlib import Path
import re
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.request import build_opener, HTTPRedirectHandler, HTTPSHandler, Request
from uuid import UUID

SPEC = json.loads(_REVIEWED_SPEC_)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def resolve(value, bindings):
    if isinstance(value, dict):
        if set(value) == {"$response_binding"}:
            return bindings[value["$response_binding"]]
        return {key: resolve(child, bindings) for key, child in value.items()}
    if isinstance(value, list):
        return [resolve(child, bindings) for child in value]
    return value


def response_id(response, pointer):
    value = response
    for token in pointer.removeprefix("/").split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        value = value[int(token)] if isinstance(value, list) else value[token]
    # Returned identifiers enter URL paths as well as JSON bodies.
    if not isinstance(value, str):
        raise ValueError("Invalid FMC response identifier")
    return str(UUID(value))


def main():
    operations = SPEC["operations"]
    if not operations:
        raise ValueError("No approved FMC operations")
    if len(sys.argv) > 2:
        raise ValueError("Usage: bash cisco_fmc_curl.sh [TOKEN_FILE]")
    host, domain = SPEC["manager_target"], SPEC["domain_id"]
    prefix = "/api/fmc_config/v1/domain/" + str(UUID(domain)) + "/"
    pattern = re.compile(r"\{\$response_binding:\s*([^{}]+?)\s*\}")
    # Preflight the whole dependency sequence before any network request.
    known = {}
    for operation in operations:
        if operation["method"] != "POST" or not operation["path"].startswith(prefix):
            raise ValueError("Operation is outside the approved FMC domain")
        path = pattern.sub(lambda match: known[match[1]], operation["path"])
        if any(part in path for part in ("{", "}", "?", "#", "..")):
            raise ValueError("Invalid FMC operation path")
        resolve(operation["request_body_template"], known)
        binding = operation.get("response_binding")
        if binding:
            if binding["binding_id"] in known or not binding["json_pointer"].startswith("/"):
                raise ValueError("Invalid FMC response binding")
            known[binding["binding_id"]] = "00000000-0000-0000-0000-000000000001"

    token = (Path(sys.argv[1]).read_text(encoding="utf-8").strip() if len(sys.argv) == 2
             else getpass.getpass("FMC access token: "))
    if not token or any(ord(char) < 32 or ord(char) > 126 for char in token):
        raise ValueError("Invalid FMC access token")
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    bindings = {}
    for index, operation in enumerate(operations, 1):
        path = pattern.sub(lambda match: bindings[match[1]], operation["path"])
        body = resolve(operation["request_body_template"], bindings)
        request = Request("https://" + host + path,
                          data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                          headers={"X-auth-access-token": token, "Content-Type": "application/json"},
                          method=operation["method"])
        with opener.open(request, timeout=30) as response:
            if not 200 <= response.status < 300:
                raise ValueError("FMC returned an unsuccessful response")
            payload = json.load(response)
        binding = operation.get("response_binding")
        if binding:
            bindings[binding["binding_id"]] = response_id(payload, binding["json_pointer"])
        print("Applied FMC operation " + str(index) + "/" + str(len(operations)))


if __name__ == "__main__":
    try:
        main()
    except HTTPError as error:
        raise SystemExit("FMC HTTP error " + str(error.code) + ". Stop and reconcile partial changes before retrying.") from None
    except (URLError, OSError, ValueError, KeyError, TypeError, IndexError, EOFError):
        raise SystemExit("FMC application stopped: invalid input, response or connection. Reconcile partial changes before retrying.") from None
'''


def render_fmc_curl_commands(operations, *, manager_target=None, domain_id=None):
    if operations and (not manager_target or not domain_id):
        raise ValueError("Explicit FMC manager and domain UUID are required for application")
    specification = json.dumps({"manager_target": manager_target, "domain_id": domain_id,
                                "operations": operations}, ensure_ascii=True)
    runner = _RUNNER.replace("_REVIEWED_SPEC_", repr(specification))
    return (
        "#!/usr/bin/env bash\nset -euo pipefail\n"
        "# Usage: bash cisco_fmc_curl.sh [TOKEN_FILE]\n"
        "# Requires Python 3.11+. Otherwise prompts privately for the access token.\n"
        "# Uses the approved host/domain, verified TLS, and no redirects or automatic retries.\n"
        "# Does not authenticate, assign interfaces or policies, or deploy.\n"
        "exec python3 - \"$@\" <<'FWMIGRATE_FMC_PY'\n"
        + runner + "\nFWMIGRATE_FMC_PY\n"
    )
