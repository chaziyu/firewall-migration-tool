"""Offline assembler for already-collected Check Point Management API responses."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from fwmigrate.parsers.checkpoint.loader import canonicalize_command


def build_checkpoint_bundle(
    response_files: List[Path],
    *,
    command_metadata: Optional[Mapping[str, Mapping[str, Any]]] = None,
    domain: Optional[str] = None,
    package: Optional[str] = None,
    layer: Optional[str] = None,
    gateway: Optional[str] = None,
    output_file: Optional[Path] = None,
) -> Dict[str, Any]:
    """Build checkpoint-export-v1 without credentials, API calls, or source reinterpretation."""
    responses: List[Dict[str, Any]] = []
    metadata = command_metadata or {}
    for source_path in response_files:
        path = Path(source_path)
        per_file = dict(metadata.get(str(path), metadata.get(path.name, {})))
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("response JSON root is not an object")
            command = canonicalize_command(
                str(per_file.get("command") or payload.get("command") or path.stem)
            )
            data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
            response = {
                "command": command,
                "domain": per_file.get("domain", payload.get("domain", domain)),
                "package": per_file.get("package", payload.get("package", package)),
                "layer": per_file.get("layer", payload.get("layer", layer)),
                "gateway": per_file.get("gateway", payload.get("gateway", gateway)),
                "collection_status": payload.get("collection_status", "OK"),
                "data": data,
            }
            for key in ("from", "to", "total"):
                value = per_file.get(key, payload.get(key, data.get(key)))
                if value is not None:
                    response[key] = value
            if payload.get("error"):
                response["error"] = payload["error"]
                response["collection_status"] = "ERROR"
            responses.append(response)
        except Exception as exc:
            responses.append({
                "command": canonicalize_command(str(per_file.get("command") or path.stem)),
                "domain": per_file.get("domain", domain),
                "package": per_file.get("package", package),
                "layer": per_file.get("layer", layer),
                "gateway": per_file.get("gateway", gateway),
                "collection_status": "ERROR",
                "error": f"Failed to load {path.name}: {exc}",
                "data": {},
            })

    bundle: Dict[str, Any] = {
        "format": "checkpoint-export-v1",
        "domain": domain,
        "gateway": gateway,
        "selected_domain": domain,
        "selected_package": package,
        "selected_access_layer": layer,
        "selected_gateway": gateway,
        "responses": responses,
    }
    if output_file is not None:
        Path(output_file).write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return bundle
