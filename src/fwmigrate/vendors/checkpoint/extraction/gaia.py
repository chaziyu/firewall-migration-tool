from __future__ import annotations

from typing import Any, Iterable, Type

from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes

from ..gaia import evaluate_gaia_commands, parse_gaia
from ..model.common import CheckPointSourceObject
from ..model.gaia import (
    CPGaiaDHCPServer, CPGaiaInterface, CPGaiaRBAUserAssignment, CPGaiaRBARole,
    CPGaiaStaticRoute, CPGaiaUser, CPVTI,
)
from ..models import CheckPointResponse
from .common import build_source_inventory, build_typed_object
from .source_inventory import CheckPointSourceRecord


def extract_gaia_records(response: CheckPointResponse) -> Iterable[tuple[str, CheckPointSourceObject | CheckPointSourceRecord]]:
    text = sanitize_raw_text(str(response.data.get("cli_text", "")))
    tree = parse_gaia(text)
    evaluations = evaluate_gaia_commands(tree)
    for index, evaluation in enumerate(evaluations, 1):
        kind = evaluation.kind
        if kind == "unsupported":
            yield "source_inventory", build_source_inventory(response, {
                "type": kind, "raw": sanitize_raw_text(str(evaluation.values.get("command", ""))),
            }, index)
            continue
        safe: dict[str, Any] = sanitize_source_attributes(dict(evaluation.values))
        safe["name"] = evaluation.identity
        safe["type"] = {"static-route-ipv4": "static-route", "static-route-ipv6": "static-route", "vpn-tunnel-vti": "vti"}.get(kind, {
            "gaia-user": "user", "gaia-rba-role": "rba-role", "gaia-rba-user-assignment": "rba-user-assignment",
        }.get(kind, kind))
        model, bucket = _model_and_bucket(kind)
        if model is CheckPointSourceRecord:
            yield bucket, build_source_inventory(response, safe, index)
            continue
        yield bucket, build_typed_object(response, safe, model, index)


def _model_and_bucket(kind: str) -> tuple[Type[CheckPointSourceObject | CheckPointSourceRecord], str]:
    return {
        "interface": (CPGaiaInterface, "gaia_interfaces"),
        "static-route-ipv4": (CPGaiaStaticRoute, "gaia_static_routes"),
        "static-route-ipv6": (CPGaiaStaticRoute, "gaia_static_routes"),
        "dhcp-server": (CPGaiaDHCPServer, "gaia_dhcp_servers"),
        "gaia-user": (CPGaiaUser, "gaia_users"),
        "gaia-rba-role": (CPGaiaRBARole, "gaia_rba_roles"),
        "gaia-rba-user-assignment": (CPGaiaRBAUserAssignment, "gaia_rba_user_assignments"),
        "vpn-tunnel-vti": (CPVTI, "vtis"),
    }.get(kind, (CheckPointSourceRecord, "source_inventory"))
