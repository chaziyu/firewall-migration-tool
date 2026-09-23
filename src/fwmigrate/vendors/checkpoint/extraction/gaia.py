from __future__ import annotations

from typing import Iterable, Type

from fwmigrate.extraction.sanitize import sanitize_raw_text, sanitize_source_attributes

from ..gaia.parser import parse_gaia
from ..model.common import CheckPointSourceObject
from ..model.gaia import (
    CPGaiaDHCPServer, CPGaiaInterface, CPGaiaRBAUserAssignment, CPGaiaRBARole,
    CPGaiaStaticRoute, CPGaiaUser, CPVTI,
)
from ..models import CheckPointResponse
from .common import build_source_inventory, build_typed_object
from .source_inventory import CheckPointSourceRecord


def extract_gaia_records(response: CheckPointResponse) -> Iterable[tuple[str, CheckPointSourceObject | CheckPointSourceRecord]]:
    text = response.data.get("cli_text", "")
    for index, parsed in enumerate(parse_gaia(text), 1):
        kind = str(parsed["kind"])
        safe = sanitize_source_attributes(dict(parsed))
        if isinstance(safe.get("tokens"), list):
            safe["tokens"] = sanitize_raw_text(" ".join(map(str, safe["tokens"])))
        model, bucket = _model_and_bucket(kind)
        if model is CheckPointSourceRecord:
            yield bucket, build_source_inventory(response, {**safe, "type": kind}, index)
            continue
        yield bucket, build_typed_object(response, {**safe, "type": kind}, model, index)


def _model_and_bucket(kind: str) -> tuple[Type[CheckPointSourceObject | CheckPointSourceRecord], str]:
    return {
        "interface": (CPGaiaInterface, "gaia_interfaces"),
        "static-route": (CPGaiaStaticRoute, "gaia_static_routes"),
        "dhcp-server": (CPGaiaDHCPServer, "gaia_dhcp_servers"),
        "user": (CPGaiaUser, "gaia_users"),
        "rba-role": (CPGaiaRBARole, "gaia_rba_roles"),
        "rba-user-assignment": (CPGaiaRBAUserAssignment, "gaia_rba_user_assignments"),
        "vti": (CPVTI, "vtis"),
    }.get(kind, (CheckPointSourceRecord, "source_inventory"))
