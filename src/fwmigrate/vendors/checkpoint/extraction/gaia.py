from __future__ import annotations

from typing import Iterable

from fwmigrate.extraction.sanitize import sanitize_source_attributes

from ..models import CheckPointResponse
from ..source_model import CheckPointSourceRecord
from ..gaia.parser import parse_gaia


def extract_gaia_records(response: CheckPointResponse) -> Iterable[tuple[str, CheckPointSourceRecord]]:
    text = response.data.get("cli_text", "")
    for index, item in enumerate(parse_gaia(text), 1):
        kind = item["kind"]
        bucket = "gaia_routes" if kind == "static-route" else "gaia_interfaces" if kind == "interface" else "dns_ntp" if kind in {"dns", "ntp"} else "management_access"
        yield bucket, CheckPointSourceRecord(
            name=item.get("name"), object_type=kind, source_plane="gaia",
            command=response.command, domain=response.domain, gateway=response.gateway,
            order=index, source_attributes=sanitize_source_attributes(item),
        )
