from __future__ import annotations

import re
from dataclasses import dataclass

from ..nodes import FortiGateConfigTree


_CONFIG_VERSION = re.compile(
    r"^#config-version=([^-\s]+)-(\d+\.\d+\.\d+)-FW-(build\d+)(?:-|:|$)"
)
_SERIAL_HEADER = re.compile(r"^#serial_number=([A-Za-z0-9]+)")


@dataclass(frozen=True, slots=True)
class FortiGateSourceMetadata:
    fortios_version: str | None = None
    hardware_model: str | None = None
    firmware_build: str | None = None
    serial_number: str | None = None


def capture_source_metadata(tree: FortiGateConfigTree) -> FortiGateSourceMetadata:
    fortios_version: str | None = None
    hardware_model: str | None = None
    firmware_build: str | None = None
    serial_number: str | None = None

    for comment in tree.comments:
        if fortios_version is None:
            match = _CONFIG_VERSION.match(comment.value)
            if match:
                hardware_model = match.group(1)
                fortios_version = match.group(2)
                firmware_build = match.group(3)
        if serial_number is None:
            sn_match = _SERIAL_HEADER.match(comment.value)
            if sn_match:
                serial_number = sn_match.group(1)

    return FortiGateSourceMetadata(
        fortios_version=fortios_version,
        hardware_model=hardware_model,
        firmware_build=firmware_build,
        serial_number=serial_number,
    )
