from __future__ import annotations

import re
from dataclasses import dataclass

from ..nodes import FortiGateConfigTree


_CONFIG_VERSION = re.compile(
    r"^#config-version=[^-\s]+-(\d+\.\d+\.\d+)-FW-build\d+(?:-|:|$)"
)


@dataclass(frozen=True, slots=True)
class FortiGateSourceMetadata:
    fortios_version: str | None = None


def capture_source_metadata(tree: FortiGateConfigTree) -> FortiGateSourceMetadata:
    for comment in tree.comments:
        match = _CONFIG_VERSION.match(comment.value)
        if match:
            return FortiGateSourceMetadata(fortios_version=match.group(1))

    return FortiGateSourceMetadata()
