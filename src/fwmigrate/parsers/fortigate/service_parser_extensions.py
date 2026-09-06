"""Focused FortiGate service/service-group parser extensions.

This module keeps Phase 26/27 behavior isolated from unrelated parser families:
- FortiOS service port expressions use ``destination[:source]`` ordering.
- quoted or unquoted multi-range values remain separate ordered ranges.
- malformed numeric service fields are retained as ``unparsed_*`` evidence.
- service-group ``member`` is explicitly a list field so set/append/unset use
  the parser's generic ordered-list mutation semantics.
"""

from __future__ import annotations

import re
from typing import Optional

from fwmigrate.parsers.fortigate.model import FGPortRange


def parse_service_port_ranges(value: Optional[str]) -> list[FGPortRange]:
    """Parse FortiOS custom-service port ranges without losing source semantics.

    FortiOS encodes a source-port constraint as ``destination:source``.  Each
    side may be a single port or a range.  Multiple expressions may arrive as
    comma-joined parser values or as one quoted whitespace-separated value.
    """

    ranges: list[FGPortRange] = []
    for original in re.split(r"[,\s]+", (value or "").strip()):
        original = original.strip()
        if not original:
            continue

        parts = original.split(":", 1)
        parsed: list[tuple[int, int]] = []
        valid = True
        for part in parts:
            bounds = part.split("-", 1)
            try:
                start = int(bounds[0])
                end = int(bounds[-1])
            except (TypeError, ValueError):
                valid = False
                break
            parsed.append((start, end))

        if not valid:
            ranges.append(FGPortRange(original=original))
            continue

        destination_start, destination_end = parsed[0]
        if len(parsed) == 1:
            ranges.append(
                FGPortRange(
                    original=original,
                    port=(
                        destination_start
                        if destination_start == destination_end
                        else None
                    ),
                    destination_start=destination_start,
                    destination_end=destination_end,
                )
            )
            continue

        source_start, source_end = parsed[1]
        ranges.append(
            FGPortRange(
                original=original,
                source_start=source_start,
                source_end=source_end,
                destination_start=destination_start,
                destination_end=destination_end,
            )
        )

    return ranges


def install_service_parser_extensions(parser_module) -> None:
    """Install Phase 26/27 behavior on the existing parser implementation."""

    parser_cls = parser_module.FortiGateParser
    parser_cls._parse_port_ranges = staticmethod(parse_service_port_ranges)

    # Make the service-group member contract explicit rather than relying on
    # the parser's broad fallback ``member`` list handling.
    parser_module.SECTION_LIST_FIELDS.setdefault(
        "firewall service group", set()
    ).add("member")

    if getattr(parser_cls.build_model, "_phase_26_27_wrapped", False):
        return

    original_build_model = parser_cls.build_model

    def build_model(self, section_path, attributes):
        if section_path == "firewall service custom":
            for field in ("protocol_number", "icmptype", "icmpcode", "color"):
                self._normalize_optional_int(attributes, field)
        elif section_path == "firewall service group":
            self._normalize_optional_int(attributes, "color")
        return original_build_model(self, section_path, attributes)

    build_model._phase_26_27_wrapped = True
    parser_cls.build_model = build_model
