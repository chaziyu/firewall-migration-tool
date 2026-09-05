"""Small, source-preserving resolver for Junos configuration groups."""

from __future__ import annotations

from collections import defaultdict
from typing import List

from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, JunosOperation, extract_value_list
from fwmigrate.extraction.models import ExtractionStatus


def resolve_group_commands(commands: List[JunosCommand]) -> List[JunosCommand]:
    groups: dict[tuple[tuple[str, ...], str], list[list[str]]] = defaultdict(list)
    applications: dict[tuple[str, ...], list[str]] = defaultdict(list)
    for command in commands:
        if command.operation != JunosOperation.SET:
            continue
        tokens = command.tokens[1:]
        group_index = next((i for i, token in enumerate(tokens) if token.lower() == "groups"), None)
        if group_index is not None and len(tokens) > group_index + 2:
            scope = tuple(tokens[:group_index])
            groups[(scope, tokens[group_index + 1].lower())].append(tokens[group_index + 2:])
            command.consumed = True
            command.handler = "groups"
            command.extraction_status = ExtractionStatus.EXTRACT_ONLY
        marker = next((i for i, token in enumerate(tokens) if token.lower() == "apply-groups"), None)
        if marker is not None:
            applications[tuple(tokens[:marker])].extend(extract_value_list(tokens[marker + 1:]))
            command.consumed = True
            command.handler = "groups"
            command.extraction_status = ExtractionStatus.EXTRACT_ONLY

    inherited: list[JunosCommand] = []
    for target, names in applications.items():
        for name in names:
            definitions = groups.get((target, name.lower()), []) or groups.get(((), name.lower()), [])
            for path in definitions:
                inherited.append(
                    JunosCommand(
                        operation=JunosOperation.SET,
                        tokens=["set", *target, *path],
                        raw_sanitized="set " + " ".join([*target, *path]),
                        line_number=0,
                        source_group=name,
                        synthetic=True,
                    )
                )
    return inherited + commands
