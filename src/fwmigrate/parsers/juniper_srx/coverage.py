"""Extraction coverage and accounting builder for Juniper SRX JunOS configurations."""

from __future__ import annotations

from collections import defaultdict
from typing import List, Sequence

from fwmigrate.extraction.models import (
    ExtractionResult,
    ExtractionStatus,
    SourceCommand,
    SourceInventoryItem,
    SourceSectionResult,
    UnsupportedItem,
)
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, JunosOperation


def get_command_section_path(cmd: JunosCommand) -> str:
    """Determine the hierarchy section path for a Junos set/activate/deactivate command."""
    if len(cmd.tokens) < 2:
        return "root"

    # Skip operation token (set/activate/deactivate)
    toks = cmd.tokens[1:]
    first = toks[0].lower()

    if first == "logical-systems" and len(toks) > 2:
        # e.g. logical-systems LS1 security policies ... -> logical-systems LS1 security policies
        sub_path = get_command_section_path(
            JunosCommand(
                operation=cmd.operation,
                tokens=[cmd.tokens[0]] + toks[2:],
                raw_sanitized=cmd.raw_sanitized,
                line_number=cmd.line_number,
            )
        )
        return f"logical-systems {toks[1]} {sub_path}"

    if first == "tenants" and len(toks) > 2:
        sub_path = get_command_section_path(
            JunosCommand(
                operation=cmd.operation,
                tokens=[cmd.tokens[0]] + toks[2:],
                raw_sanitized=cmd.raw_sanitized,
                line_number=cmd.line_number,
            )
        )
        return f"tenants {toks[1]} {sub_path}"

    if first == "security":
        if len(toks) > 1:
            second = toks[1].lower()
            if second in ("zones", "policies", "address-book", "nat", "ike", "ipsec", "utm", "screen"):
                return f"security {second}"
            return f"security {second}"
        return "security"

    if first == "routing-options":
        if len(toks) > 1:
            return f"routing-options {toks[1].lower()}"
        return "routing-options"

    if first == "routing-instances":
        if len(toks) > 2:
            return f"routing-instances {toks[1]}"
        return "routing-instances"

    if first in ("interfaces", "applications", "schedulers", "system", "version", "chassis", "protocols", "snmp"):
        return first

    return first


def build_extraction_result(
    commands: Sequence[JunosCommand],
    canonical_ir: IRConfig,
) -> ExtractionResult:
    """
    Construct the authoritative ExtractionResult accounting for 100% of input JunOS commands.
    Ensures zero silent data loss.
    """
    section_commands: dict[str, List[JunosCommand]] = defaultdict(list)
    for cmd in commands:
        path = get_command_section_path(cmd)
        section_commands[path].append(cmd)

    source_sections: List[SourceSectionResult] = []
    inventory_items: List[SourceInventoryItem] = []
    unsupported_items: List[UnsupportedItem] = []

    for path, cmds in section_commands.items():
        line_start = min(c.line_number for c in cmds)
        line_end = max(c.line_number for c in cmds)

        # Determine overall section status
        statuses = [c.extraction_status or (ExtractionStatus.NORMALIZED if c.consumed else ExtractionStatus.UNSUPPORTED) for c in cmds]
        if any(s == ExtractionStatus.PARSE_ERROR for s in statuses):
            section_status = ExtractionStatus.PARSE_ERROR
        elif any(s == ExtractionStatus.UNSUPPORTED for s in statuses):
            section_status = (
                ExtractionStatus.PARTIALLY_NORMALIZED
                if any(s in (ExtractionStatus.NORMALIZED, ExtractionStatus.PARTIALLY_NORMALIZED) for s in statuses)
                else ExtractionStatus.UNSUPPORTED
            )
        elif any(s == ExtractionStatus.PARTIALLY_NORMALIZED for s in statuses):
            section_status = ExtractionStatus.PARTIALLY_NORMALIZED
        elif any(s == ExtractionStatus.EXTRACT_ONLY for s in statuses):
            section_status = ExtractionStatus.EXTRACT_ONLY
        elif any(s == ExtractionStatus.VENDOR_EXTENSION for s in statuses):
            section_status = ExtractionStatus.VENDOR_EXTENSION
        else:
            section_status = ExtractionStatus.NORMALIZED

        source_sections.append(
            SourceSectionResult(
                path=path,
                present=True,
                line_start=line_start,
                line_end=line_end,
                object_count_source=len(cmds),
                object_count_parsed=sum(1 for c in cmds if c.consumed),
                object_count_normalized=sum(
                    1 for c in cmds if c.extraction_status == ExtractionStatus.NORMALIZED
                ),
                status=section_status,
                parser_handler=cmds[0].handler if cmds else None,
            )
        )

        source_cmds: List[SourceCommand] = []
        for c in cmds:
            status = c.extraction_status or (
                ExtractionStatus.NORMALIZED if c.consumed else ExtractionStatus.UNSUPPORTED
            )
            op = c.operation.value if isinstance(c.operation, JunosOperation) else str(c.operation)
            key = " ".join(c.tokens[1:3]) if len(c.tokens) > 2 else (c.tokens[1] if len(c.tokens) > 1 else "")
            values = c.tokens[3:] if len(c.tokens) > 3 else []
            source_cmds.append(
                SourceCommand(
                    operation=op,
                    key=key,
                    values=values,
                    line_number=c.line_number,
                    status=status,
                    parser_handler=c.handler,
                    requires_manual_review=c.requires_manual_review or status in (ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARTIALLY_NORMALIZED, ExtractionStatus.PARSE_ERROR),
                )
            )

            if status in (ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARSE_ERROR) or c.access_denied:
                reason = (
                    "Source configuration was hidden by Junos permissions (ACCESS-DENIED)"
                    if c.access_denied
                    else c.parse_error or f"Unsupported Junos hierarchy command in section '{path}'"
                )
                unsupported_items.append(
                    UnsupportedItem(
                        source_path=path,
                        source_name=" ".join(c.tokens[:4]) if len(c.tokens) >= 4 else path,
                        reason=reason,
                        requires_manual_review=True,
                        raw_capture=c.raw_sanitized,
                    )
                )

        inventory_items.append(
            SourceInventoryItem(
                domain="juniper_srx",
                source_path=path,
                name=path,
                commands=source_cmds,
                status=section_status,
                requires_manual_review=any(sc.requires_manual_review for sc in source_cmds),
            )
        )

    return ExtractionResult(
        canonical_ir=canonical_ir,
        source_sections=source_sections,
        inventory_items=inventory_items,
        unsupported_items=unsupported_items,
    )


def assert_no_silent_loss(
    extraction_result: ExtractionResult,
    total_input_commands: int | None = None,
    expected_unsupported: int = 0,
) -> None:
    """
    Assert that 100% of input JunOS commands are categorized into valid extraction statuses
    with zero silent data loss.
    """
    total_commands = 0
    status_counts: dict[ExtractionStatus, int] = defaultdict(int)

    for item in extraction_result.inventory_items:
        for cmd in item.commands:
            total_commands += 1
            assert cmd.status is not None, f"Command at line {cmd.line_number} has no extraction status"
            assert isinstance(cmd.status, ExtractionStatus), f"Command at line {cmd.line_number} status is not ExtractionStatus"
            status_counts[cmd.status] += 1

    if total_input_commands is not None:
        assert total_commands == total_input_commands, (
            f"Command count mismatch: inventory has {total_commands} commands, "
            f"expected {total_input_commands}"
        )

    accounted_sum = sum(status_counts.values())
    assert accounted_sum == total_commands, "Not all commands were accounted for"

    if expected_unsupported > 0:
        actual_unsupported = (
            status_counts[ExtractionStatus.UNSUPPORTED]
            + status_counts[ExtractionStatus.PARSE_ERROR]
        )
        assert actual_unsupported == expected_unsupported, (
            f"Expected {expected_unsupported} unsupported/parse-error commands, got {actual_unsupported}"
        )
