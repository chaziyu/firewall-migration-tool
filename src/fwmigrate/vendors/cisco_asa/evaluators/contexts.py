"""ASA contexts command evaluation."""

from __future__ import annotations

from typing import Dict, List, Optional
from fwmigrate.vendors.cisco_asa.model.context import CiscoASAContext, CiscoAllocatedInterface


from fwmigrate.extraction.sanitize import sanitize_raw_text


class ContextsEvaluator:

    def _context_definition(self, name: str, line: str) -> CiscoASAContext:
        context = next((item for item in self.config.contexts if item.name == name), None)
        if context is None:
            context = CiscoASAContext(name=name, raw_lines=[line], source_attributes={"raw_command": line, "raw_commands": [line]})
            self.config.contexts.append(context)
        else:
            context.raw_lines.append(line)
            context.source_attributes.setdefault("raw_commands", []).append(line)
        return context

    @staticmethod
    def _build_context_ownership(lines: List[str]) -> Dict[int, Optional[str]]:
        from ..parser_mpf import _build_context_ownership
        return _build_context_ownership(lines)

    def _parse_context_command(self, line, line_number):
        lower = line.lower()
        if lower.startswith("context "):
            name = line.split()[1] if len(line.split()) > 1 else "unknown"
            self._context_definition(name, line)
        elif lower == "admin-context" or lower in {"allocate-interface", "config-url", "resource-class"} or lower.startswith(("allocate-interface ", "config-url ", "admin-context ", "resource-class ")):
            if not self.config.contexts:
                self._record_unsupported(line_number, line, "ASA context command has no owning context definition")
                return
            context = self.config.contexts[-1]
            context.raw_lines.append(line)
            context.source_attributes.setdefault("raw_commands", []).append(line)
            if lower == "allocate-interface" or lower.startswith("allocate-interface "):
                parts = line.split()
                if len(parts) > 1:
                    context.allocated_interfaces.append(parts[1])
                    context.allocated_interface_entries.append(CiscoAllocatedInterface(
                        physical_interface=parts[1], mapped_name=parts[2] if len(parts) > 2 else None,
                        range_expression=parts[1] if "-" in parts[1] else None,
                        source_order=line_number, raw=sanitize_raw_text(line),
                        explicit_fields={"physical_interface", "mapped_name"} if len(parts) > 2 else {"physical_interface"},
                    ))
                else:
                    context.extraction_status = "PARSE_ERROR"
                    context.requires_manual_review = True
                    context.review_reasons.append("Malformed allocate-interface command")
                    self._record_diagnostic(line_number, line, "Malformed allocate-interface command", "context", context.name)
            elif lower == "config-url" or lower.startswith("config-url "):
                parts = line.split(maxsplit=1)
                if len(parts) > 1:
                    context.config_url = parts[1]
                else:
                    context.extraction_status = "PARSE_ERROR"
                    context.requires_manual_review = True
                    context.review_reasons.append("Malformed config-url command")
                    self._record_diagnostic(line_number, line, "Malformed config-url command", "context", context.name)
            elif lower == "resource-class" or lower.startswith("resource-class "):
                parts = line.split(maxsplit=1)
                if len(parts) > 1:
                    context.resource_class = parts[1]
                else:
                    context.extraction_status = "PARSE_ERROR"
                    context.requires_manual_review = True
                    context.review_reasons.append("Malformed resource-class command")
                    self._record_diagnostic(line_number, line, "Malformed resource-class command", "context", context.name)
            else:
                context.admin_context = True
