"""Conservative PAN-OS App-ID reference classification.

This intentionally is not an App-ID metadata database.  Names in this module
only identify references known to be built in; no ports, risk, category,
technology, dependencies, or version claims are inferred.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .source_model import PANScope


class PANApplicationReferenceState(str, Enum):
    CUSTOM_RESOLVED = "CUSTOM_RESOLVED"
    CUSTOM_UNRESOLVED = "CUSTOM_UNRESOLVED"
    PREDEFINED_REFERENCE = "PREDEFINED_REFERENCE"
    APPLICATION_GROUP_RESOLVED = "APPLICATION_GROUP_RESOLVED"
    APPLICATION_FILTER_REFERENCE = "APPLICATION_FILTER_REFERENCE"
    UNKNOWN_REFERENCE = "UNKNOWN_REFERENCE"


# Deliberately small, high-confidence names used by core PAN-OS policy examples.
PREDEFINED_APPLICATION_NAMES = frozenset({"ssl", "web-browsing", "dns", "ping", "ssh"})


@dataclass(frozen=True)
class PANApplicationReference:
    original_name: str
    classification: PANApplicationReferenceState
    resolved_name: Optional[str] = None
    resolved_scope: Optional[str] = None

    def as_evidence(self) -> dict:
        return {
            "original_name": self.original_name,
            "classification": self.classification.value,
            "resolved_name": self.resolved_name,
            "resolved_scope": self.resolved_scope,
        }


def classify_application_reference(name: str, scope: PANScope, resolver) -> PANApplicationReference:
    """Classify a policy reference, giving configured custom objects precedence."""
    resolved = resolver.resolve(name, "application-reference", scope)
    if resolved is not None:
        state = {
            "application": PANApplicationReferenceState.CUSTOM_RESOLVED,
            "application-group": PANApplicationReferenceState.APPLICATION_GROUP_RESOLVED,
            "application-filter": PANApplicationReferenceState.APPLICATION_FILTER_REFERENCE,
        }.get(resolved.kind, PANApplicationReferenceState.UNKNOWN_REFERENCE)
        return PANApplicationReference(
            original_name=name, classification=state,
            resolved_name=resolved.canonical_name or name,
            resolved_scope=(f"{resolved.scope.kind}:{resolved.scope.name}" if resolved.scope else None),
        )
    if name.lower() in PREDEFINED_APPLICATION_NAMES:
        return PANApplicationReference(name, PANApplicationReferenceState.PREDEFINED_REFERENCE, name)
    return PANApplicationReference(name, PANApplicationReferenceState.UNKNOWN_REFERENCE)
