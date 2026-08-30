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


# High-confidence PAN-OS predefined App-IDs.  This is intentionally a name
# catalog only: it does not invent ports, risk, category, technology, or
# content-version metadata.  Custom configured objects still win first in the
# resolver, so a local object can safely shadow a built-in name.
PREDEFINED_APPLICATION_NAMES = frozenset({
    "ssl", "web-browsing", "dns", "ping", "ssh", "ftp", "ftp-data", "tftp",
    "telnet", "smtp", "smtps", "imap", "imaps", "pop3", "pop3s", "http",
    "https", "ntp", "snmp", "snmp-trap", "dhcp", "dhcpv6", "rdp", "ms-rdp",
    "smb", "ms-ds-smb", "msrpc", "kerberos", "ldap", "ldaps", "radius",
    "tacacs", "ike", "ipsec", "gre", "esp", "ah", "icmp", "ipv6-icmp",
    "traceroute", "sqlnet", "mysql", "ms-sql", "postgresql", "oracle",
    "ssh-tunnel", "websocket", "websocket-base", "google-base", "google-drive",
    "gmail", "youtube", "facebook", "twitter", "linkedin", "github",
    "office365", "ms-office365", "ms-update", "windows-update", "apple-update",
    "dropbox", "boxnet", "salesforce", "webex", "zoom", "skype", "teams",
    "slack", "bitbucket", "gitlab", "amazon", "amazon-aws", "azure",
    "google-cloud", "okta", "saml", "ntlm", "sccm", "wsus", "citrix",
    "vnc", "pcanywhere", "sip", "rtsp", "rtp", "h323", "bittorrent",
    "ssl-tlsv1-2", "quic", "tcp", "udp", "icmpv6",
})


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
