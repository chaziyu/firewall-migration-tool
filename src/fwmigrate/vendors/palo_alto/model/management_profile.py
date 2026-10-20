"""Explicit device interface-management profile state."""
from pydantic import Field

from .common import PANNamedSourceModel


MANAGEMENT_PROTOCOLS = (
    'ping', 'https', 'ssh', 'snmp', 'http', 'telnet', 'http-ocsp',
    'response-pages', 'userid-service', 'userid-syslog-listener-ssl',
    'userid-syslog-listener-udp',
)


class PANInterfaceManagementProfile(PANNamedSourceModel):
    protocols: dict[str, str] = Field(default_factory=dict)
    permitted_ips: list[str] | None = None
