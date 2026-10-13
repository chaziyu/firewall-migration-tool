"""FortiOS predefined firewall service reference data.

This module contains vendor-defined built-in service and service-group names.

Important:
    These objects are NOT injected into parsed FortiGate source models.

    They are used only for:
        - reference resolution
        - dependency validation
        - distinguishing built-in objects from unresolved references
"""

from __future__ import annotations


FORTIOS_PREDEFINED_SERVICES: frozenset[str] = frozenset(
    {
        "AFS3",
        "AH",
        "ALL",
        "ALL_ICMP",
        "ALL_TCP",
        "ALL_UDP",
        "AOL",
        "BGP",
        "CVSPSERVER",
        "DCE-RPC",
        "DHCP",
        "DHCP6",
        "DNS",
        "ESP",
        "FINGER",
        "FTP",
        "FTP_GET",
        "FTP_PUT",
        "GOPHER",
        "GRE",
        "GTP",
        "H323",
        "HTTP",
        "HTTPS",
        "IKE",
        "IMAP",
        "IMAPS",
        "INFO_ADDRESS",
        "INFO_REQUEST",
        "Internet-Locator-Service",
        "IRC",
        "KERBEROS",
        "L2TP",
        "LDAP",
        "LDAP_UDP",
        "MGCP",
        "MMS",
        "MS-SQL",
        "MYSQL",
        "NetMeeting",
        "NFS",
        "NNTP",
        "NONE",
        "NTP",
        "ONC-RPC",
        "OSPF",
        "PC-Anywhere",
        "PING",
        "POP3",
        "POP3S",
        "PPTP",
        "QUAKE",
        "RADIUS",
        "RADIUS-OLD",
        "RAUDIO",
        "RDP",
        "REXEC",
        "RIP",
        "RLOGIN",
        "RSH",
        "RTSP",
        "SAMBA",
        "SCCP",
        "SIP",
        "SIP-MSNmessenger",
        "SMB",
        "SMTP",
        "SMTPS",
        "SNMP",
        "SOCKS",
        "SQUID",
        "SSH",
        "SYSLOG",
        "TALK",
        "TELNET",
        "TFTP",
        "TIMESTAMP",
        "TRACEROUTE",
        "UUCP",
        "VDOLIVE",
        "VNC",
        "WAIS",
        "WINFRAME",
        "WINS",
        "X-WINDOWS",
    }
)


FORTIOS_PREDEFINED_SERVICE_GROUPS: frozenset[str] = frozenset(
    {
        "Email Access",
        "Exchange Server",
        "Web Access",
        "Windows AD",
    }
)


def is_predefined_service(name: str) -> bool:
    """Return True when `name` is a known FortiOS built-in service."""

    return name in FORTIOS_PREDEFINED_SERVICES


def is_predefined_service_group(name: str) -> bool:
    """Return True when `name` is a known FortiOS built-in service group."""

    return name in FORTIOS_PREDEFINED_SERVICE_GROUPS


def is_predefined_service_reference(name: str) -> bool:
    """
    Return True when `name` references any known built-in service object.

    This includes both individual services and predefined service groups.
    """

    return (
        is_predefined_service(name)
        or is_predefined_service_group(name)
    )