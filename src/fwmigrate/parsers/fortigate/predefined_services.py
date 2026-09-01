"""FortiOS predefined firewall-service names."""

# FortiOS 7.4.x baseline (including 7.4.6), from Fortinet's "Default Service
# and Service Groups" inventory.  This is its 85 service objects only; the
# four predefined service groups are intentionally excluded. Names are
# case-sensitive, matching normal FortiGate source-object dependency resolution.
FORTIGATE_PREDEFINED_SERVICES = frozenset({
    "AFS3", "AH", "ALL", "ALL_ICMP", "ALL_TCP", "ALL_UDP", "AOL", "BGP",
    "CVSPSERVER", "DCE-RPC", "DHCP", "DHCP6", "DNS", "ESP",
    "FINGER", "FTP", "FTP_GET", "FTP_PUT",
    "GOPHER", "GRE", "GTP", "H323", "HTTP", "HTTPS", "IKE", "IMAP",
    "IMAPS", "INFO_ADDRESS", "INFO_REQUEST", "Internet-Locator-Service",
    "IRC", "KERBEROS", "L2TP", "LDAP", "LDAP_UDP", "MGCP", "MMS",
    "MS-SQL", "MYSQL", "NetMeeting", "NFS", "NNTP", "NONE", "NTP",
    "ONC-RPC", "OSPF", "PC-Anywhere", "PING", "POP3", "POP3S", "PPTP",
    "QUAKE", "RADIUS", "RADIUS-OLD", "RAUDIO", "RDP", "REXEC", "RIP",
    "RLOGIN", "RSH", "RTSP", "SAMBA", "SCCP", "SIP", "SIP-MSNmessenger",
    "SMB", "SMTP", "SMTPS", "SNMP", "SOCKS", "SQUID", "SSH", "SYSLOG",
    "TALK", "TELNET", "TFTP", "TIMESTAMP", "TRACEROUTE", "UUCP",
    "VDOLIVE", "VNC", "WAIS", "WINFRAME", "WINS", "X-WINDOWS",
})


def is_predefined_service(name: str) -> bool:
    return name in FORTIGATE_PREDEFINED_SERVICES
