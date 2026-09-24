"""Junos predefined application and application-set names."""

PREDEFINED_APPLICATIONS = frozenset({
    "junos-any", "junos-ah", "junos-bootp", "junos-dhcp", "junos-dns-tcp",
    "junos-dns-udp", "junos-esp", "junos-ftp", "junos-gre", "junos-http",
    "junos-https", "junos-icmp-all", "junos-icmp-ping", "junos-ike",
    "junos-ike-nat", "junos-ldap", "junos-ms-rpc", "junos-nfs", "junos-ntp",
    "junos-radius", "junos-rsh", "junos-smb", "junos-smtp", "junos-snmp",
    "junos-ssh", "junos-sun-rpc", "junos-syslog", "junos-telnet", "junos-tftp",
    "junos-whois",
})

PREDEFINED_APPLICATION_SETS = frozenset({
    "junos-h323-suite",
})
