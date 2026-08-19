from enum import Enum

class AddressType(str, Enum):
    NETWORK = "network"
    HOST = "host"
    RANGE = "range"
    FQDN = "fqdn"
    WILDCARD_FQDN = "wildcard"
    GROUP = "group"
    DYNAMIC = "dynamic"
    GEO = "geo"
    WILDCARD_MASK = "wildcard_mask"

class ServiceProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ICMPV6 = "icmpv6"
    IP = "ip"
    ANY = "any"

class PolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"

class NATType(str, Enum):
    SOURCE = "source"
    DESTINATION = "destination"

class MigrationConfidence(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    MANUAL = "manual"
    UNSUPPORTED = "unsupported"
