from enum import Enum

class AddressType(str, Enum):
    NETWORK = "network"
    HOST = "host"
    RANGE = "range"
    FQDN = "fqdn"
    WILDCARD_FQDN = "wildcard"
    DYNAMIC = "dynamic"
    GEO = "geo"
    WILDCARD_MASK = "wildcard_mask"
    MAC = "mac"
    EMS_TAG = "ems_tag"
    STUB_UNSUPPORTED = "stub_unsupported"

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
    TWICE = "twice"

class MigrationConfidence(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    MANUAL = "manual"
    UNSUPPORTED = "unsupported"
