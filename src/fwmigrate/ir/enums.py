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
    SPECIAL = "special"
    STUB_UNSUPPORTED = "stub_unsupported"

class ServiceProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"
    ICMP = "icmp"
    ICMPV6 = "icmpv6"
    IP = "ip"
    ANY = "any"

class PolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    IPSEC = "ipsec"

class NATType(str, Enum):
    SOURCE = "source"
    DESTINATION = "destination"
    TWICE = "twice"
    CENTRAL = "central"
    ADDRESS_TRANSLATION = "address-translation"

class NATFamily(str, Enum):
    NAT44 = "nat44"
    NAT46 = "nat46"
    NAT64 = "nat64"
    NAT66 = "nat66"

class NATSourcePortBehavior(str, Enum):
    DYNAMIC = "dynamic"
    PRESERVE_IF_AVAILABLE = "preserve-if-available"
    PRESERVE_STRICT = "preserve-strict"
    ALWAYS_TRANSLATE = "always-translate"
    EXPLICIT_RANGE = "explicit-range"

class NATTranslationMode(str, Enum):
    NONE = "none"
    INTERFACE_ADDRESS = "interface-address"
    POOL = "pool"
    STATIC = "static"
    DYNAMIC_IP_AND_PORT = "dynamic-ip-and-port"

class MigrationConfidence(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    MANUAL = "manual"
    UNSUPPORTED = "unsupported"
