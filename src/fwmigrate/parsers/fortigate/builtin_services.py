"""Recognized FortiOS predefined service names (case sensitive).

Recognition is not a fabricated custom-service definition. Explicit custom
objects/groups override this catalogue. Comparisons use identical names or ALL;
version-specific port equivalence is not assumed for absent definitions.
"""

BUILTIN_SERVICES = frozenset({"DNS", "HTTP", "HTTPS", "NTP", "SSH", "PING", "RDP", "SMTP", "ALL"})

# Conservative baseline for simple TCP/UDP matching. Names not listed here are
# still recognized; their absent protocol definitions remain unknown. Explicit
# source custom definitions always take precedence, including overrides of ALL.
BUILTIN_PORTS = {
    "DNS": {"tcp": [(53, 53)], "udp": [(53, 53)]},
    "HTTP": {"tcp": [(80, 80)]}, "HTTPS": {"tcp": [(443, 443)]},
    "NTP": {"udp": [(123, 123)]}, "SSH": {"tcp": [(22, 22)]},
    "SMTP": {"tcp": [(25, 25)]},
    "ALL": {"any": [(0, 65535)]},
}
