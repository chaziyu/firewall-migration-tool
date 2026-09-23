from dataclasses import dataclass


@dataclass(frozen=True)
class GaiaCommandFamily:
    name: str
    prefixes: tuple[tuple[str, ...], ...]
    operations: frozenset[str] = frozenset({"set", "add", "show", "create", "delete"})


GAIA_COMMAND_FAMILIES = (
    GaiaCommandFamily("interface", (("interface",),)),
    GaiaCommandFamily("static-route-ipv4", (("static-route",), ("route", "static"))),
    GaiaCommandFamily("static-route-ipv6", (("ipv6", "route", "static"),)),
    GaiaCommandFamily("dhcp-server", (("dhcp", "server"), ("dhcp-server",))),
    GaiaCommandFamily("gaia-user", (("user",), ("users",))),
    GaiaCommandFamily("gaia-rba-role", (("rba", "role"), ("rba", "roles"))),
    GaiaCommandFamily("gaia-rba-user-assignment", (("rba", "user"), ("rba", "users"))),
    GaiaCommandFamily("vpn-tunnel-vti", (("vpn", "tunnel"), ("vpn", "tunnels"))),
)


def match_gaia_family(arguments: tuple[str, ...]) -> tuple[GaiaCommandFamily | None, tuple[str, ...]]:
    lowered = tuple(item.lower() for item in arguments)
    for family in GAIA_COMMAND_FAMILIES:
        for prefix in family.prefixes:
            if lowered[:len(prefix)] == prefix:
                return family, arguments[len(prefix):]
    return None, arguments


SUPPORTED_GAIA_SECTIONS = frozenset(family.name for family in GAIA_COMMAND_FAMILIES)


def is_supported_gaia_section(name: str) -> bool:
    return name in SUPPORTED_GAIA_SECTIONS
