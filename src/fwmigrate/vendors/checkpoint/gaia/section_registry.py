SUPPORTED_GAIA_SECTIONS = frozenset({"interface", "static-route", "dns", "ntp", "hostname"})


def is_supported_gaia_section(name: str) -> bool:
    return name in SUPPORTED_GAIA_SECTIONS
