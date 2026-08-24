from typing import Optional


# Common FortiOS built-in session-helper baseline.
#
# FortiOS defaults can vary by release. Extend this later with
# version-specific baselines when source-version detection is available.
DEFAULT_SESSION_HELPERS = {
    1: ("pptp", 6, 1723),
    2: ("h323", 6, 1720),
    3: ("ras", 17, 1719),
    4: ("tns", 6, 1521),
    5: ("tftp", 17, 69),
    6: ("rtsp", 6, 554),
    7: ("rtsp", 6, 7070),
    8: ("rtsp", 6, 8554),
    9: ("ftp", 6, 21),
    10: ("mms", 6, 1863),
    11: ("pmap", 6, 111),
    12: ("pmap", 17, 111),
    13: ("sip", 17, 5060),
    14: ("dns-udp", 17, 53),
    15: ("rsh", 6, 514),
    16: ("rsh", 6, 512),
    17: ("dcerpc", 6, 135),
    18: ("dcerpc", 17, 135),
    19: ("mgcp", 17, 2427),
    20: ("mgcp", 17, 2727),
}


def classify_session_helper(
    source_id: int,
    name: Optional[str],
    protocol: Optional[int],
    port: Optional[int],
) -> str:
    """Classify a session helper against the known FortiOS baseline."""
    if not name or protocol is None or port is None:
        return "UNKNOWN"

    default_entry = DEFAULT_SESSION_HELPERS.get(source_id)
    if default_entry is None:
        return "CUSTOM"

    if (name.lower(), protocol, port) == default_entry:
        return "DEFAULT"

    return "CUSTOMIZED"


def protocol_number_to_name(protocol: Optional[int]) -> Optional[str]:
    if protocol == 6:
        return "TCP"
    if protocol == 17:
        return "UDP"
    if protocol is None:
        return None
    return f"IP-{protocol}"
