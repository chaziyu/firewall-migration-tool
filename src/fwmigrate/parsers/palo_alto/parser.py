"""PAN-OS source-parser primitives and compatibility imports."""
from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from typing import List

from fwmigrate.core.base_parser import BaseSourceParser

from .resolver import PANResolver
from .source_model import PANSourceDocument


# PAN-OS predefined policy regions. This is the explicit region-code catalog
# documented by Palo Alto Networks, rather than a shape-based two-letter test.
PAN_PREDEFINED_POLICY_REGIONS = frozenset("""
A1 A2
AD AE AF AG AI AL AM AN AO AP AQ AR AS AT AU AW AX AZ
BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CE CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ
DE DJ DK DM DN DO DZ
EC EE EG EH ER ES ET EU
FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY
HK HM HN HR HT HU
ID IE IL IM IN IO IQ IR IS IT
JE JM JO JP
KE KG KH KI KM KN KP KR KW KY KZ
LA LB LC LI LK LN LR LS LT LU LV LY
MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ
NA NC NE NF NG NI NL NO NP NR NU NZ
OM
PA PE PF PG PH PK PL PM PN PR PS PT PW PY
QA RE RO RS RU RW
SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ
TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ
UA UG UM US UY UZ
VA VC VE VG VI VN VU
WF WS
YE YT
ZA ZM ZW
""".split())

# PAN-OS Security Policy rule types documented by Palo Alto Networks.
PAN_SECURITY_RULE_TYPES = frozenset({"universal", "interzone", "intrazone"})
PAN_ZONE_TYPE_TAGS = ("layer3", "layer2", "virtual-wire", "tap", "tunnel")


def _configured_pan_zone_types(z_entry: ET.Element) -> list[str]:
    network = z_entry.find("./network")
    if network is None:
        return []
    return [
        zone_type
        for zone_type in PAN_ZONE_TYPE_TAGS
        if network.find(f"./{zone_type}") is not None
    ]


def load_pan_source(content: str) -> PANSourceDocument:
    """Load and normalize a PAN-OS XML export without creating canonical IR."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError as error:
        cleaned = content.strip()
        if not cleaned:
            raise ValueError("Empty configuration input.") from error
        try:
            root = ET.fromstring(cleaned)
        except ET.ParseError:
            if cleaned.startswith("set "):
                raise ValueError(
                    "PAN-OS CLI 'set' format is not supported. Please provide XML configuration."
                ) from error
            raise ValueError(f"Malformed XML input: {error}") from error

    if root.tag == "response":
        wrapped = root.find("./result/config")
        if wrapped is None:
            raise ValueError(
                "Unsupported PAN-OS XML response: missing response/result/config."
            )
        root = wrapped
    if root.tag != "config":
        raise ValueError(
            f"Unsupported XML format: expected root element '<config>', found '<{root.tag}>'."
        )

    host_elem = root.find(".//system/hostname")
    if host_elem is None:
        host_elem = root.find(".//deviceconfig/system/hostname")
    hostname = host_elem.text.strip() if host_elem is not None and host_elem.text else None
    return PANSourceDocument(
        root=root,
        raw_content=content,
        hostname=hostname,
        source_version=root.get("version"),
    )


class _PANOSBaseSourceParser(BaseSourceParser):
    """PAN-OS source-parser state shared by the IR transformer."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.resolver = PANResolver()

    def parse_source(self, content: str) -> PANSourceDocument:
        return load_pan_source(content)

    @property
    def vendor_id(self) -> str:
        return "palo_alto"

    @property
    def display_name(self) -> str:
        return "Palo Alto Networks (PAN-OS)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".xml"]

    @staticmethod
    def _is_direct_policy_address(value: str) -> bool:
        """Return whether a policy member is a literal IP address or CIDR."""
        candidate = value.strip()
        try:
            ipaddress.ip_address(candidate)
            return True
        except ValueError:
            pass

        if "/" not in candidate:
            return False
        try:
            ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            return False
        return True

    @staticmethod
    def _is_predefined_policy_region(value: str) -> bool:
        """Return whether a policy member is a known PAN-OS region code."""
        return value.strip().upper() in PAN_PREDEFINED_POLICY_REGIONS


def __getattr__(name: str):
    if name == "PANOSSourceParser":
        from .extractor import PANOSSourceParser

        return PANOSSourceParser
    raise AttributeError(name)
