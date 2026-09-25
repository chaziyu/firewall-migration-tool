from __future__ import annotations

from ..config import ExtractionConfig
from ..model.source import FGConfig
from ..nodes import FortiGateConfigTree

from .address import extract_addresses
from .admin import extract_admin
from .dhcp import extract_dhcp
from .external_resource import extract_external_resources
from .interfaces import extract_interfaces
from .ip_pools import extract_ip_pools
from .ips import extract_ips
from .policies import extract_policies
from .protocol_options import extract_protocol_options
from .security_policy import extract_security_policies
from .session_helper import extract_session_helpers
from .selected_sections import extract_selected_sections
from .shapers import extract_per_ip_shapers
from .profiles_group import extract_profile_groups
from .result import ExtractionResult
from .schedules import extract_schedules
from .source_inventory import capture_source_objects
from .source_metadata import capture_source_metadata
from .section_index import SectionIndex
from .routing import extract_routes
from .sdwan import extract_sdwan
from .services import extract_services
from .ssl_vpn import extract_ssl_vpn
from .user import extract_users
from .vips import extract_vips
from .vpn import extract_vpn
from .zones import extract_zones


def extract_fortigate_config(
    tree: FortiGateConfigTree,
    *,
    config: ExtractionConfig,
) -> ExtractionResult:
    """
    Extract explicit FortiGate source configuration into
    FortiGate source models.

    No canonical normalization, relationship resolution,
    FortiOS defaults, or target-vendor conversion occurs here.
    """

    source = FGConfig()
    index = SectionIndex.build(tree)

    # Network/source topology.
    extract_interfaces(index, source)
    extract_zones(index, source)

    # Reusable firewall objects.
    extract_addresses(index, source)
    extract_services(index, source)
    extract_schedules(index, source)

    # NAT source objects.
    extract_ip_pools(index, source)
    extract_vips(index, source)

    # Policies.
    extract_policies(index, source)
    extract_security_policies(index, source)
    extract_protocol_options(index, source)
    extract_per_ip_shapers(index, source)
    extract_session_helpers(index, source)
    extract_selected_sections(index, source)

    # Routing / VPN / SD-WAN.
    extract_routes(index, source)
    extract_vpn(index, source)
    extract_sdwan(index, source)

    # DHCP.
    extract_dhcp(index, source)

    # SSL VPN.
    extract_ssl_vpn(index, source)

    # Identity / administration.
    extract_users(index, source)
    extract_admin(index, source)

    # Security profiles.
    extract_ips(index, source)
    extract_profile_groups(index, source)

    extract_external_resources(index, source)

    return ExtractionResult(
        config=source,
        source_objects=capture_source_objects(index),
        source_metadata=capture_source_metadata(tree),
    )
