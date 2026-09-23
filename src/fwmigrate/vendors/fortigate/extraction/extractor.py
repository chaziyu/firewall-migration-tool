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
from .profiles_group import extract_profile_groups
from .result import ExtractionResult
from .schedules import extract_schedules
from .source_inventory import capture_source_objects
from .source_metadata import capture_source_metadata
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

    # Network/source topology.
    extract_interfaces(tree, source)
    extract_zones(tree, source)

    # Reusable firewall objects.
    extract_addresses(tree, source)
    extract_services(tree, source)
    extract_schedules(tree, source)

    # NAT source objects.
    extract_ip_pools(tree, source)
    extract_vips(tree, source)

    # Policies.
    extract_policies(tree, source)

    # Routing / VPN / SD-WAN.
    extract_routes(tree, source)
    extract_vpn(tree, source)
    extract_sdwan(tree, source)

    # DHCP.
    extract_dhcp(tree, source)

    # SSL VPN.
    extract_ssl_vpn(tree, source)

    # Identity / administration.
    extract_users(tree, source)
    extract_admin(tree, source)

    # Security profiles.
    extract_ips(tree, source)
    extract_profile_groups(tree, source)

    extract_external_resources(tree, source)

    return ExtractionResult(
        config=source,
        source_objects=capture_source_objects(tree),
        source_metadata=capture_source_metadata(tree),
    )
