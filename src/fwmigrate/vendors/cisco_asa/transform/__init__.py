"""Pure, read-only ASA semantic transforms."""

from .nat import ASANATTransformResult, transform_nat
from .routes import ASARouteTransformResult, transform_routes
from .vpn import ASAVPNTransformResult, build_vpn_topology

__all__ = ["ASANATTransformResult", "ASARouteTransformResult", "ASAVPNTransformResult", "transform_nat", "transform_routes", "build_vpn_topology"]
