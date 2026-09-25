"""Aggregate pair-specific, read-only migration recommendations."""

from __future__ import annotations

from .admin_suggestions import build_admin_recommendations
from .dhcp_suggestions import build_dhcp_recommendations
from .external_resource_suggestions import build_external_resource_recommendations
from .identity_suggestions import build_identity_recommendations
from .security_suggestions import build_security_recommendations
from .sdwan_suggestions import build_sdwan_recommendations
from .ssl_vpn_suggestions import build_ssl_vpn_recommendations
from .vpn_suggestions import build_vpn_recommendations


def build_recommendations(source, derived, decisions, target=None, target_device=None):
    recommendations = []
    for builder in (
        build_dhcp_recommendations,
        build_vpn_recommendations,
        build_identity_recommendations,
        build_admin_recommendations,
        build_security_recommendations,
        build_sdwan_recommendations,
        build_ssl_vpn_recommendations,
        build_external_resource_recommendations,
    ):
        recommendations.extend(builder(source, derived, decisions, target, target_device))
    return tuple(sorted(recommendations, key=lambda item: item.key))
