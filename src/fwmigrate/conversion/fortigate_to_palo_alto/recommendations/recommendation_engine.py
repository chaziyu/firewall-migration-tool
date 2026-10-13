"""Aggregate pair-specific, read-only migration recommendations."""

from __future__ import annotations

from fwmigrate.conversion.fortigate_to_palo_alto.recommendations.admin_suggestions import build_admin_recommendations
from fwmigrate.conversion.fortigate_to_palo_alto.recommendations.external_resource_suggestions import build_external_resource_recommendations
from fwmigrate.conversion.fortigate_to_palo_alto.recommendations.identity_suggestions import build_identity_recommendations
from fwmigrate.conversion.fortigate_to_palo_alto.recommendations.security_suggestions import build_security_recommendations
from fwmigrate.conversion.fortigate_to_palo_alto.recommendations.sdwan_suggestions import build_sdwan_recommendations
from fwmigrate.conversion.fortigate_to_palo_alto.recommendations.ssl_vpn_suggestions import build_ssl_vpn_recommendations
from fwmigrate.conversion.fortigate_to_palo_alto.recommendations.vpn_suggestions import build_vpn_recommendations


def build_recommendations(source, derived, decisions, target=None, target_device=None):
    recommendations = []
    for builder in (
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
