from __future__ import annotations

from .recommendations import PANMigrationRecommendation, PANRecommendationConfidence, PANRecommendationMethod, recommendation_key, source_facts


def build_external_resource_recommendations(source, derived, decisions, target=None, target_device=None):
    return tuple(
        PANMigrationRecommendation(
            recommendation_key(item.vdom or "root", "external_resource", item.name, "PAN_EXTERNAL_RESOURCE"), "External Resource", item.vdom or "root", "external_resource", item.name,
            "PAN_EXTERNAL_RESOURCE", f"External resource {item.name}", "Preserve the source resource and require target external-resource design; the selected PAN reference does not establish an authoritative EDL mapping.",
            PANRecommendationMethod.DETERMINISTIC, PANRecommendationConfidence.LOW,
            source_facts(item, ("resource", "type", "comments", "refresh_rate")), (), (), ("Target external-resource design required",), ()
        )
        for item in getattr(source, "external_resources", ())
    )
