"""Report safe ASA plan items and unresolved manual coverage."""

from ..rendering.renderer import ASACLIRenderer


def build_review_report(plan):
    return ASACLIRenderer().render(plan).report
