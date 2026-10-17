"""Separate Gaia Clish projection for the Check Point pair."""

from .management import CPManagementRenderer, RenderedCheckPoint


class GaiaCLIRenderer:
    """Compatibility facade that returns the split Management/Gaia artifact."""

    def render(self, plan, *, approved_items=None) -> RenderedCheckPoint:
        return CPManagementRenderer().render(plan, approved_items=approved_items)

