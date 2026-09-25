from __future__ import annotations

from typing import Protocol

from ..model.route_static import FGStaticRoute

from .common import (
    evaluate_edit,
    iter_section_edits,
    source_model_kwargs,
)
from .section_index import SectionIndex


class RouteConfig(Protocol):
    """Minimal destination required by route extraction."""

    static_routes: list[FGStaticRoute]


def extract_routes(
    tree: SectionIndex,
    config: RouteConfig,
) -> None:
    """Extract FortiGate static-route source objects."""

    _extract_static_routes(
        tree,
        config,
        section_path="router static",
        address_family="ipv4",
    )
    _extract_static_routes(
        tree,
        config,
        section_path="router static6",
        address_family="ipv6",
    )


def _extract_static_routes(
    tree: SectionIndex,
    config: RouteConfig,
    *,
    section_path: str,
    address_family: str,
) -> None:
    for source in iter_section_edits(
        tree,
        section_path,
    ):
        evaluation = evaluate_edit(
            section_path,
            source.edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGStaticRoute,
            vdom=source.vdom,
        )

        # Route identity comes from:
        #
        #   edit <seq-num>
        #
        # Preserve malformed source rather than dropping the route.
        try:
            attributes["seq_num"] = int(
                source.edit.name
            )
        except ValueError:
            attributes["seq_num"] = None
            attributes["raw_extra"][
                "unparsed_seq_num"
            ] = source.edit.name

        # Derived from the source section rather than a FortiOS field.
        attributes["address_family"] = (
            address_family
        )

        config.static_routes.append(
            FGStaticRoute(**attributes)
        )
