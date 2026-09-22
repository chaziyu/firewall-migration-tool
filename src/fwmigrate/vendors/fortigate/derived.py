from __future__ import annotations

from dataclasses import dataclass

from .model.source import FGConfig
from .relationships.interface_topology import (
    InterfaceTopology,
    build_interface_topology,
)
from .relationships.references import (
    BrokenReference,
    ReferenceIndex,
    build_reference_index,
    collect_broken_references,
)
from .transform.nat import (
    NormalizedSourceNAT,
    transform_nat,
)
from .transform.policies import (
    NormalizedPolicyName,
    normalize_policy_names,
)
from .transform.services import (
    ServiceTransformResult,
    transform_services,
)
from .transform.vpn import (
    VPNTransformResult,
    normalize_vpn_phase2,
)


@dataclass(frozen=True, slots=True)
class DerivedViews:
    references: ReferenceIndex
    broken_references: tuple[BrokenReference, ...]
    topology: InterfaceTopology

    services: ServiceTransformResult

    nat: tuple[NormalizedSourceNAT, ...]

    policy_names: tuple[
        NormalizedPolicyName,
        ...
    ]

    vpn: VPNTransformResult


def build_derived_views(
    config: FGConfig,
) -> DerivedViews:
    references = build_reference_index(
        config
    )

    return DerivedViews(
        references=references,
        broken_references=tuple(
            collect_broken_references(
                config,
                index=references,
            )
        ),
        topology=build_interface_topology(
            config,
            references=references,
        ),
        services=transform_services(
            config
        ),
        nat=tuple(
            transform_nat(
                config,
                references=references,
            )
        ),
        policy_names=tuple(
            normalize_policy_names(
                config
            )
        ),
        vpn=normalize_vpn_phase2(
            config,
            references=references,
        ),
    )
