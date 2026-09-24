from __future__ import annotations

from typing import Protocol

from ..model.vpn import (
    FGIPsecPhase1,
    FGIPsecPhase2,
    FGIPsecPolicyPhase1,
    FGIPsecPolicyPhase2,
)
from ..nodes import (
    CommandNode,
)

from .common import (
    evaluate_edit,
    iter_section_edits,
    source_model_kwargs,
)
from .section_index import SectionIndex


_PHASE1_SECRET_FIELDS = {
    "psksecret",
    "psksecret-remote",
    "ppk-secret",
    "authpasswd",
    "group-authentication-secret",
}


class VPNConfig(Protocol):
    """Minimal destination required by IPsec extraction."""

    ipsec_phase1: list[FGIPsecPhase1]
    ipsec_policy_phase1: list[FGIPsecPolicyPhase1]
    ipsec_phase2: list[FGIPsecPhase2]
    ipsec_policy_phase2: list[FGIPsecPolicyPhase2]


def extract_vpn(
    tree: SectionIndex,
    config: VPNConfig,
) -> None:
    """Extract FortiGate route-based IPsec source objects."""

    _extract_phase1(tree, config)
    _extract_phase1(
        tree, config, section_path="vpn ipsec phase1",
        model_type=FGIPsecPolicyPhase1, destination="ipsec_policy_phase1",
    )
    _extract_phase2(tree, config)
    _extract_phase2(
        tree, config, section_path="vpn ipsec phase2",
        model_type=FGIPsecPolicyPhase2, destination="ipsec_policy_phase2",
    )


def _extract_phase1(
    tree: SectionIndex,
    config: VPNConfig,
    *,
    section_path: str = "vpn ipsec phase1-interface",
    model_type=FGIPsecPhase1,
    destination: str = "ipsec_phase1",
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
            model_type=model_type,
            name=source.edit.name,
            vdom=source.vdom,
        )

        secret_state = _evaluate_secret_state(
            source.edit.commands,
        )

        # Secret values must never be retained in raw_extra.
        raw_extra = attributes.get(
            "raw_extra",
            {},
        )

        for key in _PHASE1_SECRET_FIELDS:
            raw_extra.pop(
                key,
                None,
            )

        attributes["raw_extra"] = raw_extra

        # Preserve only whether a credential was configured.
        attributes["psk_configured"] = (
            secret_state["psksecret"]
            or secret_state["psksecret-remote"]
        )

        attributes["ppk_secret_configured"] = (
            secret_state["ppk-secret"]
        )

        attributes["auth_password_configured"] = (
            secret_state["authpasswd"]
        )

        attributes[
            "group_authentication_secret_configured"
        ] = secret_state[
            "group-authentication-secret"
        ]

        getattr(config, destination).append(model_type(**attributes))


def _extract_phase2(
    tree: SectionIndex,
    config: VPNConfig,
    *,
    section_path: str = "vpn ipsec phase2-interface",
    model_type=FGIPsecPhase2,
    destination: str = "ipsec_phase2",
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
            model_type=model_type,
            name=source.edit.name,
            vdom=source.vdom,
        )

        getattr(config, destination).append(model_type(**attributes))


def _evaluate_secret_state(
    commands,
) -> dict[str, bool]:
    """
    Track only whether sensitive Phase-1 fields are configured.

    Secret values themselves are never returned or stored.

    State follows FortiGate source order:

        set secret ...
        unset secret

    results in False.
    """

    state = {
        key: False
        for key in _PHASE1_SECRET_FIELDS
    }

    for command in commands:
        if not isinstance(
            command,
            CommandNode,
        ):
            continue

        key = command.key

        if key not in state:
            continue

        operation = command.operation.lower()

        if operation in {
            "set",
            "append",
        }:
            state[key] = True

        elif operation == "unset":
            state[key] = False

    return state
