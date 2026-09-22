from __future__ import annotations

from dataclasses import dataclass

from ..model.source import FGConfig


DEFAULT_POLICY_NAME_LIMIT = 32
LIMIT_SUFFIX = "-L"


@dataclass(frozen=True, slots=True)
class NormalizedPolicyName:
    vdom: str
    policy_id: int | None

    source_name: str | None
    normalized_name: str | None

    truncated: bool

    # Another policy normalized to the same name.
    collision: bool = False


def normalize_policy_name(
    name: str | None,
    *,
    max_length: int = DEFAULT_POLICY_NAME_LIMIT,
) -> str | None:
    if name is None:
        return None

    if len(name) <= max_length:
        return name

    if max_length < len(
        LIMIT_SUFFIX
    ):
        raise ValueError(
            "max_length is too small "
            "for policy limit suffix"
        )

    prefix_length = (
        max_length
        - len(LIMIT_SUFFIX)
    )

    return (
        name[:prefix_length]
        + LIMIT_SUFFIX
    )


def normalize_policy_names(
    config: FGConfig,
    *,
    max_length: int = DEFAULT_POLICY_NAME_LIMIT,
) -> list[NormalizedPolicyName]:
    provisional: list[
        NormalizedPolicyName
    ] = []

    counts: dict[
        tuple[str, str],
        int,
    ] = {}

    for policy in config.policies:
        normalized = normalize_policy_name(
            policy.name,
            max_length=max_length,
        )

        if normalized is not None:
            key = (
                policy.vdom,
                normalized,
            )

            counts[key] = (
                counts.get(
                    key,
                    0,
                )
                + 1
            )

        provisional.append(
            NormalizedPolicyName(
                vdom=policy.vdom,
                policy_id=policy.policy_id,
                source_name=policy.name,
                normalized_name=normalized,
                truncated=(
                    normalized
                    != policy.name
                ),
            )
        )

    reserved_names: set[tuple[str, str]] = set()
    for item in provisional:
        if (
            item.normalized_name is not None
            and counts.get(
                (item.vdom, item.normalized_name),
                0,
            ) == 1
        ):
            reserved_names.add(
                (item.vdom, item.normalized_name)
            )

    resolved: list[NormalizedPolicyName] = []
    for item in provisional:
        collision = (
            item.normalized_name is not None
            and counts.get(
                (item.vdom, item.normalized_name),
                0,
            ) > 1
        )
        normalized_name = item.normalized_name

        if collision and item.truncated:
            if (
                item.policy_id is not None
                and item.source_name is not None
            ):
                suffix = f"-L{item.policy_id}"
                if len(suffix) <= max_length:
                    candidate = (
                        item.source_name[: max_length - len(suffix)]
                        + suffix
                    )
                    key = (item.vdom, candidate)
                    if key not in reserved_names:
                        normalized_name = candidate
                        collision = False
                        reserved_names.add(key)

        resolved.append(
            NormalizedPolicyName(
                vdom=item.vdom,
                policy_id=item.policy_id,
                source_name=item.source_name,
                normalized_name=normalized_name,
                truncated=item.truncated,
                collision=collision,
            )
        )

    return resolved
