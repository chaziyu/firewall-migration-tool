from __future__ import annotations

from typing import Any, Protocol

from ..model.schedule import FGScheduleGroup, FGOneTimeSchedule, FGRecurringSchedule
from ..nodes import FortiGateConfigTree

from .common import evaluate_edit, iter_section_edits, source_model_kwargs


class ScheduleConfig(Protocol):
    schedule_groups: list[FGScheduleGroup]
    one_time_schedules: list[FGOneTimeSchedule]
    recurring_schedules: list[FGRecurringSchedule]


def extract_schedules(tree: FortiGateConfigTree, config: ScheduleConfig) -> None:
    _extract(tree, "firewall schedule group", FGScheduleGroup, config.schedule_groups, {"member": "members"})
    _extract(tree, "firewall schedule onetime", FGOneTimeSchedule, config.one_time_schedules)
    _extract(tree, "firewall schedule recurring", FGRecurringSchedule, config.recurring_schedules, {"day": "days"})


def _extract(tree: FortiGateConfigTree, section_path: str, model_type: type[Any], destination: list[Any], field_map: dict[str, str] | None = None) -> None:
    for source in iter_section_edits(tree, section_path):
        evaluation = evaluate_edit(section_path, source.edit)
        destination.append(model_type(**source_model_kwargs(
            evaluation,
            model_type=model_type,
            name=source.edit.name,
            vdom=source.vdom,
            field_map=field_map,
        )))
