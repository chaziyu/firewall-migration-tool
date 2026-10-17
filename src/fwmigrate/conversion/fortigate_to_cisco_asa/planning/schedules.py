"""The small weekly FortiGate schedule subset representable by ASA time-range."""

from datetime import time

from .naming import item_key, target_name
from ..models import ASAPlanItem


_DAYS = {"mon": "monday", "monday": "monday", "tue": "tuesday", "tues": "tuesday",
         "tuesday": "tuesday", "wed": "wednesday", "wednesday": "wednesday",
         "thu": "thursday", "thur": "thursday", "thurs": "thursday", "thursday": "thursday",
         "fri": "friday", "friday": "friday", "sat": "saturday", "saturday": "saturday",
         "sun": "sunday", "sunday": "sunday"}


def plan_schedules(source, options):
    items = []
    vdom = options.source_vdom
    schedules = {item.name: item for item in source.recurring_schedules if (item.vdom or "root") == vdom}
    groups = {item.name: item for item in source.schedule_groups if (item.vdom or "root") == vdom}
    for name, schedule in schedules.items():
        blockers, clauses = [], []
        if not options.source_timezone or not options.target_timezone or options.source_timezone != options.target_timezone:
            blockers.append("SCHEDULE_TIMEZONE_CONFIRMATION_REQUIRED")
        try:
            start, end = time.fromisoformat(schedule.start), time.fromisoformat(schedule.end)
            if start >= end or start.second or start.microsecond or end.second or end.microsecond:
                raise ValueError
            days = list(dict.fromkeys(_DAYS[day.casefold()] for day in schedule.days))
            if not days:
                raise ValueError
            clauses = [f" periodic {' '.join(days)} {start.strftime('%H:%M')} to {end.strftime('%H:%M')}"]
        except (TypeError, ValueError, KeyError):
            blockers.append("SCHEDULE_REPRESENTATION_UNSUPPORTED")
        target = target_name("schedule", vdom, name)
        commands = (f"time-range {target}", *clauses) if clauses and not blockers else ()
        items.append(ASAPlanItem(item_key(vdom, "schedule", name), "schedule", vdom, name,
                                 target, (("commands", tuple(commands)),), blockers=tuple(dict.fromkeys(blockers))))
    for name, group in groups.items():
        blockers = []
        members = tuple(group.members)
        if not members or any(member not in schedules for member in members):
            blockers.append("SCHEDULE_GROUP_UNSUPPORTED")
        else:
            blockers.append("SCHEDULE_GROUP_UNION_UNVERIFIED")
        items.append(ASAPlanItem(item_key(vdom, "schedule", name), "schedule", vdom, name,
                                 target_name("schedule", vdom, name), blockers=tuple(blockers)))
    return items
