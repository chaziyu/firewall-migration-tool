"""Stable root issues for choice, prerequisite, conflict and manual work."""
from ..models import digest


def build_review_issues(report):
    result = []
    for row in report["items"]:
        for reason in row["blocking_reasons"]:
            category = "PREREQUISITE" if reason.startswith("Blocked dependency:") else "CONFLICT" if "Destination" in reason or "destination" in reason else "CHOICE" if reason.startswith(("Choose ", "Confirm ", "Physical interface must")) else "MANUAL"
            result.append({"id": digest((row["key"], reason)), "category": category, "source_scope": row["source_scope"],
                           "source_name": row["source_name"], "item_key": row["key"], "explanation": reason})
    return result
