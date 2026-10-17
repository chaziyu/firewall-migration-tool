"""Fail-closed comparison against explicit FortiGate target evidence."""
from dataclasses import replace


def tokens(key, value):
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    if key in {"subnet", "ip", "dst", "start", "end"}:
        return tuple(str(value).split())
    return (str(value),)


def classify_target_reuse(items, evidence, options):
    if evidence is None:
        return items
    records = evidence["records"]
    mode_records = [r for r in records if r.source_path == "system settings" and r.vdom == options.vdom]
    profile_errors = []
    expected_modes = {"opmode": "nat", "ngfw-mode": "profile-based", "central-nat": "enable" if options.profile.get("nat_mode") == "central" else "disable"}
    if len(mode_records) != 1 or any(mode_records[0].values.get(key) != value for key, value in expected_modes.items()):
        profile_errors.append("Destination operating, NGFW or NAT mode is not explicitly verified against the selected profile.")
    global_records = [r for r in records if r.source_path == "system global"]
    vdom_mode = "multi-vdom" if options.profile.get("vdom_mode") == "multi" else "no-vdom"
    if len(global_records) != 1 or global_records[0].values.get("vdom-mode") != vdom_mode:
        profile_errors.append("Destination VDOM command scope is not explicitly verified.")
    result = []
    for item in items:
        command_settings = item.settings
        relevant = [r for r in records if r.source_path == item.section and
                    (r.vdom == item.target_vdom or (item.global_scope and r.cli_scope == "global"))]
        matches = [r for r in relevant if r.object_name == item.target_name]
        reasons = list(item.reasons)
        reasons.extend(profile_errors)
        disposition = item.disposition
        if evidence["version"] != options.profile.get("fortios_version") or evidence["validation_errors"]:
            reasons.append("Destination version or validation does not match the supported profile.")
        if len(matches) > 1 or any((r.cli_scope, r.vdom, r.source_path, r.object_name) in evidence["duplicates"] for r in matches):
            reasons.append("Destination object evidence is duplicated or ambiguous.")
        elif matches:
            record = matches[0]
            settings = dict(item.settings)
            equal = all(key in record.values and tokens(key, record.values[key]) == value for key, value in settings.items())
            extra = set(record.values) - set(settings) - {"uuid", "comment", "comments", "name"}
            if item.family == "interface" and record.values.get("type") == "physical":
                extra.discard("type")
                if record.values.get("vdom") == item.target_vdom:
                    extra.discard("vdom")
            if equal and not extra:
                disposition = "REUSE"
            elif (item.family == "interface" and item.disposition == "CONFIGURE" and record.values.get("type") == "physical"
                    and tokens("ip", record.values.get("ip")) == ("0.0.0.0", "0.0.0.0") and not extra
                    and set(settings) <= {"ip", "vdom"}
                    and (options.profile.get("vdom_mode") == "single" or record.values.get("vdom") == item.target_vdom)
                    and not any(item.target_name in str(other.values) for other in records if other is not record)):
                # Add addressing only to a verified unassigned, unreferenced port; never move ownership or replace an address.
                command_settings = tuple((key, value) for key, value in item.settings if key == "ip")
            else:
                reasons.append("Existing destination settings differ or contain unverified behavior; no overwrite is allowed.")
        elif item.family == "interface" and item.disposition == "CONFIGURE":
            reasons.append("Physical destination interface must already exist in the uploaded evidence.")
        elif not any(r.object_name is None and not r.values for r in relevant):
            reasons.append("Destination absence is unverified; creation requires an explicitly empty destination table.")
        if item.family in {"policy", "nat", "static_route"} and any(r.object_name is not None for r in relevant) and disposition != "REUSE":
            reasons.append("Populated destination rule/route tables require separately verified placement.")
        if item.family == "nat":
            settings = [r for r in records if r.source_path == "system settings" and r.vdom == options.vdom]
            if len(settings) != 1 or settings[0].values.get("central-nat") != "enable":
                reasons.append("Destination central NAT must be explicitly enabled; conversion never changes this setting.")
        if item.section == "firewall vip":
            for section in ("firewall policy", "firewall central-snat-map", "firewall vip"):
                table = [r for r in records if r.source_path == section and r.vdom == options.vdom]
                if not any(r.object_name is None and not r.values for r in table) or any(r.object_name is not None for r in table):
                    reasons.append("DNAT destination traffic tables must be explicitly empty to exclude VIP side effects.")
        result.append(replace(item, settings=command_settings, disposition=disposition, reasons=tuple(dict.fromkeys(reasons))))
    return tuple(result)
