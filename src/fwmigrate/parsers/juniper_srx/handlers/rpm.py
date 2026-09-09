"""Source inventory handler for Junos RPM probes."""

from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperContextConfig, JuniperRPMProbe, JuniperRPMTest
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand, extract_value_list


def handle_rpm_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    toks = cmd.tokens
    if len(toks) < 6 or [t.lower() for t in toks[1:4]] != ["services", "rpm", "probe"]:
        return False
    owner = toks[4]
    probe_name = owner
    marker = 5
    if toks[5].lower() != "test":
        probe_name, marker = toks[5], 6
    probe = context.rpm_probes.setdefault(f"{owner}:{probe_name}", JuniperRPMProbe(owner=owner, name=probe_name))
    if len(toks) <= marker or toks[marker].lower() != "test":
        return _capture(cmd, probe.source_attributes, toks[marker:])
    if len(toks) <= marker + 1:
        return _capture(cmd, probe.source_attributes, toks[marker:])
    test_name = toks[marker + 1]
    test = probe.tests.setdefault(test_name, JuniperRPMTest(owner=owner, name=test_name))
    rest = toks[marker + 2:]
    if not rest:
        return _capture(cmd, test.source_attributes, rest)
    key = rest[0].lower()
    vals = extract_value_list(rest[1:])
    if key in {"target", "target-address"} and vals:
        test.target = vals[-1] if key == "target" and vals[0].lower() == "address" else vals[0]
    elif key in {"probe-type", "test-type"} and vals:
        test.test_type = vals[0]
    elif key == "probe-count" and vals:
        test.probe_count = _int(vals[0])
    elif key == "probe-interval" and vals:
        test.probe_interval = vals[0]
    elif key in {"successive-loss", "total-loss", "thresholds"}:
        test.thresholds[key] = vals if len(vals) != 1 else vals[0]
    elif key == "traps":
        test.traps.extend(v for v in vals if v not in test.traps)
    else:
        return _capture(cmd, test.source_attributes, rest)
    cmd.consumed = True
    cmd.handler = "rpm"
    cmd.extraction_status = ExtractionStatus.PARTIALLY_NORMALIZED
    cmd.requires_manual_review = True
    return True


def _capture(cmd, attrs, toks):
    safe = sanitize_tokens(toks)
    attrs["_".join(safe) or "root"] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
    cmd.consumed = True
    cmd.handler = "rpm"
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
