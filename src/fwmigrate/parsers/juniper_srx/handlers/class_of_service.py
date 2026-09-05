from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.juniper_srx.extraction import sanitize_source_attributes, sanitize_tokens
from fwmigrate.parsers.juniper_srx.model import JuniperCoSScheduler, JuniperContextConfig
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand


def handle_class_of_service_command(cmd: JunosCommand, context: JuniperContextConfig) -> bool:
    t = cmd.tokens
    if len(t) < 5 or t[1:4] != ["class-of-service", "schedulers", "scheduler"]:
        return False
    obj = context.cos_schedulers.setdefault(t[4], JuniperCoSScheduler(name=t[4]))
    cmd.consumed, cmd.handler = True, "class_of_service"
    if len(t) == 5:
        cmd.extraction_status = ExtractionStatus.NORMALIZED
        return True
    key, values = t[5].lower(), t[6:]
    if key in {"transmit-rate", "shaping-rate", "priority"} and values:
        setattr(obj, key.replace("-", "_"), " ".join(values))
        cmd.extraction_status = ExtractionStatus.NORMALIZED
    elif key in {"apply-groups", "scheduler-map", "forwarding-class"} and values:
        obj.references.extend(v for v in values if v not in obj.references)
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    else:
        obj.source_attributes["_".join(sanitize_tokens(t[5:]))] = sanitize_source_attributes({"raw": cmd.raw_sanitized})
        cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    return True
