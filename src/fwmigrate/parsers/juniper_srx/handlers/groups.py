from fwmigrate.parsers.juniper_srx.model import JuniperSRXConfig
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand
from fwmigrate.extraction.models import ExtractionStatus


def handle_groups_command(cmd: JunosCommand, config: JuniperSRXConfig) -> bool:
    tokens = cmd.tokens[1:]
    if not tokens or not any(token.lower() in {"groups", "apply-groups"} for token in tokens):
        return False
    cmd.consumed = True
    cmd.handler = "groups"
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    group_index = next((i for i, token in enumerate(tokens) if token.lower() == "groups"), None)
    apply_index = next((i for i, token in enumerate(tokens) if token.lower() == "apply-groups"), None)
    if group_index is not None and len(tokens) > group_index + 2:
        config.configuration_groups.setdefault(tokens[group_index + 1], []).append(tokens[group_index + 2:])
    elif apply_index is not None and len(tokens) > apply_index + 1:
        config.applied_groups.setdefault("root", []).extend(tokens[apply_index + 1:])
    return True
