from fwmigrate.parsers.juniper_srx.model import (
    JuniperConfigurationGroup, JuniperGroupNode, JuniperGroupStatement, JuniperSRXConfig,
)
from fwmigrate.parsers.juniper_srx.tokenizer import JunosCommand
from fwmigrate.extraction.models import ExtractionStatus


def handle_groups_command(cmd: JunosCommand, config: JuniperSRXConfig) -> bool:
    tokens = cmd.tokens[1:]
    if not tokens or not any(token.lower() in {"groups", "apply-groups", "apply-groups-except"} for token in tokens):
        return False
    cmd.consumed = True
    cmd.handler = "groups"
    cmd.extraction_status = ExtractionStatus.EXTRACT_ONLY
    group_index = next((i for i, token in enumerate(tokens) if token.lower() == "groups"), None)
    apply_index = next((i for i, token in enumerate(tokens) if token.lower() in {"apply-groups", "apply-groups-except"}), None)
    if group_index is not None and len(tokens) > group_index + 2:
        name = tokens[group_index + 1]
        path = tokens[group_index + 2:]
        group = config.configuration_groups.setdefault(
            name, JuniperConfigurationGroup(name=name, root_node=JuniperGroupNode(path_component=""))
        )
        node = group.root_node
        for component in path[:-1]:
            node = node.children.setdefault(
                component, JuniperGroupNode(path_component=component, wildcard=component == "<*>")
            )
        if path:
            node.statements.append(JuniperGroupStatement(
                hierarchy_path=tuple(path),
                leaf_keyword=path[-2] if len(path) > 1 else path[-1],
                leaf_values=path[-1:],
                source_order=cmd.line_number, source_metadata={"line_number": cmd.line_number},
            ))
            if path[0].lower() in {"apply-groups", "apply-groups-except"}:
                values = path[1:]
                node.apply_groups.extend(values if path[0].lower() == "apply-groups" else [])
                node.apply_groups_except.extend(values if path[0].lower() == "apply-groups-except" else [])
                node.apply_group_provenance.extend({
                    "group_name": name,
                    "referenced_group_name": value,
                    "source_group_name": name,
                    "source_path": tuple(path),
                    "source_order": cmd.line_number,
                    "active": True,
                } for value in values)
    elif apply_index is not None and len(tokens) > apply_index + 1:
        key = " ".join(tokens[:apply_index]) or "root"
        values = tokens[apply_index + 1:]
        if tokens[apply_index].lower() == "apply-groups-except":
            config.applied_group_exceptions.setdefault(key, []).extend(values)
        else:
            config.applied_groups.setdefault(key, []).extend(values)
    return True
