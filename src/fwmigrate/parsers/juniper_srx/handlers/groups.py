from fwmigrate.parsers.juniper_srx.model import (
    JuniperConfigurationGroup, JuniperGroupApplication, JuniperGroupNode,
    JuniperGroupStatement, JuniperSRXConfig,
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
        marker = next((i for i, token in enumerate(path)
                       if token.lower() in {"apply-groups", "apply-groups-except"}), None)
        node_path = path if marker is None else path[:marker]
        node = group.root_node
        for component in node_path:
            node = node.children.setdefault(
                component, JuniperGroupNode(path_component=component, wildcard=component == "<*>")
            )
        if marker is not None:
            operation = path[marker].lower()
            values = path[marker + 1:]
            node.apply_groups.extend(values if operation == "apply-groups" else [])
            node.apply_groups_except.extend(values if operation == "apply-groups-except" else [])
            for value in values:
                node.applications.append(JuniperGroupApplication(
                    target_path=tuple(node_path),
                    ordered_groups=[value] if operation == "apply-groups" else [],
                    excluded_groups=[value] if operation == "apply-groups-except" else [],
                    source_order=cmd.line_number,
                    source_metadata={"source_group_name": name, "source_path": tuple(path),
                                     "source_line": cmd.line_number, "active": True},
                ))
                node.apply_group_provenance.append({
                    "group_name": name, "referenced_group_name": value,
                    "source_group_name": name, "source_path": tuple(path),
                    "source_order": cmd.line_number, "active": True,
                })
        elif path:
            node.statements.append(JuniperGroupStatement(
                hierarchy_path=tuple(path), leaf_keyword=path[-2] if len(path) > 1 else path[-1],
                leaf_values=path[-1:], source_order=cmd.line_number,
                source_group_name=name, source_path=tuple(path),
                source_metadata={"line_number": cmd.line_number},
            ))
    elif apply_index is not None and len(tokens) > apply_index + 1:
        key = " ".join(tokens[:apply_index]) or "root"
        values = tokens[apply_index + 1:]
        if tokens[apply_index].lower() == "apply-groups-except":
            config.applied_group_exceptions.setdefault(key, []).extend(values)
        else:
            config.applied_groups.setdefault(key, []).extend(values)
    return True
