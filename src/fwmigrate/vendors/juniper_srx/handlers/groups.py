from fwmigrate.vendors.juniper_srx.model import (
    JuniperConfigurationGroup, JuniperGroupApplication, JuniperGroupNode,
    JuniperGroupStatement, JuniperSRXConfig,
)
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand
from fwmigrate.extraction.models import ExtractionStatus


def handle_groups_command(cmd: JunosCommand, config: JuniperSRXConfig) -> bool:
    tokens = cmd.tokens[1:]
    if not tokens or not any(token.lower() in {"groups", "apply-groups", "apply-groups-except"} for token in tokens):
        return False
    cmd.consumed = True
    cmd.handler = "groups"
    cmd.extraction_status = ExtractionStatus.SOURCE_ONLY
    group_index = next((i for i, token in enumerate(tokens) if token.lower() == "groups"), None)
    apply_index = next((i for i, token in enumerate(tokens) if token.lower() in {"apply-groups", "apply-groups-except"}), None)
    if group_index is not None and len(tokens) > group_index + 2:
        name = tokens[group_index + 1]
        path = tokens[group_index + 2:]
        context_prefix = tokens[:group_index]
        scope = context_prefix
        context_type, context_name = "root", None
        if len(scope) >= 2 and scope[0].lower() in {"logical-systems", "tenants"}:
            context_type = "logical-system" if scope[0].lower() == "logical-systems" else "tenant"
            context_name, scope = scope[1], scope[2:]
        group_key = config.group_storage_key(name, context_type, context_name)
        group = config.configuration_groups.setdefault(
            group_key, JuniperConfigurationGroup(name=name, root_node=JuniperGroupNode(path_component=""),
                                                 context_type=context_type, context_name=context_name)
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
            for index, value in enumerate(values):
                node.applications.append(JuniperGroupApplication(
                    target_path=tuple(context_prefix + node_path),
                    ordered_groups=[value] if operation == "apply-groups" else [],
                    excluded_groups=[value] if operation == "apply-groups-except" else [],
                    source_order=cmd.line_number,
                    group_list_priority=index,
                    group_application_depth=len(node_path),
                    hierarchy_depth=len(node_path),
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
        cmd.context_type, cmd.context_name = context_type, context_name
    elif apply_index is not None and len(tokens) > apply_index + 1:
        key = " ".join(tokens[:apply_index]) or "root"
        values = tokens[apply_index + 1:]
        if tokens[apply_index].lower() == "apply-groups-except":
            config.applied_group_exceptions.setdefault(key, []).extend(values)
        else:
            config.applied_groups.setdefault(key, []).extend(values)
        if len(tokens) >= 3 and tokens[0].lower() in {"logical-systems", "tenants"}:
            cmd.context_type = "logical-system" if tokens[0].lower() == "logical-systems" else "tenant"
            cmd.context_name = tokens[1]
        else:
            cmd.context_type, cmd.context_name = "root", None
    return True
