from fwmigrate.parsers.fortigate.model import FGApplicationEntry
from fwmigrate.parsers.fortigate.parser import (
    _effective_nested_profile_edits,
    _effective_node_attributes,
    parse_fortigate_config,
)
from fwmigrate.parsers.fortigate.source_tree import FGSourceCommand, FGSourceNode


def _command(operation: str, key: str, *values: str) -> FGSourceCommand:
    return FGSourceCommand(operation=operation, key=key, values=list(values))


def _node(*commands: FGSourceCommand) -> FGSourceNode:
    return FGSourceNode(node_type="edit", name="x", commands=list(commands))


class TestSharedProfileOperations:
    def test_repeated_scalar_set_is_last_set_wins(self):
        node = _node(
            _command("set", "action", "block"),
            _command("set", "action", "monitor"),
        )
        effective, extra = _effective_node_attributes(
            node,
            field_spec={"scalar_fields": {"action"}},
        )
        assert effective == {"action": "monitor"}
        assert extra == {}

    def test_list_set_append_unset_and_set(self):
        node = _node(
            _command("set", "category", "1", "2"),
            _command("append", "category", "3"),
            _command("unset", "category"),
            _command("set", "category", "4"),
            _command("append", "category", "5"),
        )
        effective, extra = _effective_node_attributes(
            node,
            field_spec={"list_fields": {"category"}},
        )
        assert effective == {"category": ["4", "5"]}
        assert extra == {}

    def test_append_does_not_invent_scalar_semantics(self):
        node = _node(
            _command("set", "action", "block"),
            _command("append", "action", "monitor"),
        )
        effective, extra = _effective_node_attributes(
            node,
            field_spec={"scalar_fields": {"action"}},
        )
        assert effective["action"] == "block"
        assert extra["unparsed_append_action"] == "monitor"

    def test_unset_removes_effective_field(self):
        node = _node(
            _command("set", "log", "enable"),
            _command("unset", "log"),
        )
        effective, extra = _effective_node_attributes(
            node,
            field_spec={"scalar_fields": {"log"}},
        )
        assert "log" not in effective
        assert extra == {}

    def test_malformed_integer_is_preserved(self):
        node = _node(_command("set", "limit", "not-a-number"))
        effective, extra = _effective_node_attributes(
            node,
            field_spec={"integer_fields": {"limit"}},
        )
        assert "limit" not in effective
        assert extra["unparsed_limit"] == "not-a-number"

    def test_unknown_append_is_preserved_without_guessing_field_type(self):
        node = _node(
            _command("set", "future-option", "alpha"),
            _command("append", "future-option", "beta"),
        )
        effective, extra = _effective_node_attributes(node)
        assert effective["future_option"] == "alpha"
        assert extra["future_option"] == "alpha"
        assert extra["unparsed_append_future_option"] == "beta"

    def test_secret_values_do_not_reach_effective_or_extra_settings(self):
        node = _node(_command("set", "password", "do-not-leak"))
        effective, extra = _effective_node_attributes(node)
        assert "password" not in effective
        assert "password" not in extra
        assert "do-not-leak" not in repr(effective)
        assert "do-not-leak" not in repr(extra)

    def test_nested_edit_helper_preserves_identity_order_and_source(self):
        first = FGSourceNode(
            node_type="edit",
            name="1",
            commands=[_command("set", "application", "10", "20")],
        )
        second = FGSourceNode(
            node_type="edit",
            name="2",
            commands=[_command("set", "application", "30")],
        )
        parent = FGSourceNode(
            node_type="config",
            name="entries",
            children=[first, second],
        )
        projected = _effective_nested_profile_edits(parent, FGApplicationEntry)
        assert [item["name"] for item in projected] == ["1", "2"]
        assert [item["source_order"] for item in projected] == [1, 2]
        assert projected[0]["values"]["application"] == [10, 20]
        assert projected[0]["source"] is first

    def test_source_commands_remain_lossless_while_typed_state_is_effective(self):
        parsed = parse_fortigate_config(
            '''
config antivirus profile
    edit "av"
        set status enable
        set status monitor
        unset status
        set status enable
        set future-option alpha
        append future-option beta
    next
end
'''
        )
        profile = parsed.antivirus_profiles[0]
        assert profile.status == "enable"
        assert profile.extra_settings["future_option"] == "alpha"
        assert profile.extra_settings["unparsed_append_future_option"] == "beta"

        source_object = next(
            item
            for item in parsed.structured_source_objects
            if item.source_path == "antivirus profile"
        )
        assert [command.operation for command in source_object.root.commands] == [
            "set",
            "set",
            "unset",
            "set",
            "set",
            "append",
        ]
        assert [command.key for command in source_object.root.commands][-2:] == [
            "future-option",
            "future-option",
        ]

    def test_application_integer_list_set_append_and_malformed_retention(self):
        parsed = parse_fortigate_config(
            '''
config application list
    edit "apps"
        config entries
            edit 1
                set application 100 200
                append application 300 bad-id
            next
        end
    next
end
'''
        )
        entry = parsed.application_lists[0].entries[0]
        assert entry.application == [100, 200, 300]
        assert entry.extra_settings["unparsed_append_application"] == ["bad-id"]
