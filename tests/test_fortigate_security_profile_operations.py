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


class TestAntivirusOperations:
    def test_root_av_documented_fields_are_typed_with_effective_operations(self):
        parsed = parse_fortigate_config(
            '''
config antivirus profile
    edit "av42"
        set feature-set flow
        set feature-set proxy
        set av-virus-log enable
        set analytics-accept-filetype 12
        set analytics-ignore-filetype 7
        set fortisandbox-max-upload 25
        set external-blocklist "malware-a" "malware-b"
        append external-blocklist "malware-c"
        unset external-blocklist
        set external-blocklist "malware-final"
        set fortisandbox-mode inline
        set fortisandbox-error-action block
        set fortisandbox-timeout-action log-only
        set fortindr-error-action block
        set fortindr-timeout-action ignore
        set outbreak-prevention-archive-scan enable
        set extended-log enable
    next
end
'''
        )
        profile = parsed.antivirus_profiles[0]
        assert profile.feature_set == "proxy"
        assert profile.av_virus_log == "enable"
        assert profile.analytics_accept_filetype == 12
        assert profile.analytics_ignore_filetype == 7
        assert profile.fortisandbox_max_upload == 25
        assert profile.external_blocklist == ["malware-final"]
        assert profile.fortisandbox_mode == "inline"
        assert profile.fortisandbox_error_action == "block"
        assert profile.fortisandbox_timeout_action == "log-only"
        assert profile.fortindr_error_action == "block"
        assert profile.fortindr_timeout_action == "ignore"
        assert profile.outbreak_prevention_archive_scan == "enable"
        assert profile.extended_log == "enable"

    def test_malformed_root_integer_is_preserved_without_defaulting(self):
        parsed = parse_fortigate_config(
            '''
config antivirus profile
    edit "av-bad-int"
        set fortisandbox-max-upload invalid-size
    next
end
'''
        )
        profile = parsed.antivirus_profiles[0]
        assert profile.fortisandbox_max_upload is None
        assert profile.extra_settings["unparsed_fortisandbox_max_upload"] == "invalid-size"

    def test_protocol_fields_use_shared_set_append_unset_semantics(self):
        parsed = parse_fortigate_config(
            '''
config antivirus profile
    edit "av-protocols"
        config http
            set archive-block encrypted corrupted
            append archive-block timeout
            unset archive-block
            set archive-block nested
            append archive-block multipart
            set archive-log encrypted
            append archive-log corrupted
            set av-scan block
            set av-scan monitor
            set content-disarm enable
            set emulator disable
            set external-blocklist monitor
            set fortindr block
            set fortisandbox monitor
            set outbreak-prevention block
            set quarantine enable
        end
    next
end
'''
        )
        protocol = parsed.antivirus_profiles[0].protocols[0]
        assert protocol.name == "http"
        assert protocol.archive_block == ["nested", "multipart"]
        assert protocol.archive_log == ["encrypted", "corrupted"]
        assert protocol.av_scan == "monitor"
        assert protocol.content_disarm == "enable"
        assert protocol.emulator == "disable"
        assert protocol.external_blocklist == "monitor"
        assert protocol.fortindr == "block"
        assert protocol.fortisandbox == "monitor"
        assert protocol.outbreak_prevention == "block"
        assert protocol.quarantine == "enable"

    def test_cifs_and_mapi_are_distinct_typed_protocols_in_source_order(self):
        parsed = parse_fortigate_config(
            '''
config antivirus profile
    edit "av-more-protocols"
        config cifs
            set av-scan block
            set archive-log encrypted
        end
        config mapi
            set av-scan monitor
            set executables virus
        end
    next
end
'''
        )
        protocols = parsed.antivirus_profiles[0].protocols
        assert [protocol.name for protocol in protocols] == ["cifs", "mapi"]
        assert protocols[0].av_scan == "block"
        assert protocols[0].archive_log == ["encrypted"]
        assert protocols[1].av_scan == "monitor"
        assert protocols[1].executables == "virus"

    def test_content_disarm_and_nac_quarantine_configs_are_typed_separately(self):
        parsed = parse_fortigate_config(
            '''
config antivirus profile
    edit "av-configs"
        config content-disarm
            set detect-only enable
            set error-action block
            set office-macro enable
            set original-file-destination fortisandbox
            set pdf-javacode enable
        end
        config nac-quar
            set infected quar-src-ip
            set log enable
            set expiry 30
        end
    next
end
'''
        )
        configs = parsed.antivirus_profiles[0].configs
        assert [config.name for config in configs] == ["content-disarm", "nac-quar"]
        assert configs[0].detect_only == "enable"
        assert configs[0].error_action == "block"
        assert configs[0].office_macro == "enable"
        assert configs[0].original_file_destination == "fortisandbox"
        assert configs[0].pdf_javacode == "enable"
        assert configs[1].infected == "quar-src-ip"
        assert configs[1].log == "enable"
        assert configs[1].expiry == "30"

    def test_unknown_av_fields_remain_extra_settings_and_source_commands_survive(self):
        parsed = parse_fortigate_config(
            '''
config antivirus profile
    edit "av-source"
        set future-av-option alpha
        config smtp
            set av-scan block
            set future-protocol-option beta
            unset av-scan
            set av-scan monitor
        end
    next
end
'''
        )
        profile = parsed.antivirus_profiles[0]
        protocol = profile.protocols[0]
        assert profile.extra_settings["future_av_option"] == "alpha"
        assert protocol.extra_settings["future_protocol_option"] == "beta"
        assert protocol.av_scan == "monitor"

        source_object = next(
            item
            for item in parsed.structured_source_objects
            if item.source_path == "antivirus profile" and item.name == "av-source"
        )
        smtp = next(child for child in source_object.root.children if child.name == "smtp")
        assert [(command.operation, command.key) for command in smtp.commands] == [
            ("set", "av-scan"),
            ("set", "future-protocol-option"),
            ("unset", "av-scan"),
            ("set", "av-scan"),
        ]
