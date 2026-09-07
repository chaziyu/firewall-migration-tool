from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


class TestApplicationControlOperations:
    def test_root_fields_and_list_operations_are_typed(self):
        parsed = parse_fortigate_config(
            '''
config application list
    edit "app45"
        set app-replacemsg disable
        set app-replacemsg enable
        set control-default-network-services enable
        set deep-app-inspection enable
        set enforce-default-app-port disable
        set extended-log enable
        set force-inclusion-ssl-di-sigs enable
        set options allow-dns
        append options allow-icmp
        unset options
        set options allow-dns
        set p2p-block-list bittorrent skype
        append p2p-block-list edonkey
        set other-application-action block
        set other-application-log enable
        set unknown-application-action pass
        set unknown-application-log enable
        set replacemsg-group "app-msgs"
    next
end
'''
        )
        profile = parsed.application_lists[0]
        assert profile.app_replacemsg == "enable"
        assert profile.control_default_network_services == "enable"
        assert profile.deep_app_inspection == "enable"
        assert profile.enforce_default_app_port == "disable"
        assert profile.extended_log == "enable"
        assert profile.force_inclusion_ssl_di_sigs == "enable"
        assert profile.options == ["allow-dns"]
        assert profile.p2p_block_list == ["bittorrent", "skype", "edonkey"]
        assert profile.other_application_action == "block"
        assert profile.other_application_log == "enable"
        assert profile.unknown_application_action == "pass"
        assert profile.unknown_application_log == "enable"
        assert profile.replacemsg_group == "app-msgs"

    def test_default_network_services_keep_order_and_integer_port(self):
        parsed = parse_fortigate_config(
            '''
config application list
    edit "network-services"
        config default-network-services
            edit 9
                set port 443
                set services https
                append services http
                set violation-action block
            next
            edit 2
                set port 22
                set services ssh
                set violation-action monitor
            next
        end
    next
end
'''
        )
        services = parsed.application_lists[0].default_network_services
        assert [item.name for item in services] == ["9", "2"]
        assert [item.source_order for item in services] == [1, 2]
        assert services[0].port == 443
        assert services[0].services == ["https", "http"]
        assert services[0].violation_action == "block"
        assert services[1].port == 22
        assert services[1].services == ["ssh"]

    def test_entry_integer_lists_use_set_append_unset_and_preserve_malformed(self):
        parsed = parse_fortigate_config(
            '''
config application list
    edit "entry-ops"
        config entries
            edit 7
                set application 100 200
                append application 300 bad-app
                set category 2 6
                append category bad-category 7
                set exclusion 500
                append exclusion 600
                set risk 2 3
                unset risk
                set risk 4
                append risk 5 bad-risk
                set popularity 1 2
                append popularity 3
                set action block
                set action reset
                set log enable
                set log-packet enable
                set rate-count 100
                set rate-duration 60
                set session-ttl 300
            next
        end
    next
end
'''
        )
        entry = parsed.application_lists[0].entries[0]
        assert entry.name == "7"
        assert entry.application == [100, 200, 300]
        assert entry.application_id == 100
        assert entry.category == [2, 6, 7]
        assert entry.exclusion == [500, 600]
        assert entry.risk == [4, 5]
        assert entry.popularity == [1, 2, 3]
        assert entry.action == "reset"
        assert entry.log == "enable"
        assert entry.log_packet == "enable"
        assert entry.rate_count == 100
        assert entry.rate_duration == 60
        assert entry.session_ttl == 300
        assert entry.extra_settings["unparsed_append_application"] == ["bad-app"]
        assert entry.extra_settings["unparsed_append_category"] == ["bad-category"]
        assert entry.extra_settings["unparsed_append_risk"] == ["bad-risk"]

    def test_parameters_and_members_retain_identity_and_source_order(self):
        parsed = parse_fortigate_config(
            '''
config application list
    edit "parameters"
        config entries
            edit 1
                set application 12345
                config parameters
                    edit 8
                        config members
                            edit 3
                                set name "channel"
                                set value "stable"
                            next
                            edit 1
                                set name "region"
                                set value "apac"
                            next
                        end
                    next
                    edit 2
                        config members
                            edit 9
                                set name "tenant"
                                set value "corp"
                            next
                        end
                    next
                end
            next
        end
    next
end
'''
        )
        entry = parsed.application_lists[0].entries[0]
        assert [item.name for item in entry.parameters] == ["8", "2"]
        assert [item.source_order for item in entry.parameters] == [1, 2]
        assert [item.name for item in entry.parameters[0].members] == ["3", "1"]
        assert [item.parameter_name for item in entry.parameters[0].members] == ["channel", "region"]
        assert [item.value for item in entry.parameters[0].members] == ["stable", "apac"]
        assert entry.parameters[1].members[0].parameter_name == "tenant"

    def test_malformed_scalar_integer_is_preserved(self):
        parsed = parse_fortigate_config(
            '''
config application list
    edit "bad-int"
        config default-network-services
            edit 1
                set port not-a-port
                set services https
            next
        end
        config entries
            edit 1
                set rate-count not-a-count
                set session-ttl bad-ttl
            next
        end
    next
end
'''
        )
        profile = parsed.application_lists[0]
        service = profile.default_network_services[0]
        entry = profile.entries[0]
        assert service.port is None
        assert service.extra_settings["unparsed_port"] == "not-a-port"
        assert entry.rate_count is None
        assert entry.extra_settings["unparsed_rate_count"] == "not-a-count"
        assert entry.session_ttl is None
        assert entry.extra_settings["unparsed_session_ttl"] == "bad-ttl"

    def test_unknown_child_is_source_preserved_without_heuristic_typing(self):
        parsed = parse_fortigate_config(
            '''
config application list
    edit "source-only"
        set future-app-option alpha
        config future-section
            edit 1
                set category 2
                set application 99
            next
        end
    next
end
'''
        )
        profile = parsed.application_lists[0]
        assert profile.extra_settings["future_app_option"] == "alpha"
        assert profile.extra_settings["source_only_sections"] == ["future-section"]

        source_object = next(
            item
            for item in parsed.structured_source_objects
            if item.source_path == "application list" and item.name == "source-only"
        )
        assert [child.name for child in source_object.root.children] == ["future-section"]
        commands = source_object.root.children[0].children[0].commands
        assert [(cmd.operation, cmd.key) for cmd in commands] == [
            ("set", "category"),
            ("set", "application"),
        ]
