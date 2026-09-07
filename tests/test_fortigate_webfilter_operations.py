from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


class TestWebFilterOperations:
    def test_root_fields_and_list_operations_are_typed(self):
        parsed = parse_fortigate_config(
            '''
config webfilter profile
    edit "wf43"
        set feature-set flow
        set feature-set proxy
        set extended-log enable
        set inspection-mode flow-based
        set status enable
        set log-all-url enable
        set options activexfilter cookiefilter
        append options javafilter
        unset options
        set options block-invalid-url
        append options js
        set ovrd-perm bannedword-override
        append ovrd-perm urlfilter-override
        set web-url-log enable
        set web-content-log enable
        set wisp-servers "wisp-a" "wisp-b"
        append wisp-servers "wisp-c"
    next
end
'''
        )
        profile = parsed.webfilter_profiles[0]
        assert profile.feature_set == "proxy"
        assert profile.extended_log == "enable"
        assert profile.inspection_mode is None
        assert profile.status is None
        assert profile.extra_settings["inspection_mode"] == "flow-based"
        assert profile.extra_settings["status"] == "enable"
        assert profile.log_all_url == "enable"
        assert profile.options == ["block-invalid-url", "js"]
        assert profile.ovrd_perm == ["bannedword-override", "urlfilter-override"]
        assert profile.web_url_log == "enable"
        assert profile.web_content_log == "enable"
        assert profile.wisp_servers == ["wisp-a", "wisp-b", "wisp-c"]

    def test_ftgd_filters_keep_category_identity_order_and_effective_operations(self):
        parsed = parse_fortigate_config(
            '''
config webfilter profile
    edit "wf-categories"
        config ftgd-wf
            set options error-allow
            append options rate-image-urls
            set max-quota-timeout 600
            config filters
                edit 10
                    set category 52
                    set category 53
                    set action block
                    set auth-usr-grp "grp-a"
                    append auth-usr-grp "grp-b"
                    set log enable
                next
                edit 20
                    set category 91
                    unset category
                    set action monitor
                next
            end
        end
    next
end
'''
        )
        profile = parsed.webfilter_profiles[0]
        assert profile.ftgd_wf is not None
        assert profile.ftgd_wf.options == ["error-allow", "rate-image-urls"]
        assert profile.ftgd_wf.max_quota_timeout == 600
        assert [entry.name for entry in profile.categories] == ["10", "20"]
        assert [entry.source_order for entry in profile.categories] == [1, 2]
        assert profile.categories[0].category == 53
        assert profile.categories[0].action == "block"
        assert profile.categories[0].auth_usr_grp == ["grp-a", "grp-b"]
        assert profile.categories[0].log == "enable"
        assert profile.categories[1].category is None
        assert profile.categories[1].action == "monitor"

    def test_urlfilter_table_stays_reference_and_supports_replace_unset(self):
        parsed = parse_fortigate_config(
            '''
config webfilter profile
    edit "wf-urlref"
        config web
            set urlfilter-table 10
            set urlfilter-table 20
            unset urlfilter-table
            set urlfilter-table 30
            set bword-table 7
            set content-header-list 9
            set keyword-match "credential" "malware"
            append keyword-match "phishing"
            set safe-search url header
        end
    next
end
'''
        )
        web = parsed.webfilter_profiles[0].url_filters[0]
        assert web.name == "web"
        assert web.urlfilter_table == 30
        assert isinstance(web.urlfilter_table, int)
        assert web.bword_table == 7
        assert web.content_header_list == 9
        assert web.keyword_match == ["credential", "malware", "phishing"]
        assert web.safe_search == ["url", "header"]
        assert not hasattr(web, "entries")

    def test_override_section_is_distinct_and_keeps_references(self):
        parsed = parse_fortigate_config(
            '''
config webfilter profile
    edit "wf-override"
        config override
            set ovrd-cookie allow
            set ovrd-dur 30
            set ovrd-dur-mode constant
            set ovrd-scope user-group
            set ovrd-user-group "admins"
            append ovrd-user-group "helpdesk"
            set profile "temporary-web"
            append profile "restricted-web"
            set profile-type list
        end
        config antiphish
            set status enable
        end
    next
end
'''
        )
        profile = parsed.webfilter_profiles[0]
        assert len(profile.overrides) == 1
        override = profile.overrides[0]
        assert override.name == "override"
        assert override.ovrd_cookie == "allow"
        assert override.ovrd_scope == "user-group"
        assert override.ovrd_user_group == ["admins", "helpdesk"]
        assert override.profile == ["temporary-web", "restricted-web"]
        assert override.profile_type == "list"
        assert [entry.name for entry in profile.entries] == ["antiphish"]

    def test_multiple_documented_nested_entries_retain_order(self):
        parsed = parse_fortigate_config(
            '''
config webfilter profile
    edit "wf-order"
        config ftgd-wf
            config filters
                edit 3
                    set category 3
                    set action block
                next
                edit 1
                    set category 1
                    set action monitor
                next
                edit 2
                    set category 2
                    set action warning
                next
            end
            config quota
                edit 9
                    set category 52
                    set value 100
                    set unit MB
                next
                edit 4
                    set category 53
                    set value 200
                    set unit MB
                next
            end
        end
    next
end
'''
        )
        profile = parsed.webfilter_profiles[0]
        assert [entry.name for entry in profile.categories] == ["3", "1", "2"]
        assert [entry.source_order for entry in profile.categories] == [1, 2, 3]
        assert [quota.name for quota in profile.ftgd_wf.quotas] == ["9", "4"]
        assert [quota.source_order for quota in profile.ftgd_wf.quotas] == [1, 2]
        assert [quota.value for quota in profile.ftgd_wf.quotas] == [100, 200]

    def test_malformed_typed_values_and_unknown_fields_are_preserved(self):
        parsed = parse_fortigate_config(
            '''
config webfilter profile
    edit "wf-malformed"
        set future-web-setting alpha
        config web
            set urlfilter-table invalid-id
            set future-web-child beta
        end
        config ftgd-wf
            config filters
                edit 1
                    set category bad-category
                    set future-filter-option gamma
                next
            end
        end
    next
end
'''
        )
        profile = parsed.webfilter_profiles[0]
        web = profile.url_filters[0]
        category = profile.categories[0]
        assert profile.extra_settings["future_web_setting"] == "alpha"
        assert web.urlfilter_table is None
        assert web.extra_settings["unparsed_urlfilter_table"] == "invalid-id"
        assert web.extra_settings["future_web_child"] == "beta"
        assert category.category is None
        assert category.extra_settings["unparsed_category"] == "bad-category"
        assert category.extra_settings["future_filter_option"] == "gamma"

    def test_source_hierarchy_and_operations_remain_lossless(self):
        parsed = parse_fortigate_config(
            '''
config webfilter profile
    edit "wf-source"
        set log-all-url disable
        set log-all-url enable
        config ftgd-wf
            config filters
                edit 7
                    set category 52
                    set action block
                    unset action
                    set action monitor
                next
            end
        end
        config web
            set urlfilter-table 11
            unset urlfilter-table
            set urlfilter-table 12
        end
    next
end
'''
        )
        source_object = next(
            item
            for item in parsed.structured_source_objects
            if item.source_path == "webfilter profile" and item.name == "wf-source"
        )
        assert [(c.operation, c.key) for c in source_object.root.commands] == [
            ("set", "log-all-url"),
            ("set", "log-all-url"),
        ]
        ftgd = next(child for child in source_object.root.children if child.name == "ftgd-wf")
        filters = next(child for child in ftgd.children if child.name == "filters")
        entry = filters.children[0]
        assert [(c.operation, c.key) for c in entry.commands] == [
            ("set", "category"),
            ("set", "action"),
            ("unset", "action"),
            ("set", "action"),
        ]
        web = next(child for child in source_object.root.children if child.name == "web")
        assert [(c.operation, c.key) for c in web.commands] == [
            ("set", "urlfilter-table"),
            ("unset", "urlfilter-table"),
            ("set", "urlfilter-table"),
        ]
