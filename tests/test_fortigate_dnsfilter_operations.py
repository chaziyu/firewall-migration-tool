from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


class TestDNSFilterOperations:
    def test_root_botnet_logging_and_list_operations_are_typed(self):
        parsed = parse_fortigate_config(
            '''
config dnsfilter profile
    edit "dns44"
        set block-botnet disable
        set block-botnet enable
        set block-action block
        set block-action redirect
        set log-all-domain enable
        set sdns-domain-log enable
        set sdns-ftgd-err-log disable
        set safe-search enable
        set strip-ech enable
        set youtube-restrict strict
        set external-ip-blocklist "feed-a" "feed-b"
        append external-ip-blocklist "feed-c"
        unset external-ip-blocklist
        set external-ip-blocklist "feed-final"
        set transparent-dns-database "db-a"
        append transparent-dns-database "db-b"
    next
end
'''
        )
        profile = parsed.dnsfilter_profiles[0]
        assert profile.block_botnet == "enable"
        assert profile.block_action == "redirect"
        assert profile.log_all_domain == "enable"
        assert profile.sdns_domain_log == "enable"
        assert profile.sdns_ftgd_err_log == "disable"
        assert profile.safe_search == "enable"
        assert profile.strip_ech == "enable"
        assert profile.youtube_restrict == "strict"
        assert profile.external_ip_blocklist == ["feed-final"]
        assert profile.transparent_dns_database == ["db-a", "db-b"]
        assert len(profile.botnet) == 1
        assert profile.botnet[0].block_botnet == "enable"
        assert profile.botnet[0].block_action == "redirect"

    def test_domain_filter_reference_set_unset_set_remains_reference(self):
        parsed = parse_fortigate_config(
            '''
config dnsfilter profile
    edit "dns-ref"
        config domain-filter
            set domain-filter-table 10
            unset domain-filter-table
            set domain-filter-table 42
        end
    next
end
'''
        )
        profile = parsed.dnsfilter_profiles[0]
        assert len(profile.domain_filters) == 1
        reference = profile.domain_filters[0]
        assert reference.name == "domain-filter"
        assert reference.domain_filter_table == 42
        assert "domain" not in reference.model_dump()

    def test_domain_filter_malformed_integer_is_preserved(self):
        parsed = parse_fortigate_config(
            '''
config dnsfilter profile
    edit "dns-bad-ref"
        config domain-filter
            set domain-filter-table not-an-id
        end
    next
end
'''
        )
        reference = parsed.dnsfilter_profiles[0].domain_filters[0]
        assert reference.domain_filter_table is None
        assert reference.extra_settings["unparsed_domain_filter_table"] == "not-an-id"

    def test_ftgd_categories_preserve_order_identity_and_operations(self):
        parsed = parse_fortigate_config(
            '''
config dnsfilter profile
    edit "dns-categories"
        config ftgd-dns
            set options error-allow
            append options ftgd-disable
            unset options
            set options error-allow
            config filters
                edit 7
                    set category 10
                    set action block
                    unset action
                    set action monitor
                    set log enable
                next
                edit 3
                    set category 20
                    set action block
                    set log disable
                next
            end
        end
    next
end
'''
        )
        profile = parsed.dnsfilter_profiles[0]
        assert profile.ftgd_dns is not None
        assert profile.ftgd_dns.options == ["error-allow"]
        assert [entry.name for entry in profile.categories] == ["7", "3"]
        assert [entry.source_order for entry in profile.categories] == [1, 2]
        assert profile.categories[0].category == 10
        assert profile.categories[0].action == "monitor"
        assert profile.categories[0].log == "enable"
        assert profile.categories[1].category == 20
        assert profile.categories[1].action == "block"
        assert profile.categories[1].log == "disable"

    def test_malformed_category_id_is_preserved_without_collapsing_entries(self):
        parsed = parse_fortigate_config(
            '''
config dnsfilter profile
    edit "dns-bad-category"
        config ftgd-dns
            config filters
                edit 1
                    set category bad-id
                    set action monitor
                next
                edit 2
                    set category 5
                    set action block
                next
            end
        end
    next
end
'''
        )
        categories = parsed.dnsfilter_profiles[0].categories
        assert len(categories) == 2
        assert categories[0].category is None
        assert categories[0].extra_settings["unparsed_category"] == "bad-id"
        assert categories[1].category == 5

    def test_unknown_child_is_source_preserved_not_misclassified(self):
        parsed = parse_fortigate_config(
            '''
config dnsfilter profile
    edit "dns-source"
        set future-dns-option alpha
        config dns-translation
            edit 9
                set src 192.0.2.1
                set dst 198.51.100.1
            next
        end
    next
end
'''
        )
        profile = parsed.dnsfilter_profiles[0]
        assert profile.extra_settings["future_dns_option"] == "alpha"
        assert len(profile.categories) == 0
        assert len(profile.domain_filters) == 0
        assert len(profile.entries) == 1
        assert profile.entries[0].name == "dns-translation"

        source_object = next(
            item
            for item in parsed.structured_source_objects
            if item.source_path == "dnsfilter profile" and item.name == "dns-source"
        )
        translation = next(
            child for child in source_object.root.children
            if child.name == "dns-translation"
        )
        assert translation.children[0].name == "9"
        assert [(cmd.operation, cmd.key) for cmd in translation.children[0].commands] == [
            ("set", "src"),
            ("set", "dst"),
        ]
