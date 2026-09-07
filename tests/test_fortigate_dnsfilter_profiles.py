from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_dnsfilter_domains_categories_botnet_and_actions_are_typed():
    config = '''config dnsfilter profile
    edit "dns"
        set comment "DNS policy"
        set block-botnet enable
        set block-action redirect
        config ftgd-dns
            config filters
                edit 1
                    set category 1
                    set action block
                    set log enable
                next
            end
        end
        config domain-filter
            set domain-filter-table 42
        end
    next
end
'''
    parsed = parse_fortigate_config(config)
    profile = parsed.dnsfilter_profiles[0]
    assert profile.categories[0].category == 1
    assert profile.categories[0].action == "block"
    assert profile.categories[0].log == "enable"
    assert profile.domain_filters[0].domain_filter_table == 42
    assert profile.block_action == "redirect"
    assert profile.botnet[0].block_botnet == "enable"
    assert profile.botnet[0].block_action is None
    assert next(
        item
        for item in extract_fortigate_config(config).source_sections
        if item.path == "dnsfilter profile"
    ).status == ExtractionStatus.NORMALIZED
