from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def test_dnsfilter_domains_categories_botnet_and_actions_are_typed():
    config = '''config dnsfilter profile
    edit "dns"
        set comment "DNS policy"
        config ftgd-dns
            edit "adult"
                set category 1
                set action block
                set redirect "blocked.example"
            next
        end
        config domain-filter
            edit "internal"
                set domain corp.example
                set action allow
            next
        end
        config botnet-domain-filter
            edit "botnet"
                set action block
            next
        end
    next
end
'''
    parsed = parse_fortigate_config(config)
    profile = parsed.dnsfilter_profiles[0]
    assert profile.categories[0].action == "block"
    assert profile.categories[0].redirect == "blocked.example"
    assert profile.domain_filters[0].domain == "corp.example"
    assert profile.domain_filters[0].action == "allow"
    assert profile.botnet[0].action == "block"
    assert next(item for item in extract_fortigate_config(config).source_sections
                if item.path == "dnsfilter profile").status == ExtractionStatus.NORMALIZED
