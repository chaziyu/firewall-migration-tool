from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_webfilter_categories_url_filters_and_overrides_are_typed():
    config = '''
config webfilter profile
    edit "strict-web"
        set comment "Strict web"
        set feature-set proxy
        config ftgd-wf
            config filters
                edit 1
                    set category 1
                    set action block
                next
            end
        end
        config override
            set ovrd-cookie allow
            set profile "trusted-profile"
            set ovrd-user-group "reviewer"
        end
        config web
            set urlfilter-table 7
        end
    next
end
'''
    source = parse_fortigate_config(config).webfilter_profiles[0]
    result = extract_fortigate_config(config)
    assert source.comment == "Strict web"
    assert source.categories[0].category == 1
    assert source.categories[0].action == "block"
    assert source.overrides[0].ovrd_cookie == "allow"
    assert source.overrides[0].profile == ["trusted-profile"]
    assert source.overrides[0].ovrd_user_group == ["reviewer"]
    assert source.url_filters[0].urlfilter_table == 7
    inventory = next(item for item in result.source_sections if item.path == "webfilter profile")
    assert inventory.status == ExtractionStatus.NORMALIZED
