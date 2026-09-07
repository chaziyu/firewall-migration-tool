"""Regression checks derived from the FortiOS 7.4.6 CLI field scope."""

from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_application_entry_undocumented_inherited_status_stays_source_only():
    parsed = parse_fortigate_config(
        '''
config application list
    edit "strict-app"
        config entries
            edit 1
                set application 100
                set status enable
                set action block
            next
        end
    next
end
'''
    )

    entry = parsed.application_lists[0].entries[0]
    assert entry.application == [100]
    assert entry.action == "block"
    assert entry.status is None
    assert entry.extra_settings["status"] == "enable"
