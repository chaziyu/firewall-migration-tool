"""Regression tests for FortiGate Application Control list parsing."""

import pytest
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_application_list_single_category():
    """Test 1: Single category preserves [int]."""
    config = '''config application list
    edit "Test"
        config entries
            edit 1
                set category 2
            next
        end
    next
end
'''
    parsed = parse_fortigate_config(config)
    assert len(parsed.application_lists) == 1
    profile = parsed.application_lists[0]
    assert len(profile.entries) == 1
    entry = profile.entries[0]
    assert entry.category == [2]
    assert isinstance(entry.category, list)
    assert entry.category[0] == 2
    assert isinstance(entry.category[0], int)


def test_application_list_multiple_categories():
    """Test 2: Multiple categories preserves full list."""
    config = '''config application list
    edit "Test"
        config entries
            edit 1
                set category 2 6 7
            next
        end
    next
end
'''
    parsed = parse_fortigate_config(config)
    assert len(parsed.application_lists) == 1
    profile = parsed.application_lists[0]
    assert len(profile.entries) == 1
    entry = profile.entries[0]
    assert entry.category == [2, 6, 7]
    assert isinstance(entry.category, list)
    assert all(isinstance(val, int) for val in entry.category)


def test_application_list_multiple_applications():
    """Test 3: Multiple application IDs preserves full list."""
    config = '''config application list
    edit "Test"
        config entries
            edit 1
                set application 1234 5678
            next
        end
    next
end
'''
    parsed = parse_fortigate_config(config)
    assert len(parsed.application_lists) == 1
    profile = parsed.application_lists[0]
    assert len(profile.entries) == 1
    entry = profile.entries[0]
    assert entry.application == [1234, 5678]
    assert isinstance(entry.application, list)
    assert all(isinstance(val, int) for val in entry.application)


def test_application_list_multiple_risks():
    """Test 4: Multiple risk values preserves full list."""
    config = '''config application list
    edit "Test"
        config entries
            edit 1
                set risk 2 3 4
            next
        end
    next
end
'''
    parsed = parse_fortigate_config(config)
    assert len(parsed.application_lists) == 1
    profile = parsed.application_lists[0]
    assert len(profile.entries) == 1
    entry = profile.entries[0]
    assert entry.risk == [2, 3, 4]
    assert isinstance(entry.risk, list)
    assert all(isinstance(val, int) for val in entry.risk)


def test_application_list_multiple_entries_independent_values():
    """Test 5: Multiple entries in application list remain independent."""
    config = '''config application list
    edit "Test"
        config entries
            edit 1
                set category 2 6 7
                set action block
            next
            edit 2
                set application 1234 5678
                set risk 3 4
                set action pass
            next
        end
    next
end
'''
    parsed = parse_fortigate_config(config)
    assert len(parsed.application_lists) == 1
    profile = parsed.application_lists[0]
    assert len(profile.entries) == 2
    entry1 = profile.entries[0]
    entry2 = profile.entries[1]
    assert entry1.category == [2, 6, 7]
    assert entry1.action == "block"
    assert entry1.application == []
    assert entry1.risk == []
    assert entry2.application == [1234, 5678]
    assert entry2.risk == [3, 4]
    assert entry2.action == "pass"
    assert entry2.category == []
