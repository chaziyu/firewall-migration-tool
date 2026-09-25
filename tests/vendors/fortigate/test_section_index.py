import unittest
from fwmigrate.vendors.fortigate.section_registry import (
    SECTION_REGISTRY,
    get_section_spec,
)
from fwmigrate.vendors.fortigate.extraction.section_index import SectionIndex
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config


def test_section_index_preserves_order_and_vdom_context():
    tree = parse_fortigate_config(
        """
config firewall address
    edit root-address
    next
end
config vdom
    edit tenant-a
        config firewall address
            edit a-address
            next
            edit a-second
            next
        end
        config system interface
            edit port1
                config secondaryip
                    edit 1
                    next
                end
            next
        end
    next
    edit tenant-b
        config firewall address
            edit b-address
            next
        end
    next
end
"""
    )

    index = SectionIndex.build(tree)

    assert [entry.node.name for entry in index.entries] == [
        "firewall address",
        "firewall address",
        "system interface",
        "secondaryip",
        "firewall address",
    ]
    assert [source.edit.name for source in index.iter_edits("firewall address")] == [
        "root-address",
        "a-address",
        "a-second",
        "b-address",
    ]
    assert [source.vdom for source in index.iter_edits("firewall address")] == [
        "root",
        "tenant-a",
        "tenant-a",
        "tenant-b",
    ]
    assert index.entries[3].source_path == "system interface secondaryip"
    assert index.entries[3].parent_objects == ("port1",)
    assert [entry.source_path for entry in index.source_entries] == [
        "firewall address",
        "firewall address",
        "system interface",
        "system interface secondaryip",
        "firewall address",
    ]


def test_section_index_keeps_empty_sections_and_excludes_vdom_control_node():
    tree = parse_fortigate_config(
        """
config vdom
    edit root
        config empty section
        end
    next
end
"""
    )

    index = SectionIndex.build(tree)

    assert [entry.node.name for entry in index.entries] == ["empty section"]
    assert list(index.iter_configs("empty section"))[0].vdom == "root"
    assert list(index.iter_edits("empty section")) == []


def test_section_index_keeps_duplicate_sections_and_source_order():
    tree = parse_fortigate_config(
        """
config system sdwan
    set status enable
end
config firewall address
    edit first
    next
end
config vdom
    edit tenant-a
        config system sdwan
            set status disable
        end
        config firewall address
            edit second
            next
        end
    next
end
config system sdwan
    set status disable
end
"""
    )

    index = SectionIndex.build(tree)

    configs = list(index.iter_configs("system sdwan"))
    assert [config.vdom for config in configs] == [
        "root",
        "tenant-a",
        "root",
    ]
    assert [config.config.commands[0].values for config in configs] == [
        ["enable"],
        ["disable"],
        ["disable"],
    ]

    edits = list(index.iter_edits("firewall address"))
    assert [edit.edit.name for edit in edits] == ["first", "second"]
    assert [edit.vdom for edit in edits] == ["root", "tenant-a"]


def test_section_index_returns_empty_for_unregistered_sections():
    tree = parse_fortigate_config(
        """
config system interface
end
"""
    )

    index = SectionIndex.build(tree)

    assert list(index.iter_configs("not registered")) == []
    assert list(index.iter_edits("not registered")) == []


class SectionRegistryTest(unittest.TestCase):
    def test_public_registry_is_read_only(self):
        self.assertIsNotNone(get_section_spec("system interface"))

        with self.assertRaises(TypeError):
            SECTION_REGISTRY["test"] = get_section_spec("system interface")
