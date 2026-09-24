import unittest

from fwmigrate.vendors.fortigate.section_registry import (
    SECTION_REGISTRY,
    get_section_spec,
)


class SectionRegistryTest(unittest.TestCase):
    def test_public_registry_is_read_only(self):
        self.assertIsNotNone(get_section_spec("system interface"))

        with self.assertRaises(TypeError):
            SECTION_REGISTRY["test"] = get_section_spec("system interface")


if __name__ == "__main__":
    unittest.main()

