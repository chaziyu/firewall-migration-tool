from __future__ import annotations

import unittest

from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.transform.policies import normalize_policy_names


def policy(
    name: str | None,
    policy_id: int | None,
    vdom: str = "root",
) -> FGPolicy:
    return FGPolicy(name=name, policy_id=policy_id, vdom=vdom)


class PolicyNameTransformTest(unittest.TestCase):
    def test_long_unique_name_keeps_first_pass_suffix(self):
        item = normalize_policy_names(
            FGConfig(policies=[policy("a" * 40, 1)])
        )[0]

        self.assertTrue(item.normalized_name.endswith("-L"))
        self.assertLessEqual(len(item.normalized_name), 32)
        self.assertTrue(item.truncated)
        self.assertFalse(item.collision)

    def test_long_collision_uses_policy_ids(self):
        items = normalize_policy_names(
            FGConfig(
                policies=[
                    policy("a" * 32 + "A", 1470),
                    policy("a" * 32 + "B", 1471),
                ]
            )
        )

        names = [item.normalized_name for item in items]
        self.assertEqual(names, ["a" * 26 + "-L1470", "a" * 26 + "-L1471"])
        self.assertEqual(len(set(names)), 2)
        self.assertTrue(all(len(name) <= 32 for name in names))
        self.assertTrue(all(item.truncated and not item.collision for item in items))

    def test_three_name_collision_group_is_unique(self):
        items = normalize_policy_names(
            FGConfig(
                policies=[
                    policy("shared-prefix-" + "x" * 20 + "A", 1),
                    policy("shared-prefix-" + "x" * 20 + "B", 2),
                    policy("shared-prefix-" + "x" * 20 + "C", 3),
                ]
            )
        )

        names = [item.normalized_name for item in items]
        self.assertEqual(len(set(names)), 3)
        self.assertTrue(all(name.endswith(f"-L{index}") for index, name in enumerate(names, 1)))
        self.assertTrue(all(not item.collision for item in items))

    def test_generated_name_respects_reserved_short_name(self):
        items = normalize_policy_names(
            FGConfig(
                policies=[
                    policy("a" * 40, 1),
                    policy("a" * 29 + "-L1", 2),
                    policy("a" * 40 + "different", 3),
                ]
            )
        )

        self.assertTrue(items[0].collision)
        self.assertFalse(items[1].collision)
        self.assertFalse(items[2].collision)

    def test_missing_policy_id_stays_unresolved(self):
        item = normalize_policy_names(
            FGConfig(
                policies=[
                    policy("a" * 40, None),
                    policy("a" * 41, 2),
                ]
            )
        )[0]

        self.assertEqual(item.normalized_name, "a" * 30 + "-L")
        self.assertTrue(item.collision)

    def test_short_duplicate_is_not_renamed(self):
        items = normalize_policy_names(
            FGConfig(policies=[policy("same", 1), policy("same", 2)])
        )

        self.assertEqual([item.normalized_name for item in items], ["same", "same"])
        self.assertTrue(all(item.collision for item in items))

    def test_same_name_in_different_vdoms_is_allowed(self):
        items = normalize_policy_names(
            FGConfig(
                policies=[
                    policy("a" * 40, 1, "root"),
                    policy("a" * 40, 2, "vdom2"),
                ]
            )
        )

        self.assertTrue(all(not item.collision for item in items))


if __name__ == "__main__":
    unittest.main()

