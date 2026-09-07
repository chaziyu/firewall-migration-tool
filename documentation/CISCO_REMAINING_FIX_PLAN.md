# Cisco remaining issue disposition

This change set follows the source-parser -> canonical IR -> target-generator
architecture. It does not create ASA-to-FTD or FTD-to-ASA conversion paths.

| Area | Disposition |
|---|---|
| FMC Access Control Policy | Implemented from FMC REST export JSON bundles. |
| FMC manual/auto NAT | Implemented from FMC REST export JSON bundles. |
| FMC referenced network/service/zone/application/user objects | Implemented with explicit unresolved-reference blocking. |
| ASA address-only dynamic NAT | Canonical `dynamic-ip` translation mode added; no longer mislabeled as PAT. |
| ASA dynamic NAT with interface PAT fallback | Exact primary/fallback evidence remains source-preserved and manual-review because canonical IR has one active translation mode and no ordered fallback field. |
| ASA legacy `nat 0 access-list` exemption | Parsed and correlated as source evidence; remains extract-only because target-neutral NAT ordering/exemption semantics are not currently modeled safely. |
| ASA standard ACL | Correct destination-only IPv4 meaning retained; remains partial/manual because standard ACL attachment/consumer semantics are not equivalent to an extended transit policy. |

The last three conservative statuses are intentional safety boundaries, not
unparsed source syntax. Removing them requires adding new canonical semantics
for ordered NAT fallback/exemption or consumer-specific ACL attachment rather
than guessing a target behavior.
