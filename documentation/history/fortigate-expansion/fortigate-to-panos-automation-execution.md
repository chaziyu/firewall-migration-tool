# FortiGate to PAN-OS automation execution status

2026-10-20. The 14-phase plan is **partly implemented**, not complete.
PAN-OS 11.1 is the command baseline. No PA-820 hardware assumption was added.
Existing unrelated working-tree edits were preserved. No commit or live-device
operation was performed.

## Changes implemented

- Added version-verified 7.2.13 effective values for omitted IPv4 address
  type/subnet, IP-pool type, VIP port protocol, policy NAT/status and DHCP modes.
  Source models remain explicit and unchanged. Each derived value retains its
  version and official reference.
- Separated IPv4 and IPv6 address identities and bindings in the web and CLI
  paths. Unsupported IPv6 evidence remains visible.
- Classified explicit routing eligibility and checked associated-interface
  restrictions against direct/nested policy consumers before converting them.
- Added bounded static interface-subnet conversion, including interface approval,
  renderability and prefix dependencies.
- Added vendor-native PAN management-profile extraction, source accounting and
  exact reuse checks. Incomplete, unknown, inherited or conflicting evidence
  cannot become exact reuse.
- Corrected NAT precedence classification to recognize a version-derived deny.
  This does not make unsupported VIP policy semantics executable.
- Extended combined static VIP/pool SNAT from one isolated policy to a complete
  bounded set of isolated policy partitions. Overlap, missing partitions,
  identity/time differences and uncertain translation remain blocked.
- Preserved ordered supported IKE DH lists for one supported proposal.
  Multi-proposal cross products and authenticated tunnel generation remain gated.
- Added regression tests and official-reference/support-boundary notes in
  `fortigate-to-panos-automation-evidence.md`.

## Plan phase ledger

| Phase | Current state | Remaining work or gate |
| --- | --- | --- |
| 1. Source/target evidence | Partial | Verified source defaults implemented; target capabilities and corrected/missing source evidence still required. |
| 2. Addresses | Partial | Family binding, bounded association/routing and interface-subnet support implemented; dynamic identities and unsupported/invalid forms remain. |
| 3. Interfaces/management | Partial | Exact profile reuse implemented; full placement, additional interface semantics and hardware checks need explicit design/evidence. |
| 4. Routing/DHCP | Partial | DHCP consumes verified modes; route-priority/ECMP and remaining DHCP options need implementation and equivalence checks. |
| 5. Protocols/schedules | Pending | General IP/ICMP application selectors and overnight/timezone conversion are not implemented. |
| 6. VIP-aware policy semantics | Partial | Derived-deny classification corrected; the general VIP-aware policy compiler/equivalence checker is not implemented. |
| 7. Joint NAT | Partial | Isolated static partitions implemented; arbitrary joint NAT/no-NAT partitioning remains unimplemented. |
| 8. Protection/decryption | Pending | Profile-definition extraction, content crosswalks, target proof and decryption planning are still required. |
| 9. VPN | Partial | IKE DH lists implemented; gateway/tunnel rendering, full comparison and secure authentication prerequisites remain. |
| 10. Identity/admin | Pending | Verified authentication/provisioning and permission mappings, plus executable planning/rendering, remain. |
| 11. Dynamic resources | Pending | EDL/DAG/EMS/ISDB/wildcard behavior and any necessary runtime integration remain. |
| 12. GlobalProtect | Pending | Approved replacement design, authentication/certificates, client behavior and executable planning remain. |
| 13. Residual coverage | Pending | Reachability/exclusion outcomes and approved replacements for non-equivalent features remain. Source coverage stays visible. |
| 14. End-to-end validation | Local path tested | New covered behavior tested; operational/lab acceptance and validation of unimplemented families remain. |

Pending implementation is distinct from missing input. The ledger does not
describe all outstanding work as a target-evidence problem. No warning was
removed merely to count an unsupported feature as converted.

## Supplied configuration validation

Raw input file SHA-256:
`8ab528b1f9627c96f9321cade26ef3c25c79d9a1e1169561fbfb6893d1557881`.

Sanitized source SHA-256:
`1a2e849109f7daf6a1997803f93980b6c235eaffab197f2614d39c925da8cb41`.

The local Flask workflow used PAN-OS 11.1 settings without a target model:
source preview -> prepare -> reject unapproved build -> explicit test approval
of all ready rows -> build -> command preview -> download -> bundle.

- Output: 9,995 command lines and 7,775 included plan items.
- Earlier equivalent offline API run: 9,146 lines and 6,935 included items.
- Increase: 849 lines and 840 items. Included addresses: 4,646 -> 5,421;
  address groups: 126 -> 182; normalized services: 1,786 -> 1,795.
- Security rules, NAT rules and static routes in this supplied file still have
  **zero rendered commands**. The artifact remains `NEEDS_MAPPING`, with offline
  deployment eligibility false. It is not a complete firewall migration.
- All 83 source interfaces are accounted for in this selection: 79 plan rows
  plus 4 remaining-source rows. Most planned interfaces remain blocked. This
  selection differs from the earlier browser selection of 8 planned interfaces
  plus 75 remaining-source rows; do not compare their coverage counts as equal
  approval scopes.
- The current artifact has 656 remaining-source records. These are additional
  coverage records, not the number of all excluded plan items.
- Preview/download/bundle bytes match and the command SHA-256 is
  `bf64f35176c835fc15b956f2ed827f718bdcb8f5d84954c21e4e5f85f3e9b92e`.
- An independent output audit compared included address values/group bindings
  and serialized service fields with source/derived evidence. Excluded items
  had no commands. All command rows were accounted for.
- The audit checked 543 distinct redacted source tokens against saved draft,
  report, artifact and command outputs; no matches were found. This is a bounded
  scan, not a claim that arbitrary credentials were exhaustively detected.

Detailed local evidence is under
`C:\Users\ziyu.cha-c\Downloads\migration-review-20261020\automation-execution`.
Its artifact uses an ephemeral local test approval and is for review only.

## Checks

- A complete Python run executed: 2,833 passed, 1 skipped, 16 subtests passed,
  and 1 pre-existing failure in
  `tests/architecture/test_web_migration_boundary.py::test_web_uses_pair_application_facade_for_migration_semantics`.
  The failure is the unchanged Check Point web import of its requirements module.
- After the final address-dependency checks and model-independent mapping
  regression, the affected conversion and PAN registry suites passed: 628 tests.
  The earlier full run is not claimed as a run of those final additions.
- Frontend: 181 tests passed; lint and production build passed. The build retained
  its existing chunk-size warning.
- Python compile, Ruff and whitespace checks passed during implementation.
- Browser UI was not rerun in this stage. The actual HTTP approval/export path
  was exercised with Flask's local test client.
- No live firewall, peer, DHCP client, identity provider, feed update or
  GlobalProtect client was tested. Candidate validation/commit were not invoked.

The next implementation dependency is the VIP-aware source/target traffic
semantics in phases 6-7, with explicit original/post-NAT zone evidence. Completing
this and the other pending phases is required before calling the 14-phase plan
complete.
