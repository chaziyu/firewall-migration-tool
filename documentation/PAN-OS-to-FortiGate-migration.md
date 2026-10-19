# PAN-OS to FortiGate migration

Implemented on 2026-10-17. This is reviewed FortiOS CLI export, not device
deployment or a complete replacement firewall configuration.

## Workflow

1. Upload PAN-OS XML through Configuration report or Plan migration.
2. Open Plan migration. PAN-OS sources select FortiGate as their target.
3. Review the automatically prepared conversion. A sole standalone device/VSYS
   is selected; multiple scopes require a selection. Managed inheritance stays manual.
4. Open Mappings and remaining choices. Review the proposed target profile,
   VDOM, zones, and routing placement. Declare actual physical ports once when
   destination evidence cannot establish available ports. Interface and VLAN
   allocations are proposals; confirm hardware ownership and cabling.
5. Resolve remaining policy choices individually or preview and apply a bulk
   choice. Existing individual choices are preserved. Unsupported policies stay
   visible without ineffective omitted-field questions.
6. Review the updated conversion and blocked/manual work. Destination evidence
   may populate explicit settings but does not authorize overwrite or live execution.
7. Select configuration, review exact settings and expanded prerequisites, then
   explicitly approve and generate commands.
8. Download `fortigate_config.conf` or `migration_palo_alto_to_fortigate.zip`.

Mappings, drafts, approvals, and artifacts remain in memory. Source/scope,
mapping, profile, or destination edits revoke approval and artifacts.
Failed validation preserves entered values. Failed generation can retry the
current signed approval. Mapping JSON export/import restores proposals only.
Source changes, expiration, and server signing-key changes can require reapproval.

## Supported subset

- XML source analysis uses the existing PAN-OS source reporter, scoped reference
  resolutions, topology, extraction issues, and source inventory.
- One explicit standalone VSYS per migration. Shared objects retain identity.
  Ambiguous visible objects remain blocked; the converter does not invent
  shared/local precedence. Managed Panorama/template inheritance remains manual.
- Target command baseline: FortiOS 7.4.6, NAT operating mode, profile-based NGFW.
   Offline profile values are visible target-design proposals included in final
   approval. Explicit destination settings are used when available; unsupported
   modes/versions stay blocked. The converter never changes device modes.
- For standalone local PAN-OS 11.1 rules only, documented effective rule type,
  session logging, source-user and absent-schedule behavior is derived separately
  from explicit XML. Each derived value carries version and official reference.
  Disabled state, address negation and category omissions still require target
  choices. Unknown versions and managed inheritance are not defaulted.
  References: [rule settings](https://docs.paloaltonetworks.com/ngfw/help/11-1/policies/policies-security/building-blocks-in-a-security-policy-rule)
  and [source-user behavior](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/security-policy/create-a-security-policy-rule).
- IPv4 subnet, range, and FQDN objects; static address groups; TCP/UDP services
  with supported source/destination port intervals; static service groups.
- One-time schedules with one interval, and uniform recurring intervals.
  Engineers must confirm matching source/destination timezone identifiers.
  Times are not converted. Overnight or differing weekly intervals remain manual.
- Explicit primary IPv4 addressing on mapped Layer 3 ethernet ports and VLAN
  units. Every VLAN depends on its mapped parent. Management, aggregate,
  secondary address, IPv6, and other unimplemented behavior remains blocked.
- Layer 3 zones with explicit member mappings. Generated zones explicitly deny
  intrazone traffic; default-security/intrazone equivalence remains visible as
  manual work. A traffic-policy export is therefore labeled partial.
- Static IPv4 routes with explicit next hop, outgoing interface, administrative
  distance, and a single source router mapped to VRF 0. Metric, monitoring,
  dynamic routing, multiple routing domains and unverified isolation remain manual.
- Restricted ordered L3/L4 security policies with application `any`, supported
  match/action/logging, and reviewed values for omitted fields. Each policy
  depends on its predecessor. Partial approval cannot omit an earlier rule and
  thereby expose a later allow. App-ID, `application-default`, identity, HIP,
  category-specific matching, inspection profiles, application-dependent deny,
  reset actions, start-only logging, and explicit
  default security rules remain manual.

## NAT restrictions

The target must already use central NAT, or the engineer must declare that mode
for offline planning. Generated commands do not enable central NAT.

- Dynamic-IP-and-port SNAT supports an explicit mapped
  interface address equal to that interface's sole IPv4 address, or one literal
  translated pool IPv4 address. Original zone members resolve to explicit target
  interfaces. Pool proxy ARP is disabled; routed return traffic needs explicit
  engineer confirmation.
- Multiple source NAT rules require pairwise disjoint literal IPv4 source
  prefixes referenced directly by each rule. Source order is preserved. Groups,
  `any` and uncertain overlaps cannot prove isolation and remain blocked.
- Static DNAT supports one address-only rule and one exactly matched security
  rule. It requires a public `/32` object, literal mapped IPv4 host, one ingress
  interface, a verified connected post-NAT zone, explicit VIP proxy-ARP choice,
  and an empty target policy/VIP/central-SNAT baseline.
- DNAT generates a mapped-host address and VIP. The security policy matches the
  translated host and sets `match-vip-only enable`, preventing direct private-IP
  packets from matching that policy. VIP source-interface filtering is explicit.
- Port-translated DNAT, combined SNAT/DNAT, multiple DNAT rules, no-NAT exception
  ordering, dynamic DNAT, bidirectional static SNAT, NAT64/46, and uncertain
  overlaps remain blocked. Unsupported or unapproved NAT blocks consuming policies.

## Destination comparison

Optional destination uploads use the existing FortiGate native reporter and its
sanitized source records. Missing typed objects do not prove absence.

- Firmware, operating mode, NGFW mode, NAT mode, and VDOM command scope must match
  explicit destination evidence. Missing values are not defaults.
- Only explicitly unaddressed, unreferenced physical ports with verified ownership
  can populate port proposals. Configuration evidence is not a complete chassis inventory.
- `REUSE` requires matching planned settings and no unexplained target behavior.
- `CREATE` requires an explicitly empty destination table. Missing or populated
  tables cannot establish safe placement or object absence.
- `CONFIGURE` can add addressing to a verified physical port only when its address
  is explicitly `0.0.0.0 0.0.0.0`, ownership matches, and no target records reference
  the port. It emits the approved IP addition only. Existing addresses/ownership
  are not overwritten.
- DNAT requires explicitly empty destination traffic tables to exclude effects
  on existing traffic. Other conflicts and incomplete evidence produce `BLOCK`.

Destination comparison is configuration evidence, not proof of live hardware,
capacity, licensing, cabling, candidate state, or actual device acceptance.

## CLI

Use `--format cli` and the existing pair-specific mapping-file option:

```text
fwmigrate migrate --input panos.xml --output output --source-vendor palo_alto --target-vendor fortigate --format cli --zone-map fortigate-mapping.yaml
```

Mapping shape:

```yaml
source_scope: vsys:vsys1:device:fw1
vdom: root
interfaces:
  ethernet1/1: port1
  ethernet1/2: port2
zones:
  trust: inside
  untrust: outside
routers: {}
profile:
  fortios_version: 7.4.6
  operating_mode: nat
  ngfw_mode: profile-based
  nat_mode: central
  vdom_mode: single
  ports: [port1, port2]
timezone: ""
policy_settings: {}
```

Use the browser's proposal export to obtain exact scoped policy keys and missing
field choices; do not build those identities from display names.
`--target-config` optionally accepts native FortiGate configuration evidence.
PAN-OS target-device/target-intent flags do not apply to this reverse pair.
CLI planning does not require web approval and cannot enable web deployment.

## API and artifact integrity

Routes live under `/api/migration/palo_alto_to_fortigate/`:
`requirements`, `design/prepare`, `design/approve`, `build`, `command-preview`,
`commands`, `bundle`, `decisions/import`, and `decisions/export`.
Web routes use the pair's `application/` facade; vendor semantics stay backend-owned.

Drafts and approvals bind source digest/scope, target digest, exact options,
configuration, operations, and dependencies. Only current signed approvals can
build web artifacts. Forged, cross-pair, changed, expired, or incomplete approvals
are rejected. The PAN-OS deployment endpoints reject reverse-pair artifacts.
Proposal generation also binds requested overrides, resolved mappings and effective
source-value provenance. Preparation, approval and build recompute the same design.
Older drafts need preparation again. Mapping imports restore proposals only.
The bundle exports resolved CLI-compatible mappings, plus effective-value and
target-proposal provenance in the migration report.

Preview, command download, and bundle share one immutable command list. Count
means CLI lines, including FortiOS block delimiters. SHA-256 covers UTF-8 commands
joined with `\n`, without a trailing newline. Bundles include the same command
bytes, migration report, proposal document, CLI-compatible `target_mapping.yaml`,
and sanitized PAN-OS source workbook.

## Reference and validation boundaries

Command spellings were checked against the repository's selected FortiGate CLI
reference and the official [FortiOS 7.4.6 CLI reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/cb8d6b09-b8b3-11ef-9411-ae1fcf29f169/FortiOS-7.4.6-CLI_Reference.pdf).
Central DNAT policy placement follows the official [7.4.6 central DNAT example](https://docs.fortinet.com/document/fortigate/7.4.6/administration-guide/448790/central-dnat).
PAN-OS original-address/post-NAT-zone matching follows [PAN-OS NAT policy rules](https://docs.paloaltonetworks.com/ngfw/networking/nat/nat-policy-rules).

Tests cover real native analysis through review/approval/rendering/export,
tampering, stale evidence, ordering, scoped references, cycles, a 2,500-item
dependency chain, target comparison, restricted NAT, schedules/routes, command
injection, and rejection by PAN-OS deployment. Frontend tests cover explicit
approval, failed generation retry, preserved edits, and context invalidation.
The production frontend builds successfully. No live firewall was accessed.
Browser upload verification requires the Edge extension's file-URL permission;
that permission was unavailable during this implementation.
