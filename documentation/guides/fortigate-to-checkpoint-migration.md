# FortiGate to Check Point coverage and usage

This pair creates an offline review package. It does not connect to Check Point
Management or Gaia. The Management output is a version-pinned API request
specification with explicit response UID bindings; the Gaia output is a
separate Clish file. Preview, individual downloads, and the bundle use the same
approved file bytes.

## New target workflow

The browser starts with **New target — create a policy package**. No destination
configuration is required. The backend selects a sole source VDOM and proposes
a source-scoped package name. Multiple VDOMs still require a source selection.
Proposals become approved operations only after explicit review.

The plan includes `add-package` with Access Control enabled. Its returned
`access-layers[0].uid` identifies the new layer. A new explicit Drop cleanup
rule is inserted at the top. Supported source rules are inserted above this
new anchor, then below the preceding imported rule. No existing package or
cleanup rule is used. Unsupported source rules and dependent later rules stay
blocked. A new target does not make unsupported semantics convertible.

The reviewed bundle also includes `checkpoint_management.sh`. Run it manually
with Bash, `mgmt_cli`, `jq`, and an existing API session file:

```bash
bash checkpoint_management.sh /path/to/existing-session.json
```

Log in to the intended Management Domain separately. The script pins API
1.8.1, captures returned UIDs, stops on command or response-binding errors,
and requires exactly one access layer in the new package response. Names must
be unused. It does not create a session, publish, install policy, or configure
gateway interfaces. Rules use `Policy Targets` unless explicit gateways were
supplied. Select the intended gateway before installation. Gaia static routes
remain a separate file; verify addressing and topology before applying them.

Choose **Existing target — add to a policy** for existing-package mappings and
optional destination comparison. Existing mapping documents without
`target_mode` retain this behavior. CLI new-target generation uses a mapping
document containing `target_mode: new`; it remains unapproved review material.

## Verified subset

- Source scope is one explicitly selected FortiGate VDOM.
- Check Point Management API baseline is R81 API 1.8.1.
- IPv4 host, network and range objects can be proposed with `add-host`,
  `add-network` and `add-address-range` requests.
- Explicit IPv6 `ipprefix` host/network objects use `add-host` with
  `ipv6-address`, or `add-network` with `subnet6` and `mask-length6`. Scoped
  IPv6 identity is separate from IPv4. Unknown types, missing fields and invalid
  prefixes remain blocked. IPv6 policies and NAT are not enabled.
- Explicit TCP and UDP custom services can be proposed with
  `add-service-tcp` and `add-service-udp` requests.
- Static address and service groups are expanded to leaf UID references; no
  group creation operations are emitted. Nested groups are supported when
  complete, acyclic, non-IPv6, and otherwise representable.
- Explicit IPv4 access rules are supported only when interfaces are `any`, the
  schedule is `always`, NAT is explicitly disabled, UTM is explicitly disabled,
  and all match, state, and negation fields are explicit and representable.
- Source rule order is preserved. Existing-target mode places the first rule
  above a named, engineer-confirmed Drop cleanup rule. New-target mode creates
  its own package and Drop anchor. Following rules use returned
  rule UIDs for insertion order.
- Gaia supports explicit enabled IPv4 and IPv6 static routes with a destination
  and same-family gateway, when blackhole is explicitly disabled and no
  device, VRF, dynamic gateway, multipath, distance, or other unsupported
  selector is present.
- CLI output is unapproved review material. Web downloads require a current
  signed approval bound to the source, pair, target options, selected items,
  dependencies, and exact output files.

## Manual and blocked coverage

Policy export remains blocked for interface-bound matching, schedules other
than `always`, IPv6 and identity selectors, inspection/UTM, NAT, central SNAT,
unknown fields, unresolved references, cyclic or ambiguous groups, and any
unsupported earlier policy that could affect later traffic. Rules need an
explicit package, access layer, Management Domain, install-on selection, and
cleanup anchor in existing-target mode. Optional native destination comparison can reuse exact host,
network, range, IPv6 host/network and service objects by UID. Address reuse requires explicit
automatic NAT disablement. Unknown settings and name collisions block output.

Destination-aware policy insertion requires complete native Management evidence
for objects, services, packages, layers, gateways, policies and NAT. Domain,
Management server and API version must match. The selected layer must contain
only an active Drop cleanup rule with explicit unrestricted matching and the
selected gateway coverage. Existing target NAT or other access rules block new
policy output. Package, layer, cleanup and gateway UIDs are bound to review.

In existing-target mode Gaia routes remain manual when their target label is
unknown. In either mode routes remain manual when the source gateway is
unknown or route selection includes unsupported topology or
policy. Management and Gaia outputs are independent; no interface, gateway,
cluster, or routing topology is inferred between them.

The output does not publish a package, assign a policy, install policy, execute
Management API calls, run Gaia commands, or include `save config`. No live
Management API acceptance or Gaia device validation was performed. Management
destination evidence does not prove Gaia topology; Gaia route export is blocked
when using that evidence. Source inventory accounting remains visible in review
and export reports. See the [support matrix](../migration-support-matrix.md).

## CLI

```powershell
fwmigrate migrate --input fortigate.conf --output checkpoint-review `
  --source-vendor fortigate --target-vendor checkpoint --format json
```

Optional pair-specific mapping YAML can supply values such as `source_vdom`,
`management_target`, `management_domain`, `policy_package`, `access_layer`,
`install_on`, `insertion_anchor`, `insertion_relation`, `target_cleanup_action`,
and `gaia_target`. CLI output is not engineer approval. `--target-config` accepts
native Check Point Management JSON when the mapping also supplies
`target_evidence` with `context`, `version`, `mode: management` and
`complete_families`. Browser uploads expose the same declarations. Destination
changes invalidate approval.

## References

- [Check Point Management API R81 v1.8.1](https://sc1.checkpoint.com/documents/latest/APIs/#web/add-access-rule~v1.8.1)
- [R81 v1.8.1 package creation](https://sc1.checkpoint.com/documents/latest/APIs/index.html#web/add-package~v1.8.1) and [versioned schema](https://sc1.checkpoint.com/documents/latest/APIs/data/v1.8.1/dynamic/apis.json): `access`, package response `access-layers`, `add-access-rule` positions and name/UID references. Reviewed against the official schema on 2026-10-19. No live API acceptance was tested.
- [Check Point Gaia R81 IPv4 static routes](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_Gaia_AdminGuide/Topics-GAG/IPv4-Static-Routes-Gaia-Clish.htm)
- [Check Point Gaia R81 IPv6 static routes](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_Gaia_AdminGuide/Topics-GAG/IPv6-Static-Routes.htm)
