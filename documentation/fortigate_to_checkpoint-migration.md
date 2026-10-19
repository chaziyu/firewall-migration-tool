# FortiGate to Check Point coverage and usage

This pair creates an offline review package. It does not connect to Check Point
Management or Gaia. The Management output is a version-pinned API request
specification with explicit response UID bindings; the Gaia output is a
separate Clish file. Preview, individual downloads, and the bundle use the same
approved file bytes.

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
- Source rule order is preserved. The first rule is placed above a specifically
  named, engineer-confirmed Drop cleanup rule. Following rules use returned
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
cleanup anchor. Optional native destination comparison can reuse exact host,
network, range, IPv6 host/network and service objects by UID. Address reuse requires explicit
automatic NAT disablement. Unknown settings and name collisions block output.

Destination-aware policy insertion requires complete native Management evidence
for objects, services, packages, layers, gateways, policies and NAT. Domain,
Management server and API version must match. The selected layer must contain
only an active Drop cleanup rule with explicit unrestricted matching and the
selected gateway coverage. Existing target NAT or other access rules block new
policy output. Package, layer, cleanup and gateway UIDs are bound to review.

Gaia routes remain manual when their target gateway/cluster label or source
gateway is unknown, or when route selection includes unsupported topology or
policy. Management and Gaia outputs are independent; no interface, gateway,
cluster, or routing topology is inferred between them.

The output does not publish a package, assign a policy, install policy, execute
Management API calls, run Gaia commands, or include `save config`. No live
Management API acceptance or Gaia device validation was performed. Management
destination evidence does not prove Gaia topology; Gaia route export is blocked
when using that evidence. Source inventory accounting remains visible in review
and export reports. See the [support matrix](migration-support-matrix.md).

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
- [Check Point Gaia R81 IPv4 static routes](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_Gaia_AdminGuide/Topics-GAG/IPv4-Static-Routes-Gaia-Clish.htm)
- [Check Point Gaia R81 IPv6 static routes](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_Gaia_AdminGuide/Topics-GAG/IPv6-Static-Routes.htm)
