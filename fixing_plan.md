Yes. I would implement this as a **canonical NAT-model expansion**, not as four isolated FortiGate patches.

The key architectural change is:

> **“Fully normalized” must mean the FortiGate behavior is represented precisely in canonical IR. It must not mean every target vendor can generate it.**

Right now those concepts are partly coupled: advanced FortiGate NAT behavior is often marked `PARTIALLY_NORMALIZED` merely because a target requires review. The current IR already has `NATType.CENTRAL`, translation modes, and a `safe_for_target_generation` check, so the foundation exists.  

FortiOS 7.4.6 makes this expansion necessary: Central SNAT alone includes IPv4/IPv6 address selectors, ports, protocol, NAT pools, NAT46/NAT64, source-port preservation, status and rule type.  Policy NAT additionally has `fixedport`, `poolname6`, PCP, STUN, RTP, NAT46/NAT64 and policy-based-IPsec NAT controls. 

# Recommended implementation sequence

| Phase | Main result |
|---|---|
| 1 | Expand canonical NAT IR |
| 2 | Complete typed FortiGate NAT source models/parser |
| 3 | Fully normalize Central SNAT |
| 4 | Fully normalize SCTP `ip-translation` |
| 5 | Fully normalize IPv6 / NAT46 / NAT64 / NAT66 |
| 6 | Normalize advanced/source-specific NAT semantics |
| 7 | Add target capability gating + FortiGate regeneration |
| 8 | Update Excel, coverage, validation and documentation |
| 9 | Full regression/golden test matrix |

---

# Phase 1 — Expand the canonical NAT IR

### Objective

Make `IRNATRule` expressive enough that Central SNAT, SCTP translation, NAT46/64/66, source-port semantics and advanced FortiGate NAT can be represented **without FortiGate-only raw fields**.

The current `IRNATRule` already has source/destination matches, translation modes, pool references and translated source/destination lists.  It also already supports `NATType.CENTRAL`. 

### Files

| Path | Action |
|---|---|
| `src/fwmigrate/ir/enums.py` | Edit |
| `src/fwmigrate/ir/core.py` | Edit |
| `src/fwmigrate/ir/__init__.py` | Edit if new types are exported |
| `src/fwmigrate/ir/version.py` | Edit |
| `src/fwmigrate/ir/migrations.py` | Edit |
| `tests/test_ir_schema_version.py` | Edit |
| `tests/test_ir_nat_semantics.py` | **Add** |

### Code changes

Add a canonical NAT-family concept:

```text
NAT44
NAT46
NAT64
NAT66
```

Add a new NAT type for FortiGate SCTP IP translation rather than incorrectly pretending it is ordinary SNAT/DNAT:

```text
NATType.ADDRESS_TRANSLATION
```

Add structured models to `core.py`, preferably:

```text
IRNATPortRange
IRNATAddressRangeMapping
IRNATRuntimeBehavior
```

Extend `IRNATRule` with fields equivalent to:

```text
nat_family
original_address_family
translated_address_family

protocol_number
protocol_name

original_source_ports[]
original_destination_ports[]
translated_source_ports[]
translated_destination_ports[]

source_port_behavior

address_range_mappings[]

install_translation_route

runtime_behavior
source_origin
```

`source_origin` should distinguish at least:

```text
firewall-policy
central-snat-map
vip
vip6
ip-translation
multicast-policy
```

For source-port behavior, do **not** combine FortiGate `fixedport` and `port-preserve`. They mean different things. FortiOS defines `fixedport enable` as preventing SNAT from changing the session source port, while `port-preserve enable` means use the original source port when available; `port-preserve disable` always changes it. 

Suggested canonical enum:

```text
DYNAMIC
PRESERVE_IF_AVAILABLE
PRESERVE_STRICT
ALWAYS_TRANSLATE
EXPLICIT_RANGE
```

### Schema action

Current IR version is **1.34**. 

Bump:

```text
1.34 → 1.35
```

Keep all existing scalar NAT properties for backward compatibility. Add a `1.34 → 1.35` migration that supplies defaults for newly introduced fields.

### Exit criteria

An `IRNATRule` must be able to represent all requested FortiGate NAT semantics without putting required behavior only into `source_attributes`.

---

# Phase 2 — Complete typed FortiGate NAT source models

### Objective

Before correlation, every FortiOS NAT field must have a typed FortiGate source representation.

Central SNAT is already substantially typed, including IPv6 lists and default handling. Existing tests explicitly verify that behavior. 

By contrast, `firewall ip-translation` is currently registered under the generic `SOURCE_ONLY_RULE_FAMILIES`. 

### Files

| Path | Action |
|---|---|
| `src/fwmigrate/parsers/fortigate/model.py` | Edit |
| `src/fwmigrate/parsers/fortigate/parser.py` | Edit |
| `src/fwmigrate/parsers/fortigate/extractor.py` | Edit |
| `src/fwmigrate/parsers/fortigate/coverage.py` | Edit |
| `tests/test_parser.py` | Edit |
| `tests/test_fortigate_policy_field_typing.py` | Edit |
| `tests/test_fortigate_central_snat.py` | Edit |
| `tests/test_fortigate_ip_translation.py` | **Add** |

### Code changes

Add:

```python
class FGIPTranslation(FGContextualModel):
    id: int
    type: str = "SCTP"
    startip: Optional[str]
    endip: Optional[str]
    map_startip: Optional[str]
    extra_settings: Dict[str, Any]
```

Add:

```text
FGConfig.ip_translations: List[FGIPTranslation]
```

Remove:

```text
"firewall ip-translation"
```

from the generic source-only handling and give it a dedicated parser branch.

FortiOS defines exactly `startip`, `endip`, `map-startip` and `type=SCTP` for this configuration. 

Also promote currently untyped policy NAT controls into `FGPolicy`:

```text
pcp_inbound
pcp_outbound
pcp_poolname[]
permit_any_host
permit_stun_host
rtp_nat
rtp_addr[]
```

FortiOS documents PCP inbound DNAT, PCP outbound SNAT and PCP pools explicitly.  It also documents STUN and RTP-related policy behavior. 

### Additional action

Continue preserving `extra_settings` for future FortiOS fields. Typed normalization must **add fidelity**, not remove forward compatibility.

---

# Phase 3 — Fully normalize Central SNAT

### Objective

Change `firewall central-snat-map` from source-only inventory into canonical `IRNATRule(type=CENTRAL)` objects.

The current implementation instead puts Central SNAT in `IRConfig.central_snat_rules`, and the current test explicitly expects `canonical_ir.nat_rules == []`. 

That is the primary behavior to change.

### Files

| Path | Action |
|---|---|
| `src/fwmigrate/parsers/fortigate/transformer.py` | Major edit |
| `src/fwmigrate/parsers/fortigate/dependencies.py` | Edit |
| `src/fwmigrate/parsers/fortigate/semantic_validation.py` | Edit |
| `src/fwmigrate/ir/core.py` | Supporting edit |
| `tests/test_fortigate_central_snat.py` | Major edit |
| `tests/test_fortigate_nat_correlation.py` | Edit |

### Code changes

Create a dedicated:

```python
_transform_central_snat()
```

Do not bury it inside policy NAT correlation.

Map:

| FortiOS | Canonical IR |
|---|---|
| `policyid` | `source_rule_id` |
| source position | `sequence` |
| `type` | original address family |
| `srcintf` | `source_from_interfaces` |
| `dstintf` | `source_to_interfaces` |
| `orig-addr` / `orig-addr6` | original source match |
| `dst-addr` / `dst-addr6` | destination match |
| `protocol` | `protocol_number` |
| `orig-port` | original source ports |
| `dst-port` | original destination ports |
| `nat-ippool` / `nat-ippool6` | source pool references |
| `nat-port` | translated source ports |
| `port-preserve` | source-port behavior |
| `nat46` / `nat64` | `nat_family` |
| `nat disable` | translation mode `NONE` |
| `status` | enabled |
| `uuid` | source UUID |

FortiOS officially supports this entire set in Central SNAT. 

### Important implementation rule

Preserve **source ordering**, not merely numeric `policyid`.

Central SNAT is an ordered rulebase. Add `source_order` to `FGCentralSNATRule` if the parser currently only retains its ID.

When Central NAT is enabled:

```text
firewall policy NAT
    → must NOT create authoritative policy-derived SNAT

central-snat-map
    → MUST create authoritative canonical NAT rules
```

Retain `central_snat_rules` as provenance/source inventory for compatibility, but also populate `ir.nat_rules`.

### Pool correlation

Resolve:

```text
nat-ippool  → IRIPPool(address_family=ipv4)
nat-ippool6 → IRIPPool(address_family=ipv6)
```

Missing pool references:

```text
preserve reference
requires_manual_review = true
do not substitute interface NAT
```

### Exit criteria

A Central NAT configuration with 10 source entries must produce 10 canonical ordered NAT rules unless an entry is genuinely invalid.

---

# Phase 4 — Fully normalize SCTP `firewall ip-translation`

### Objective

Represent FortiGate's SCTP address-range translation canonically instead of `EXTRACT_ONLY`.

### Files

| Path | Action |
|---|---|
| `src/fwmigrate/parsers/fortigate/model.py` | From Phase 2 |
| `src/fwmigrate/parsers/fortigate/parser.py` | From Phase 2 |
| `src/fwmigrate/parsers/fortigate/transformer.py` | Edit |
| `src/fwmigrate/parsers/fortigate/net_utils.py` | Add range-validation helper if appropriate |
| `tests/test_fortigate_ip_translation.py` | Add/expand |
| `src/fwmigrate/parsers/fortigate/coverage.py` | Edit |

### Code changes

Emit:

```text
NATType.ADDRESS_TRANSLATION
protocol_name = SCTP
nat_family = NAT44
```

Store an explicit range mapping:

```text
original:
    startip → endip

translated:
    map-startip →
        map-startip + (endip - startip)
```

Use Python `ipaddress` arithmetic.

Validate:

```text
startip <= endip
addresses are IPv4
map-startip is valid
calculated mapped end does not overflow IPv4
type == SCTP
```

Fortinet describes `map-startip` as the starting address for translation of the configured source range, so deriving the corresponding mapped end is appropriate and deterministic. 

Do **not** classify this as ordinary SNAT or DNAT unless Fortinet documentation establishes packet-direction semantics. `ADDRESS_TRANSLATION + SCTP` is safer and more accurate.

---

# Phase 5 — Fully normalize IPv6 NAT

### Objective

Convert `ippool6`, `vip6`, `vipgrp6`, `poolname6`, NAT46, NAT64 and NAT66 from inventory-only/source evidence into canonical NAT correlation.

The current transformer deliberately marks IPv6 pools/VIPs/groups `EXTRACT_ONLY`. The FortiOS source models already cover much of this data.  

### Files

| Path | Action |
|---|---|
| `src/fwmigrate/parsers/fortigate/transformer.py` | Major edit |
| `src/fwmigrate/parsers/fortigate/model.py` | Complete missing IPv6 fields |
| `src/fwmigrate/parsers/fortigate/net_utils.py` | IPv6/range helpers |
| `src/fwmigrate/ir/core.py` | NAT-family fields |
| `tests/test_fortigate_ipv6_nat.py` | **Add** |
| `tests/test_fortigate_nat_correlation.py` | Expand |

### Correlation matrix

| Source combination | Canonical result |
|---|---|
| IPv4 → IPv4 | NAT44 |
| IPv4 VIP + `nat46` | NAT46 |
| IPv6 VIP + `nat64` | NAT64 |
| IPv6 → IPv6 | NAT66 |
| IPv6 source pool + NAT46 | NAT46 |
| IPv4 pool with NAT64 | NAT64 |

`ippool6` specifically exposes IPv6 ranges, `nat46`, and automatic NAT46 route behavior. 

`vip6` exposes `nat64`, `nat66`, IPv4 mapped addresses/ports, embedded IPv4 handling and automatic NAT64 route behavior. 

### VIP6 logic

Normalize:

```text
extip
mappedip
ipv4-mappedip
ipv4-mappedport
embedded-ipv4-address
nat64
nat66
portforward
protocol
extport
mappedport
```

Also normalize route side effects:

```text
add-nat46-route
add-nat64-route
```

into something like:

```text
install_translation_route
```

Do not invent an `interface` for `vipgrp6`: FortiOS `vipgrp6` has members, UUID, comments and color, but unlike IPv4 `vipgrp`, its documented syntax has no group interface. 

---

# Phase 6 — Normalize advanced/source-specific NAT semantics

### Objective

Stop treating known FortiGate NAT functionality as generic manual-review metadata.

### Files

| Path | Action |
|---|---|
| `src/fwmigrate/parsers/fortigate/model.py` | Edit |
| `src/fwmigrate/parsers/fortigate/parser.py` | Edit |
| `src/fwmigrate/parsers/fortigate/transformer.py` | Major edit |
| `src/fwmigrate/ir/core.py` | Edit |
| `src/fwmigrate/ir/enums.py` | Edit |
| `tests/test_fortigate_policy_semantics.py` | Update expectations |
| `tests/test_fortigate_nat_correlation.py` | Expand |
| `tests/test_fortigate_advanced_nat_semantics.py` | **Add** |

### Normalize these groups

**Source-port semantics**

```text
fixedport
port-preserve
nat-port
startport/endport
```

**Policy-based IPsec NAT**

```text
natinbound
natoutbound
natip
```

FortiOS explicitly defines these as policy-based-IPsec inbound DNAT and outbound SNAT controls. 

**PCP/STUN**

```text
pcp-inbound
pcp-outbound
pcp-poolname
permit-any-host
permit-stun-host
```

**RTP NAT**

```text
rtp-nat
rtp-addr
```

**Advanced pool allocation**

```text
one-to-one
fixed-port-range
port-block-allocation
CGN resource allocation
exclude-ip
block-size
num-blocks-per-user
pba-timeout
PBA logging
ports-per-user
full-cone / permit-any-host
```

The existing `IRIPPool` already models many of these, so the main change is semantic: once every configured behavior is represented exactly, the pool should be:

```text
migration_status = NORMALIZED
```

even if PAN-OS cannot reproduce it.

**Advanced VIP behavior**

Continue normalizing:

```text
nat-source-vip
source filters
interface filters
service restrictions
port mapping type
load-balancing method
real servers
persistence
monitors
```

The NAT rule should reference the normalized VIP rather than duplicating arbitrary raw fields.

### Optional but recommended for the word “fully”

Also bring:

```text
config firewall multicast-policy
config firewall multicast-policy6
```

into the same canonical NAT model.

FortiOS explicitly describes `firewall multicast-policy` as multicast NAT and provides `dnat`, `snat`, `snat-ip`, protocol and ports. 

Otherwise the project should describe itself as **fully normalized unicast NAT**, not fully normalized FortiGate NAT.

---

# Phase 7 — Separate normalization from target support

### Objective

Prevent a fully understood FortiGate NAT rule from being labeled incomplete only because a target platform cannot implement it.

### Files

| Path | Action |
|---|---|
| `src/fwmigrate/generators/nat_capabilities.py` | **Add** |
| `src/fwmigrate/generators/palo_alto/transformer.py` | Edit |
| `src/fwmigrate/generators/palo_alto/xml_generator.py` | Edit |
| `src/fwmigrate/generators/palo_alto/terraform_generator.py` | Edit |
| `src/fwmigrate/generators/fortigate/cli_generator.py` | Edit |
| `src/fwmigrate/generators/fortigate/terraform_generator.py` | Edit |
| `tests/test_fortigate_generator_safety.py` | Expand |

FortiGate CLI/Terraform generator paths are confirmed in the repository. 

### Code change

Introduce target capability assessment such as:

```python
NATCapabilities(
    ipv6_nat=True/False,
    nat46=True/False,
    nat64=True/False,
    nat66=True/False,
    central_nat=True/False,
    sctp_address_translation=True/False,
    pba=True/False,
    cgn=True/False,
    pcp=True/False,
    source_port_policy=True/False,
)
```

The pipeline becomes:

```text
source understood exactly
        ↓
IR migration_status = NORMALIZED
        ↓
target capability evaluator
        ↓
supported → generate
unsupported → withhold + target-specific audit
```

Do **not** change:

```text
NORMALIZED → PARTIALLY_NORMALIZED
```

just because the target lacks a feature.

For FortiGate→FortiGate, the generator should be able to recreate Central SNAT, IP translation, IPv6 pools/VIPs and the advanced settings accurately.

Before editing other target adapters, have Codex run:

```bash
rg "nat_rules|IRNATRule|NATType|source_translation_mode" src/fwmigrate/generators
```

and apply the same safety gate to every consumer discovered.

---

# Phase 8 — Reporting, coverage and documentation

### Objective

Make the newly normalized information observable and auditable.

### Files

| Path | Action |
|---|---|
| `src/fwmigrate/report/excel_exporter.py` | Major edit |
| `src/fwmigrate/report/migration_report.py` | Edit |
| `src/fwmigrate/parsers/fortigate/coverage.py` | Edit |
| `src/fwmigrate/parsers/fortigate/extractor.py` | Edit |
| `documentation/FORTIGATE_CONFIG_EXTRACTION_REFERENCE.md` | Edit |
| `documentation/EXTRACTION_DATA_MODEL.md` | Edit |
| `documentation/IR_DATA_STRUCTURE.md` | Edit |
| `tests/test_excel_exporter.py` | Expand |

### NAT Rules sheet additions

Add columns for:

```text
Source Origin
NAT Family
Original Address Family
Translated Address Family
Protocol / Protocol Number
Original Source Port
Original Destination Port
Translated Source Port
Translated Destination Port
Source Port Behavior
Install Translation Route
PCP Inbound
PCP Outbound
PCP Pools
STUN Any Host
RTP NAT
RTP Addresses
```

The existing NAT Rules exporter already exposes pool/VIP and policy NAT metadata, so this extends an existing sheet rather than creating another competing representation. 

### Coverage classification changes

After completion:

```text
firewall central-snat-map → NORMALIZED
firewall ip-translation → NORMALIZED
firewall ippool6 → NORMALIZED
firewall vip6 → NORMALIZED / PARTIALLY_NORMALIZED only for genuinely unresolved fields
firewall vipgrp6 → NORMALIZED
```

Do not count target-generator unsupported status as extraction coverage failure.

---

# Phase 9 — Regression and golden validation

### Objective

Prove that expanding NAT normalization does not weaken current safety behavior.

### Files

| Path | Action |
|---|---|
| `tests/test_fortigate_central_snat.py` | Expand/rewrite |
| `tests/test_fortigate_nat_correlation.py` | Expand |
| `tests/test_fortigate_ip_translation.py` | Add |
| `tests/test_fortigate_ipv6_nat.py` | Add |
| `tests/test_fortigate_advanced_nat_semantics.py` | Add |
| `tests/test_fortigate_policy_semantics.py` | Update |
| `tests/test_fortigate_extraction_remediation.py` | Update |
| `tests/test_fortigate_generator_safety.py` | Expand |
| `tests/test_excel_exporter.py` | Expand |
| `tests/test_ir_schema_version.py` | Expand |

### Required test matrix

Codex should cover at minimum:

| Case | Expected |
|---|---|
| Central IPv4 SNAT | Fully normalized |
| Central IPv6 SNAT | Fully normalized |
| Central NAT46 | Fully normalized |
| Central NAT64 | Fully normalized |
| Central `nat disable` | Explicit no-NAT rule |
| Central original/destination ports | Exact ranges |
| Central `port-preserve disable` | `ALWAYS_TRANSLATE` |
| Missing Central pool | Rule retained + review |
| SCTP one-address mapping | Exact |
| SCTP range mapping | Correct translated end |
| Invalid SCTP range | Review/parse error, no guessing |
| IPv4 pool overload | Existing behavior unchanged |
| IPv6 pool | Normalized |
| VIP NAT44 | Existing behavior unchanged |
| VIP NAT46 | Normalized |
| VIP6 NAT64 | Normalized |
| VIP6 NAT66 | Normalized |
| VIPGRP6 expansion | Correct |
| `fixedport enable` | Strict source-port preservation |
| PCP inbound/outbound | Typed normalized behavior |
| RTP NAT | Typed normalized behavior |
| PBA/CGN pool | Normalized IR, target capability checked |
| Unsupported target | Withheld by target, IR remains normalized |
| FortiGate round-trip | Equivalent NAT semantics |

---

## Final implementation rule for Codex

The most important instruction I would put at the top of the Codex task is:

> **Never fix these gaps by merely adding more `source_*` fields or by changing `requires_manual_review`. The goal is to represent the actual NAT semantics in canonical IR. Source-specific evidence remains for provenance, while target limitations are handled separately by generator capability checks.**

The current code is already close to this architecture: Central NAT is typed, `NATType.CENTRAL` exists, IPv6 pools/VIPs are typed, and the current NAT correlation tests already exercise advanced pool and policy behavior.   The work is therefore primarily a **semantic promotion from preserved/extract-only data into canonical NAT IR**, rather than a parser rewrite.

**Recommended implementation order:** **1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9**. Do not start Excel or generator work before Phase 1's IR contract is finalized.