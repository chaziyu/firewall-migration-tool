# Vendor-Neutral Intermediate Representation (IR) Data Structure
## Nested interface source configuration update

This file contains the documentation changes required for the nested-interface extraction implementation. Merge these sections into `documentation/IR_DATA_STRUCTURE.md`.

---

## Replace / extend section `9.1 Interfaces`

### `IRInterface`

Recommended portable interface fields remain unchanged. The current executable compatibility model also retains source-oriented fields needed for extraction fidelity:

```text
source_vdom
interface_type
remote_ip
secondary_ips[]
role
addressing_mode
management_access[]
dhcp_client
source_attributes
nested_source_configs[]
requires_manual_review
parse_errors[]
```

The canonical interface fields represent portable network intent where semantics are understood. Source-only compatibility fields must not be interpreted by target generators as portable behavior.

### Interface type source fidelity

An omitted source interface type is not equivalent to an explicit physical interface.

The source adapter should preserve:

```text
explicit set type <value> -> explicit source value
omitted set type          -> None/unset in source model
```

A source transformer may derive a normalized VLAN type when unambiguous structural evidence exists, such as a configured parent interface plus VLAN ID. Any derived value belongs only in the normalized interface field and must not be written back into source-preservation metadata.

---

## `IRSourceConfigCommand`

`IRSourceConfigCommand` is a recursive-source compatibility type used when a source adapter needs to preserve structured, non-portable configuration under an otherwise normalized object.

```python
class IRSourceConfigCommand(BaseModel):
    operation: str
    key: str
    values: List[str] = Field(default_factory=list)
```

Fields:

| Field | Type | Description |
| --- | --- | --- |
| `operation` | string | Source operation such as `set`, `unset`, or `append`. |
| `key` | string | Original/sanitized source setting key. |
| `values` | list[string] | Ordered sanitized source tokens. |

The values must already have passed source secret sanitization. This type must never contain plaintext passwords, PSKs, private keys, API tokens, SNMP communities, or equivalent secret material.

---

## `IRSourceConfigNode`

`IRSourceConfigNode` preserves recursive source hierarchy without claiming cross-vendor semantics.

```python
class IRSourceConfigNode(BaseModel):
    node_type: str
    name: str
    commands: List[IRSourceConfigCommand] = Field(default_factory=list)
    children: List["IRSourceConfigNode"] = Field(default_factory=list)
```

Fields:

| Field | Type | Description |
| --- | --- | --- |
| `node_type` | string | Source hierarchy node type, normally `config` or `edit`. |
| `name` | string | Native config subsection name or edit identity. |
| `commands` | list[IRSourceConfigCommand] | Sanitized commands directly attached to this node. |
| `children` | list[IRSourceConfigNode] | Ordered recursive child nodes. |

Required invariants:

1. Preserve source hierarchy.
2. Preserve child ordering.
3. Preserve command ordering.
4. Preserve edit identity.
5. Preserve source operation (`set`, `unset`, `append`).
6. Do not synthesize FortiOS defaults.
7. Sanitize secrets before the node reaches IR.
8. Target generators must ignore the node unless a future explicitly designed canonical model consumes the equivalent semantics.

This is not intended as a generic replacement for canonical IR. It is a temporary/extraction-oriented compatibility structure for source semantics that are important to account for but not yet portable.

---

## `IRInterface.nested_source_configs`

Add to the executable `IRInterface`:

```python
nested_source_configs: List[
    IRSourceConfigNode
] = Field(default_factory=list)
```

Meaning:

> Recursive, sanitized source configuration found inside an interface that has not been normalized into portable interface semantics.

Examples for FortiGate include:

```text
config client-options
config dhcp-snooping-server-list
config egress-queues
config ipv6
config l2tp-client-settings
config tagging
config vrrp
config wifi-mac-list
config wifi-networks
```

`config secondaryip` is excluded from this generic collection because it already has the dedicated typed path:

```text
IRInterface.secondary_ips[]
```

When `nested_source_configs` is non-empty:

```text
IRInterface.requires_manual_review = true
```

unless a future implementation has normalized every retained nested node into portable semantics and removed the source-only condition.

`nested_source_configs` must be ignored by target generators. A target generator must never discover a FortiGate-specific nested setting in this collection and opportunistically translate it. Promotion to target-consumable behavior requires a dedicated canonical model, explicit source transformer logic, validation, compatibility analysis, and tests.

---

## `IRInterfaceSecondaryIP`

The existing typed secondary-IP representation remains authoritative for FortiGate `config secondaryip`:

| Field | Type | Description |
| --- | --- | --- |
| `source_id` | string/null | Source edit ID. |
| `source_ip` | string/null | Exact raw source IP/netmask value. |
| `ip` | string/null | Strictly normalized IPv4 CIDR value, or null when invalid/unusable. |
| `management_access` | list[string] | Explicit per-secondary management access. |
| `requires_manual_review` | bool | True for invalid/missing values or retained unmodeled child settings. |
| `parse_error` | string/null | Explicit parsing/normalization failure. |
| `source_attributes` | dict | Sanitized unmodeled child settings. |

Do not duplicate secondary-IP child nodes into `nested_source_configs`.

---

## Source-only IR compatibility boundary

The architectural preference remains:

```text
portable semantics -> canonical IR
source/vendor-specific extraction -> ExtractionResult inventory
```

The current executable implementation permits limited source-oriented compatibility fields such as:

```text
IRInterface.source_attributes
IRInterface.nested_source_configs
```

because Excel and existing migration flows still consume the executable IR object directly.

These fields have strict rules:

```text
target generators must ignore them
they must contain no plaintext secrets
they must not change normalized firewall behavior
they must not create permissive fallback semantics
they must remain clearly documented as extraction-only
```

When the broader structured `ExtractionResult.inventory.network.interfaces` model becomes the sole reporting source, these compatibility fields may be migrated out of canonical IR through an explicit schema/version transition.

---

## Update section `31. IPv4 and IPv6`

IPv4 and IPv6 remain first-class target-schema requirements.

During the current FortiGate nested-interface preservation phase, an unmodeled:

```text
config system interface
    edit "port1"
        config ipv6
            ...
        end
    next
end
```

is retained recursively in:

```text
IRInterface.nested_source_configs
```

with `EXTRACT_ONLY` semantics and manual review.

This is not equivalent to full canonical IPv6 interface support. Full normalization requires dedicated IPv6 interface fields such as addresses, delegated prefixes, router advertisements, DHCPv6 behavior, VRRP6, and related source semantics to be modeled and validated explicitly.

The recursive source node is the zero-silent-loss fallback until that normalization exists.

---

## Update section `36. Excel/report contract`

The interface-related workbook sheets should include:

```text
Interfaces
Interface Secondary IPs
Interface Source Settings
Interface Nested Configuration
```

Their responsibilities are distinct:

| Sheet | Responsibility |
| --- | --- |
| Interfaces | Portable/normalized interface inventory plus selected source provenance. |
| Interface Secondary IPs | Dedicated typed nested secondary IPv4 addresses. |
| Interface Source Settings | Sanitized explicit top-level source `set` settings. |
| Interface Nested Configuration | Recursive extraction-only source hierarchy not yet represented as portable interface semantics. |

`Interface Nested Configuration` should expose at least:

```text
Interface
Config Path
Node Type
Object / Edit
Operation
Setting
Value
Extraction Status
Manual Review
```

Secrets must remain redacted.

---

## Schema-version assessment

Adding serialized optional fields such as:

```text
IRInterface.nested_source_configs
IRSourceConfigNode
IRSourceConfigCommand
```

is additive but still changes the serialized IR contract.

Before merging, assess `IR_SCHEMA_VERSION` according to the project's versioning rules:

```text
optional backward-compatible serialized field -> MINOR version candidate
field removal/rename/incompatible meaning      -> MAJOR version
internal helper only                           -> no schema bump
```

Do not bump the version mechanically if these structures are explicitly excluded from serialized IR. If they are emitted by normal `IRConfig.model_dump()`/JSON serialization, treat the addition as a serialized schema change and update fixtures/tests accordingly.

---

## Validation invariants for nested source configuration

Add these invariants to interface/source-validation expectations:

1. Every nested source node remains associated with its source interface.
2. Source order is deterministic.
3. No nested source node can change target behavior directly.
4. Secret-like values are absent/redacted.
5. `secondaryip` is not duplicated between typed and generic child collections.
6. Presence of unmodeled nested source configuration is observable through manual-review/audit state.
7. Invalid nested data must not be converted into `any`, default routes, guessed addresses, guessed zones, or other permissive semantics.
8. A future promotion from source-only node to canonical semantics must preserve the original source evidence for audit.
