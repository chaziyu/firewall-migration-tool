# Firewall Configuration Extraction Data Model
## Nested interface source hierarchy update

This file contains the documentation changes required for the nested-interface extraction implementation. Merge these sections into `documentation/EXTRACTION_DATA_MODEL.md`.

---

## Replace the phase-1 interface extraction implementation note in section 3

For phase-1 FortiGate interface extraction, explicitly configured top-level source-interface settings are retained in the executable:

```text
IRInterface.source_attributes
```

compatibility field and exposed in:

```text
Interface Source Settings
```

with extraction-only semantics.

Nested secondary IPv4 entries:

```text
config system interface
    edit <interface>
        config secondaryip
            edit <id>
                ...
            next
        end
    next
end
```

use a dedicated typed extraction path:

```text
FGInterfaceSecondaryIP
    -> IRInterfaceSecondaryIP
    -> Interface Secondary IPs
```

Other nested interface blocks that do not yet have dedicated portable models are retained recursively under their owning interface:

```text
FGInterface.nested_configs[]
    -> IRInterface.nested_source_configs[]
    -> Interface Nested Configuration
```

These recursive nodes preserve source hierarchy and sanitized source commands but remain `EXTRACT_ONLY`. Their presence makes the owning interface require manual migration review and makes the parent `system interface` coverage `PARTIALLY_NORMALIZED`.

Target generators must not consume either `source_attributes` or `nested_source_configs`.

This compatibility representation prevents interface configuration from disappearing while the broader `ExtractionResult.inventory.network` model is being implemented.

---

# Nested interface source hierarchy

## Purpose

A recognized parent object may be largely portable while containing nested source behavior that is not yet portable.

Example:

```text
config system interface
    edit "port1"
        set ip 10.0.0.1 255.255.255.0

        config ipv6
            set ip6-address 2001:db8::1/64
        end

        config vrrp
            edit 1
                set vrip 10.0.0.254
            next
        end
    next
end
```

The extractor must not choose between:

```text
normalize port1
OR
preserve ipv6/vrrp
```

It must do both:

```text
portable interface semantics -> canonical/interface IR
nested source semantics       -> extraction-only recursive inventory
```

---

## Required recursive properties

Nested source retention must preserve:

```text
owning source object/interface
config subsection name
edit identity
parent/child hierarchy
command operation
setting key
ordered values
source ordering
empty structural nodes where practical
```

Supported source operations include:

```text
set
unset
append
```

The extractor must not flatten all nested commands into one string or lose which interface owns them.

---

## Secret handling

Recursive source retention is still subject to the extraction redaction policy.

Sensitive examples include:

```text
password
passwd
secret
psk
psksecret
private_key
seed
activation_code
community
auth_key
token
api_key
```

A nested command must pass through the same sanitization mechanism used for other source-inventory commands before it is retained.

Example:

```text
config l2tp-client-settings
    set user "operator"
    set password "secret-value"
end
```

may retain:

```text
user = operator
password = [REDACTED]
```

but must never serialize or export `secret-value`.

Zero silent loss does not require preservation of plaintext credentials. It requires observable, sanitized accounting.

---

## Typed-child precedence

When a nested path already has a dedicated typed extraction model, that typed path remains authoritative.

For FortiGate interfaces:

```text
system interface secondaryip
```

uses:

```text
FGInterfaceSecondaryIP
IRInterfaceSecondaryIP
```

and must not also appear in the generic `nested_configs` / `nested_source_configs` collections.

This avoids double counting, duplicated Excel rows, and inconsistent coverage.

Future nested interface families promoted into dedicated typed models should follow the same rule:

1. parse into the dedicated child model;
2. normalize supported semantics;
3. retain unmodeled child settings in sanitized child `extra_settings` / source attributes;
4. remove the same block from the generic nested fallback only when no source evidence would be lost.

---

## Coverage rules

### Parent `system interface`

`system interface` may be `NORMALIZED` only when:

```text
source/parsed/normalized interface counts align
AND
no relevant interface network parse errors exist
AND
no unmodeled nested interface configuration remains
```

If nested source configuration is preserved but not normalized:

```text
status = PARTIALLY_NORMALIZED
```

with a note similar to:

```text
N nested interface configuration block(s) were retained as
extraction-only source data and are not yet normalized into
portable IR.
```

### Nested interface paths

Any nested path under:

```text
system interface ...
```

without a dedicated typed handler should be:

```text
EXTRACT_ONLY
```

rather than:

```text
UNSUPPORTED
```

because the recursive structure is understood and retained safely.

Use a coverage rule based on the prefix instead of enumerating every FortiOS nested interface subsection.

Exception:

```text
system interface secondaryip
```

retains its dedicated `NORMALIZED / PARTIALLY_NORMALIZED` typed coverage.

---

## Manual review rule

An interface with one or more unmodeled nested source blocks must have:

```text
requires_manual_review = true
```

The reason is semantic incompleteness, not parser failure.

A single audit entry per interface is preferred:

```text
Interface 'port1' contains nested FortiGate configuration preserved
as extraction-only source data: ipv6, vrrp, tagging.
Review these settings before target migration.
```

Do not produce one warning for every recursive child unless a child itself has an independent error that warrants a diagnostic.

---

## Excel contract

Add:

```text
Interface Nested Configuration
```

as a source-detail sheet.

Minimum columns:

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

Example:

| Interface | Config Path | Node Type | Object / Edit | Operation | Setting | Value | Extraction Status | Manual Review |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| port1 | ipv6 | config | | set | ip6-address | 2001:db8::1/64 | EXTRACT_ONLY | Yes |
| port1 | ipv6 / ip6-prefix-list | edit | 2001:db8::/64 | set | autonomous-flag | enable | EXTRACT_ONLY | Yes |
| port1 | vrrp | edit | 1 | set | priority | 150 | EXTRACT_ONLY | Yes |

The workbook must preserve multi-value token boundaries deterministically. JSON-list formatting is acceptable when it prevents ambiguity.

---

## Interaction with generic source inventory

The exporter currently omits source paths that have a dedicated FortiGate inventory sheet.

Because:

```text
system interface
```

has dedicated inventory, nested paths beginning with:

```text
system interface ...
```

may also be filtered from the generic `FortiGate Source Configuration` fallback.

Therefore the dedicated:

```text
Interface Nested Configuration
```

sheet is required. Do not rely solely on generic fallback source inventory for these nodes.

---

## Zero-silent-loss acceptance criteria

Nested interface extraction satisfies this model only when:

1. every nested block is either on a dedicated typed path or recursively retained;
2. the owning interface is retained;
3. `config`/`edit` hierarchy is retained;
4. `set`/`unset`/`append` operations are retained;
5. value ordering is deterministic;
6. credentials are sanitized;
7. nested source nodes cannot affect target generation directly;
8. coverage is explicit;
9. manual-review state is explicit;
10. Excel exposes the retained source data;
11. no nested block is simultaneously typed and duplicated into generic fallback;
12. tests cover multiple parent interfaces to prove parent association is not lost.

---

## Recommended future migration

The generic recursive interface tree is a safety net, not the final canonical model.

Future implementation should promote high-value families independently, for example:

```text
config ipv6 -> typed IPv6 interface model
config vrrp -> typed first-hop redundancy model
config vrrp6 -> typed IPv6 redundancy model
```

Promotion must be incremental.

Do not remove the recursive source-preservation mechanism merely because one nested family becomes normalized; it remains the fallback for other or future source constructs.
