For `mediatype`, I recommend fixing the gap by making it a **typed source-oriented interface semantic**:

```text
set mediatype sr-lr
```

should become:

```python
FGInterface.mediatype = "sr-lr"
IRInterface.source_media_type = "sr-lr"
source_attributes["mediatype"] = "sr-lr"
```

This makes the value structured and available in the IR/Excel, while **not pretending that FortiGate `mediatype` has a universal cross-vendor equivalent**. Fortinet also notes that `mediatype` is hardware-dependent and, for example, may only exist on units/interfaces with SFPs. 

# Codex implementation plan

## 1. Add typed FortiGate source field

**File**

```text
src/fwmigrate/parsers/fortigate/model.py
```

Current `FGInterface` already has typed fields such as `type`, `role`, `status`, `mode`, and the recently added `speed`, while untyped values fall back to `source_attributes`. 

Add:

```python
class FGInterface(BaseModel):
    ...

    # FortiOS interface media/SFP type.
    # Hardware-dependent source setting; preserve the exact FortiOS token.
    mediatype: Optional[str] = None
```

Recommended placement:

```python
status: str = "up"
mode: str = "static"
username: Optional[str] = None

speed: Optional[str] = None
mediatype: Optional[str] = None
```

### Parser changes

No dedicated parser branch should be necessary if the existing generic `system interface` attribute handling already creates:

```python
FGInterface(**attributes)
```

Codex should verify this with a parser test rather than adding unnecessary special-case parsing.

---

# 2. Add source-oriented IR field

**File**

```text
src/fwmigrate/ir/core.py
```

Inside:

```python
class IRInterface(BaseModel):
```

add:

```python
# Source interface media/SFP mode.
# This is structured source inventory and is not assumed to be a
# portable target-vendor interface media configuration.
source_media_type: Optional[str] = None
```

Recommended placement near:

```python
source_speed: Optional[str] = None
source_duplex: Optional[str] = None
```

For example:

```python
source_mtu: Optional[int] = None
source_link_state: Optional[str] = None
source_speed: Optional[str] = None
source_duplex: Optional[str] = None
source_media_type: Optional[str] = None
source_netflow_profile: Optional[str] = None
```

The existing IR already uses `source_*` interface fields specifically for structured source-oriented inventory that is not necessarily portable. 

### Why `source_media_type` instead of `media_type`

Use:

```python
source_media_type
```

not:

```python
media_type
```

because FortiGate `mediatype` is hardware/platform dependent. It would be unsafe to imply:

```text
FortiGate sr-lr
    =
Vendor B media-type sr-lr
```

without a target-specific mapping layer.

---

# 3. Map FortiGate `mediatype` into IR

**File**

```text
src/fwmigrate/parsers/fortigate/transformer.py
```

When constructing `IRInterface(...)`, add:

```python
source_media_type=intf.mediatype,
```

Example:

```python
ir_interface = IRInterface(
    name=intf.name,
    ...
    source_speed=source_speed,
    source_duplex=source_duplex,
    source_media_type=intf.mediatype,
    ...
)
```

Expected result:

```text
set mediatype sr-lr
```

→

```python
FGInterface.mediatype == "sr-lr"

IRInterface.source_media_type == "sr-lr"

IRInterface.source_attributes["mediatype"] == "sr-lr"
```

---

# 4. Do not remove raw source preservation

Keep:

```python
source_attributes["mediatype"] = "sr-lr"
```

even after adding:

```python
source_media_type = "sr-lr"
```

They serve different purposes:

| Field | Purpose |
|---|---|
| `source_media_type` | Structured IR inventory |
| `source_attributes["mediatype"]` | Exact FortiGate source fidelity |

Do not replace one with the other.

---

# 5. Do not over-normalize `mediatype`

This is important.

Codex should **not** implement logic such as:

```python
if mediatype == "sr-lr":
    media = "fiber"
    optic_type = "SFP+"
    reach = "long-range"
```

That would infer information FortiGate did not explicitly provide.

Fortinet describes `mediatype` as hardware-dependent; availability itself depends on the unit/interface hardware. 

Therefore use the exact source token:

```python
source_media_type = intf.mediatype
```

### Correct

```text
sr-lr → "sr-lr"
```

### Incorrect

```text
sr-lr → "fiber-10G-long-range-SFP+"
```

unless Fortinet documentation explicitly guarantees that interpretation and the project later creates a formal portable media model.

---

# 6. Fix manual-review classification

**File**

```text
src/fwmigrate/parsers/fortigate/transformer.py
```

Currently `mediatype` is preserved but considered an unmodeled top-level setting, which can cause:

```text
PARTIALLY_NORMALIZED
Manual Review = Yes
```

Once it has a typed IR representation, add it to the recognized/normalized source-setting handling.

For example, if the transformer has:

```python
INTERFACE_NORMALIZED_SOURCE_SETTINGS = {
    ...
}
```

add the internal source key:

```python
"mediatype",
```

However, treat it as **recognized source semantics**, not portable target semantics.

After this change:

```text
set mediatype sr-lr
```

alone should no longer create:

```text
Unmodeled top-level interface setting 'mediatype'
```

---

# 7. Unknown values should still be preserved

Unlike `speed`, I would **not use a strict mediatype allowlist**.

Reason: Fortinet explicitly says settings/options can vary by hardware model. 

Therefore:

```text
set mediatype future-optic-mode
```

should still produce:

```python
source_media_type = "future-optic-mode"
source_attributes["mediatype"] = "future-optic-mode"
```

Do **not** reject it simply because the parser has never seen that token before.

This is different from something like an `enable|disable` field whose valid domain is tightly bounded.

---

# 8. Add Excel column

**File**

```text
src/fwmigrate/report/excel_exporter.py
```

Add:

```text
Media Type
```

next to the physical interface properties.

Recommended ordering:

```text
Enabled
MTU
Link State
Speed
Duplex
Media Type
NetFlow Profile
LLDP Enabled
```

The current exporter already has `Speed` and `Duplex` columns in this section. 

### Header

Change:

```python
"Enabled",
"MTU",
"Link State",
"Speed",
"Duplex",
"NetFlow Profile",
```

to:

```python
"Enabled",
"MTU",
"Link State",
"Speed",
"Duplex",
"Media Type",
"NetFlow Profile",
```

### Row

Add in exactly the matching position:

```python
item.source_speed,
item.source_duplex,
item.source_media_type,
item.source_netflow_profile,
```

Be careful to keep header/row indexes aligned.

---

# 9. Update FortiGate interface review tests

**File**

```text
tests/test_fortigate_interface_review.py
```

If `mediatype` is currently included in the parameterized test for unmodeled interface settings, remove it.

For example, remove:

```python
("mediatype", "sr-lr"),
```

from something like:

```python
test_unmodeled_top_level_interface_setting_requires_review
```

It is no longer unmodeled after this change.

---

# 10. Add dedicated mediatype tests

Recommended new file:

```text
tests/test_fortigate_interface_mediatype.py
```

## Test A — parser typing

Input:

```python
config = """
config system interface
    edit "x1"
        set vdom "root"
        set type physical
        set mediatype sr-lr
    next
end
"""
```

Assert:

```python
assert interface.mediatype == "sr-lr"
```

and raw preservation:

```python
assert (
    interface.source_attributes["mediatype"]
    == "sr-lr"
)
```

---

## Test B — IR mapping

Assert:

```python
assert ir_interface.source_media_type == "sr-lr"
```

and:

```python
assert (
    ir_interface.source_attributes["mediatype"]
    == "sr-lr"
)
```

---

## Test C — no unmodeled review warning

For:

```text
set mediatype sr-lr
```

assert:

```python
assert not any(
    "mediatype" in reason.lower()
    for reason in interface.review_reasons
)
```

Do not necessarily assert:

```python
requires_manual_review is False
```

unless the test interface contains **no other reason** for manual review.

That makes the test less brittle.

---

## Test D — preserve hardware-specific unknown token

Input:

```text
set mediatype vendor-new-optic
```

Assert:

```python
assert (
    interface.source_media_type
    == "vendor-new-optic"
)

assert (
    interface.source_attributes["mediatype"]
    == "vendor-new-optic"
)
```

This verifies future FortiGate hardware values are not dropped.

---

# 11. Add Excel test

**File**

```text
tests/test_excel_exporter.py
```

Add an interface such as:

```python
IRInterface(
    name="x1",
    source_speed="10000",
    source_duplex="full",
    source_media_type="sr-lr",
)
```

Assert:

```python
assert row["Speed"] == "10000"
assert row["Duplex"] == "full"
assert row["Media Type"] == "sr-lr"
```

---

# 12. Include IR schema-versioning files from the start

Because this adds a serialized field to:

```python
IRInterface
```

Codex must include schema management in the plan immediately.

The repository currently shows IR schema `1.23`. 

However, **do not blindly hard-code 1.24** if your `device-identification` change lands first.

### Files

```text
src/fwmigrate/ir/version.py
src/fwmigrate/ir/migrations.py
tests/test_ir_schema_version.py
```

### Version rule

At implementation time:

```text
current schema N
       ↓
bump one minor version
```

For example:

- if current = `1.23` → mediatype becomes `1.24`;
- if `device-identification` already bumped it to `1.24` → mediatype becomes `1.25`.

Do not create two unrelated migration functions claiming the same schema version.

---

## Migration change

**File**

```text
src/fwmigrate/ir/migrations.py
```

The migration should add:

```python
interface.setdefault(
    "source_media_type",
    None,
)
```

for every interface.

The existing migration framework already uses this pattern for adding optional interface fields. 

For example:

```python
def _migrate_1_25(
    payload: dict[str, Any],
) -> dict[str, Any]:
    migrated = dict(payload)

    interfaces = []

    for source_interface in payload.get(
        "interfaces",
        [],
    ):
        if not isinstance(source_interface, dict):
            interfaces.append(source_interface)
            continue

        interface = dict(source_interface)

        interface.setdefault(
            "source_media_type",
            None,
        )

        interfaces.append(interface)

    migrated["interfaces"] = interfaces
    migrated["schema_version"] = IR_SCHEMA_VERSION

    return migrated
```

Adapt the function version to whatever the actual next schema is.

### Important

Migration default must be:

```python
None
```

not:

```python
"auto"
```

and not:

```python
"unknown"
```

because old serialized IR documents contain no evidence about the source interface's `mediatype`.

---

# 13. Update schema tests

**File**

```text
tests/test_ir_schema_version.py
```

Add/update tests proving:

### Current schema

```python
assert IR_SCHEMA_VERSION == "<new version>"
```

### Previous-version migration

Old:

```python
{
    "schema_version": "<previous>",
    "interfaces": [
        {
            "name": "x1",
            "source_speed": "10000",
        }
    ],
}
```

After migration:

```python
assert interface["source_media_type"] is None
```

and:

```python
assert interface["source_speed"] == "10000"
```

This proves the migration does not alter unrelated interface data.

---

# 14. Update documentation

## File

```text
documentation/FORTIGATE_CONFIG_EXTRACTION_REFERENCE.md
```

Add:

```markdown
### Interface media type

FortiGate `system interface -> mediatype` is retained as a
typed source-interface property.

The exact configured token is represented as:

`IRInterface.source_media_type`

and is also retained in `source_attributes["mediatype"]`
for source fidelity.

Example:

`set mediatype sr-lr`

becomes:

`source_media_type = "sr-lr"`

FortiOS media-type availability and supported values are
hardware-dependent. The extractor therefore preserves the
configured token and does not infer optic type, wavelength,
reach, connector type, or equivalent target-vendor media
configuration.
```

## File

```text
documentation/IR_DATA_STRUCTURE.md
```

Document:

```python
source_media_type: Optional[str]
```

as **structured source inventory**, not universally portable target semantics.

---

# Full Codex file list

| Full path | Change |
|---|---|
| `src/fwmigrate/parsers/fortigate/model.py` | Add `FGInterface.mediatype` |
| `src/fwmigrate/ir/core.py` | Add `IRInterface.source_media_type` |
| `src/fwmigrate/parsers/fortigate/transformer.py` | Map mediatype and remove unmodeled classification |
| `src/fwmigrate/report/excel_exporter.py` | Add `Media Type` column |
| `src/fwmigrate/ir/version.py` | Minor IR schema bump |
| `src/fwmigrate/ir/migrations.py` | Migration default `source_media_type=None` |
| `tests/test_ir_schema_version.py` | Version/migration tests |
| `tests/test_fortigate_interface_review.py` | Remove `mediatype` from unmodeled case |
| `tests/test_fortigate_interface_mediatype.py` | New parser/transformer tests |
| `tests/test_excel_exporter.py` | Verify `Media Type` Excel output |
| `documentation/FORTIGATE_CONFIG_EXTRACTION_REFERENCE.md` | Document FortiGate semantics |
| `documentation/IR_DATA_STRUCTURE.md` | Document IR field |

## Acceptance criteria

For:

```text
set mediatype sr-lr
```

Codex should produce:

```text
FortiGate model
FGInterface.mediatype
= "sr-lr"

        ↓

IR
IRInterface.source_media_type
= "sr-lr"

        ↓

Source fidelity
source_attributes["mediatype"]
= "sr-lr"

        ↓

Excel
Media Type
= sr-lr
```

And `mediatype` should **no longer trigger a manual-review reason simply because it is unmodeled**.

The fix should **not** attempt:

```text
sr-lr → standardized SFP/SFP+/fiber/optic specification
```

or automatically translate it into a target-vendor media configuration. That requires a separate cross-vendor physical-interface media model and reliable equivalence rules; FortiOS itself makes these options hardware-dependent. 