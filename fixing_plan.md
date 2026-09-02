Assuming you mean **`device-identification` — “Preserved, not modeled”**, the fix should be different from `speed`.

For `device-identification`, I would **model the source semantic explicitly in IR**, but keep it as **source-oriented vendor-neutral inventory**, not as a guaranteed portable target behavior. FortiGate defines this as passive device identification on the interface, so automatically translating it into another vendor’s feature would be unsafe.

## Codex implementation plan

### Goal

Current FortiGate:

```text
config system interface
    edit "HQ_Vlan20"
        set device-identification enable
    next
end
```

Currently becomes roughly:

```python
source_attributes["device_identification"] = "enable"
requires_manual_review = True
```

Target result:

```python
IRInterface.source_device_identification = "enable"
source_attributes["device_identification"] = "enable"
```

and Excel:

| Name | Device Identification |
|---|---|
| HQ_Vlan20 | enable |

The setting should no longer be considered an **unknown/unmodeled top-level interface setting**.

---

# 1. Add typed FortiGate model field

### File

```text
src/fwmigrate/parsers/fortigate/model.py
```

`FGInterface` currently has typed interface properties such as `status`, `mode`, `role`, `allowaccess`, etc., while other explicit settings remain only in `source_attributes`. 

Add:

```python
class FGInterface(BaseModel):
    name: str
    vdom: str = "root"
    source_context: str = "root"

    ...

    status: str = "up"
    mode: str = "static"
    username: Optional[str] = None

    # FortiOS passive device identification setting.
    device_identification: Optional[str] = None
```

Use `Optional[str]`, **not `bool`**, at the source-model layer.

Reason: preserve exact FortiOS semantics:

```text
enable
disable
```

without prematurely converting unknown/future values.

The parser already constructs:

```python
FGInterface(**attributes)
```

so adding the typed field should allow existing generic attribute parsing to populate it. 

---

# 2. Add a source-oriented field to the vendor-neutral IR

### File

```text
src/fwmigrate/ir/core.py
```

Inside:

```python
class IRInterface(BaseModel):
```

add:

```python
# Source interface device-identification behavior.
# This records whether the source platform enables passive
# device identification on the interface. It is inventory/audit
# data and must not imply direct target-vendor portability.
source_device_identification: Optional[str] = None
```

Recommended name:

```python
source_device_identification
```

rather than:

```python
device_identification
```

### Why use `source_...`?

Because this is **not safely universal firewall behavior**.

For example:

```text
FortiGate device-identification
```

does not necessarily equal:

```text
Palo Alto Device-ID
```

or another vendor's device discovery mechanism.

The repository already follows this pattern for source-oriented interface semantics such as:

```python
source_speed
source_duplex
source_mtu
source_link_state
```



So the IR becomes vendor-neutral as an **inventory representation**, without falsely claiming the setting is portable.

---

# 3. Populate the IR field in the FortiGate transformer

### File

```text
src/fwmigrate/parsers/fortigate/transformer.py
```

Inside the interface transformation where `IRInterface(...)` is created, add:

```python
source_device_identification=intf.device_identification,
```

For example:

```python
ir_interface = IRInterface(
    name=intf.name,
    source_context=intf.source_context,
    ...
    source_device_identification=intf.device_identification,
    ...
)
```

Expected transformation:

```text
set device-identification enable
```

becomes:

```python
FGInterface.device_identification
    == "enable"

IRInterface.source_device_identification
    == "enable"

IRInterface.source_attributes["device_identification"]
    == "enable"
```

The raw source copy should remain.

---

# 4. Keep source preservation

### File

```text
src/fwmigrate/parsers/fortigate/transformer.py
```

Do **not** remove:

```python
source_attributes["device_identification"]
```

when introducing the typed field.

You want both:

```python
source_device_identification = "enable"
```

and:

```python
source_attributes["device_identification"] = "enable"
```

They serve different purposes:

| Field | Purpose |
|---|---|
| `source_device_identification` | Structured semantic inventory |
| `source_attributes[...]` | Exact FortiGate source/audit preservation |

The repository explicitly preserves top-level interface settings for source fidelity. 

---

# 5. Fix manual-review classification

### File

```text
src/fwmigrate/parsers/fortigate/transformer.py
```

This is one of the most important changes.

Currently `device-identification` is deliberately tested as an unmodeled setting that requires review. The repository contains:

```python
("device-identification", "enable"),
```

inside:

```text
tests/test_fortigate_interface_review.py
```

under:

```python
test_unmodeled_top_level_interface_setting_requires_review
```



That expectation should be changed after modeling the setting.

### Add it to the recognized interface source settings

Where the transformer defines something equivalent to:

```python
INTERFACE_NORMALIZED_SOURCE_SETTINGS = {
    ...
}
```

add:

```python
"device_identification",
```

or the corresponding normalized source key used by the parser.

Remember:

```text
device-identification
```

in CLI becomes:

```python
device_identification
```

internally.

---

## Important distinction

I would **not** classify it as fully portable target semantics.

Instead, treat it as:

```text
recognized + structured source semantic
```

Therefore:

```text
device-identification alone
```

should **not trigger manual review merely because the parser did not understand it**.

But target generators must still not automatically translate it unless a target-specific mapping is explicitly implemented.

---

# 6. Normalize only valid FortiOS values

### File

```text
src/fwmigrate/parsers/fortigate/transformer.py
```

Add a small validation helper:

```python
def _normalize_device_identification(
    value: Optional[str],
) -> Optional[str]:
    if value is None:
        return None

    normalized = value.lower()

    if normalized in {"enable", "disable"}:
        return normalized

    return None
```

Then:

```python
source_device_identification = (
    _normalize_device_identification(
        intf.device_identification
    )
)
```

### Unknown values

If somehow the source contains:

```text
set device-identification unexpected-value
```

do **not** guess.

Expected result:

```python
source_attributes["device_identification"]
    == "unexpected-value"

source_device_identification
    is None

requires_manual_review
    is True
```

This preserves the project's conservative parsing behavior.

---

# 7. Add Excel column

Unlike `speed`, this one **does require an Excel exporter change**, because there currently is no dedicated Device Identification column.

### File

```text
src/fwmigrate/report/excel_exporter.py
```

Inside:

```python
def _build_interfaces(self, workbook):
```

the current interface headers include fields such as:

```text
Enabled
MTU
Link State
Speed
Duplex
...
```



Add a new column, preferably near other operational/interface properties:

```python
"Device Identification",
```

For example:

```python
headers = (
    "Name",
    "Source VDOM",
    ...
    "Enabled",
    "MTU",
    "Link State",
    "Speed",
    "Duplex",
    "Device Identification",
    "NetFlow Profile",
    ...
)
```

Then in the corresponding row:

```python
item.source_device_identification,
```

Keep header and row ordering exactly aligned.

---

# 8. Update the existing review test

### File

```text
tests/test_fortigate_interface_review.py
```

Currently this setting is explicitly expected to be unmodeled:

```python
("device-identification", "enable"),
```



Remove:

```python
("device-identification", "enable"),
```

from:

```python
test_unmodeled_top_level_interface_setting_requires_review
```

because it will no longer be unmodeled.

Then add a dedicated test.

---

# 9. Add FortiGate device-identification tests

Recommended new file:

```text
tests/test_fortigate_interface_device_identification.py
```

### Test 1 — parser creates typed field

```python
def test_interface_device_identification_is_typed():
    config = """
config system interface
    edit "port1"
        set vdom "root"
        set device-identification enable
    next
end
"""

    result = parse_fortigate_config(config)

    interface = result.interfaces[0]

    assert interface.device_identification == "enable"
```

Also verify raw preservation:

```python
assert (
    interface.source_attributes["device_identification"]
    == "enable"
)
```

---

### Test 2 — transformer populates IR

```python
def test_device_identification_maps_to_ir():
    ...
```

Assert:

```python
assert (
    interface.source_device_identification
    == "enable"
)
```

and:

```python
assert (
    interface.source_attributes["device_identification"]
    == "enable"
)
```

---

### Test 3 — disable

Input:

```text
set device-identification disable
```

Assert:

```python
assert (
    interface.source_device_identification
    == "disable"
)
```

Do not interpret `"disable"` as missing.

---

# 10. Test manual-review behavior

Add:

```python
def test_known_device_identification_does_not_trigger_unmodeled_review():
```

Input:

```text
config system interface
    edit "port1"
        set device-identification enable
    next
end
```

Assert:

```python
assert not any(
    "device-identification" in reason
    or "device_identification" in reason
    for reason in interface.review_reasons
)
```

The key point is:

> `device-identification` must no longer be classified as an **unknown top-level setting**.

---

## Test unknown value separately

```python
def test_unknown_device_identification_requires_review():
```

Use:

```text
set device-identification unknown
```

Expected:

```python
assert interface.source_device_identification is None

assert (
    interface.source_attributes["device_identification"]
    == "unknown"
)

assert interface.requires_manual_review is True
```

---

# 11. Add Excel exporter test

### File

```text
tests/test_excel_exporter.py
```

Create:

```python
IRInterface(
    name="port1",
    source_device_identification="enable",
)
```

Generate the workbook and assert:

```python
assert row["Device Identification"] == "enable"
```

Also ensure `Additional Settings` still contains the source setting when the test passes it through `source_attributes`.

---

# 12. Update documentation

### File

```text
documentation/FORTIGATE_CONFIG_EXTRACTION_REFERENCE.md
```

Add something similar:

```markdown
### Device identification

FortiGate `system interface -> device-identification`
is extracted as a typed source-interface semantic.

The normalized source value is stored in:

`IRInterface.source_device_identification`

Supported values:

- `enable`
- `disable`

The exact FortiGate setting remains preserved in
`IRInterface.source_attributes`.

This field represents source inventory semantics only.
It must not be interpreted as a direct portable equivalent
of another vendor's device-identification technology.
```

---

### File

```text
documentation/IR_DATA_STRUCTURE.md
```

Document:

```python
source_device_identification: Optional[str]
```

and explicitly state:

> This is structured vendor-neutral **source inventory**, not guaranteed cross-vendor migration behavior.

That wording matters.

---

# Files Codex should modify

| Full repository path | Required change |
|---|---|
| `src/fwmigrate/parsers/fortigate/model.py` | Add `FGInterface.device_identification` |
| `src/fwmigrate/ir/core.py` | Add `IRInterface.source_device_identification` |
| `src/fwmigrate/parsers/fortigate/transformer.py` | Validate/map setting and stop classifying valid values as unmodeled |
| `src/fwmigrate/report/excel_exporter.py` | Add `Device Identification` interface column |
| `tests/test_fortigate_interface_review.py` | Remove it from unmodeled-setting test |
| `tests/test_fortigate_interface_device_identification.py` | New parser/transformer/review tests |
| `tests/test_excel_exporter.py` | Test Excel output |
| `documentation/FORTIGATE_CONFIG_EXTRACTION_REFERENCE.md` | Document extraction semantics |
| `documentation/IR_DATA_STRUCTURE.md` | Document new IR field |

## Acceptance criteria for Codex

For:

```text
set device-identification enable
```

the completed pipeline should produce:

```text
FortiGate model
FGInterface.device_identification
= "enable"

        ↓

IR
IRInterface.source_device_identification
= "enable"

        ↓

Source fidelity
source_attributes["device_identification"]
= "enable"

        ↓

Excel
Device Identification
= enable
```

And the interface should **not be marked manual-review merely because `device-identification` is present**.

However, Codex should **not implement automatic target-vendor conversion** such as:

```text
FortiGate device-identification
→ Palo Alto Device-ID
```

as part of this fix. Those technologies are not necessarily semantically equivalent. This change should make the setting **structured and understood in IR**, while remaining conservative about cross-vendor portability.