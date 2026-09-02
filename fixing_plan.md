Object: make FortiGate `speed` a **typed interface field**, decode the FortiOS combined value into the existing IR `Speed` + `Duplex` fields, and keep the original raw value for audit.

FortiOS 7.4.6 defines `speed` as a hardware-dependent option. Examples include `100full`, `1000auto`, `10000full`, `10000auto`, and hardware-specific higher-speed variants. 

## Codex implementation plan

### Goal

Change:

```text
set speed 10000full
```

from only:

```text
Additional Settings:
speed=10000full
```

to:

```text
Speed: 10000
Duplex: full
Additional Settings:
speed=10000full
```

Likewise:

```text
set speed 5000auto
```

becomes:

```text
Speed: 5000
Duplex: auto
```

The raw FortiGate value must still be retained for source fidelity.

---

## 1. Add `speed` to the FortiGate interface model

**File**

```text
src/fwmigrate/parsers/fortigate/model.py
```

`FGInterface` currently models fields such as `type`, `role`, `vlanid`, `status`, `mode`, and `username`, but not `speed`. 

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

    # FortiOS physical interface speed option.
    # Preserve the exact source token, e.g.:
    # auto, 100full, 1000auto, 10000full, 5000auto.
    speed: Optional[str] = None
```

### Why

The parser already creates interfaces through:

```python
FGInterface(**attributes)
```

so once `speed` exists in `FGInterface`, the existing generic parsing machinery can populate it from:

```text
set speed 10000full
```

without writing a special parser branch. 

---

## 2. Decode FortiGate speed semantics

**File**

```text
src/fwmigrate/parsers/fortigate/transformer.py
```

Add a helper near `_normalize_interface_ip()`.

Recommended implementation:

```python
FORTIGATE_INTERFACE_SPEED_RE = re.compile(
    r"^(?P<rate>\d+)(?P<unit>G)?"
    r"(?P<mode>full|half|auto|cr4?|sr4?)$",
    re.IGNORECASE,
)


def _normalize_interface_speed(
    value: Optional[str],
) -> tuple[Optional[str], Optional[str]]:
    """
    Convert a FortiOS combined interface speed token into
    speed and duplex/negotiation fields.

    Examples:
        100full    -> ("100", "full")
        1000auto   -> ("1000", "auto")
        10000full  -> ("10000", "full")
        5000auto   -> ("5000", "auto")
        100Gfull   -> ("100000", "full")
        auto        -> ("auto", "auto")

    Hardware/media-specific suffixes such as sr/cr still expose
    the speed, but do not invent duplex semantics.
    """
    if not value:
        return None, None

    raw = value.strip()

    if raw.lower() == "auto":
        return "auto", "auto"

    match = FORTIGATE_INTERFACE_SPEED_RE.fullmatch(raw)
    if not match:
        return None, None

    rate = int(match.group("rate"))

    if match.group("unit"):
        rate *= 1000

    mode = match.group("mode").lower()

    if mode == "full":
        duplex = "full"
    elif mode == "half":
        duplex = "half"
    elif mode == "auto":
        duplex = "auto"
    else:
        # sr/cr describe media, not duplex.
        duplex = None

    return str(rate), duplex
```

### Required behavior

| FortiGate source | Speed | Duplex |
|---|---:|---|
| `auto` | `auto` | `auto` |
| `100full` | `100` | `full` |
| `100half` | `100` | `half` |
| `1000full` | `1000` | `full` |
| `1000auto` | `1000` | `auto` |
| `5000auto` | `5000` | `auto` |
| `10000full` | `10000` | `full` |
| `10000auto` | `10000` | `auto` |
| `100Gfull` | `100000` | `full` |
| hardware-specific `10000sr` | `10000` | blank |

Do **not** simply strip `full`/`auto` with hardcoded string replacements. FortiOS speed choices are hardware-dependent. 

---

## 3. Map decoded values into `IRInterface`

**File**

```text
src/fwmigrate/parsers/fortigate/transformer.py
```

Inside:

```python
_transform_interfaces_and_zones()
```

before constructing `IRInterface`, calculate:

```python
source_speed, source_duplex = _normalize_interface_speed(
    intf.speed
)
```

Then add to the existing `IRInterface(...)`:

```python
IRInterface(
    name=intf.name,
    ...
    source_speed=source_speed,
    source_duplex=source_duplex,
    ...
)
```

The IR already contains:

```python
source_speed: Optional[str] = None
source_duplex: Optional[str] = None
```

so **do not add duplicate IR fields**. 

---

## 4. Fix the manual-review classification

**File**

```text
src/fwmigrate/parsers/fortigate/transformer.py
```

This part is important.

Currently `speed` is not considered semantically normalized, so the tool generates:

```text
Unmodeled top-level interface setting 'speed'
may affect traffic behavior
```

Do **not** blindly add:

```python
"speed"
```

to `INTERFACE_NORMALIZED_SOURCE_SETTINGS` unless every possible value is guaranteed to parse.

Instead, make the classification conditional:

```python
if setting == "speed":
    normalized_speed, normalized_duplex = (
        _normalize_interface_speed(interface.speed)
    )

    if normalized_speed is not None:
        # Known/understood FortiOS speed syntax.
        continue
```

Then let an unrecognized speed value continue through the existing manual-review logic.

### Expected result

Known:

```text
set speed 10000full
```

→ no `"speed"` manual-review reason.

Unknown/future hardware token:

```text
set speed some-new-hardware-mode
```

→ preserve the source setting and retain manual review.

This is safer because Fortinet explicitly states that available speed options depend on interface hardware. 

---

## 5. Do not remove raw `speed` from source preservation

The final IR should contain both:

```python
source_speed = "10000"
source_duplex = "full"
```

and:

```python
source_attributes["speed"] = "10000full"
```

This is intentional.

The structured fields answer:

> What does this setting mean?

The source attribute answers:

> What exactly did FortiGate contain?

The project already documents that explicit top-level FortiGate interface settings are retained as source attributes for audit/source fidelity. 

---

## 6. Excel exporter does not need structural changes

**Existing file**

```text
src/fwmigrate/report/excel_exporter.py
```

No new Excel columns are required.

The `Interfaces` sheet already has:

```text
Speed
Duplex
```

and already exports:

```python
item.source_speed,
item.source_duplex,
```



Therefore, once the transformer populates these IR fields, Excel will automatically change from:

| Interface | Speed | Duplex | Additional Settings |
|---|---|---|---|
| x1 | | | `speed=10000full; ...` |

to:

| Interface | Speed | Duplex | Additional Settings |
|---|---|---|---|
| x1 | 10000 | full | `speed=10000full; ...` |

**Do not duplicate these columns.**

---

# 7. Add dedicated unit tests

I recommend a new file:

```text
tests/test_fortigate_interface_speed.py
```

### Test 1 — typed parsing

```python
def test_fortigate_interface_speed_is_typed():
    config = """
config system interface
    edit "port1"
        set vdom "root"
        set type physical
        set speed 10000full
    next
end
"""

    result = parse_fortigate_config(config)

    interface = result.interfaces[0]

    assert interface.speed == "10000full"
    assert interface.source_attributes["speed"] == "10000full"
```

This proves parsing is no longer source-only.

---

### Test 2 — semantic decoding

Use parameterized tests:

```python
@pytest.mark.parametrize(
    ("raw_speed", "expected_speed", "expected_duplex"),
    [
        ("auto", "auto", "auto"),
        ("100full", "100", "full"),
        ("100half", "100", "half"),
        ("1000full", "1000", "full"),
        ("1000auto", "1000", "auto"),
        ("5000auto", "5000", "auto"),
        ("10000full", "10000", "full"),
        ("10000auto", "10000", "auto"),
        ("100Gfull", "100000", "full"),
    ],
)
def test_fortigate_interface_speed_normalization(
    raw_speed,
    expected_speed,
    expected_duplex,
):
    ...
```

Assert:

```python
assert interface.source_speed == expected_speed
assert interface.source_duplex == expected_duplex
```

---

### Test 3 — known speed does not require manual review

Use a minimal interface:

```text
config system interface
    edit "port1"
        set type physical
        set speed 10000full
    next
end
```

Assert:

```python
assert interface.requires_manual_review is False
assert not any(
    "speed" in reason.lower()
    for reason in interface.review_reasons
)
```

This directly fixes the current issue.

---

### Test 4 — unknown speed remains safe

```python
def test_unknown_fortigate_interface_speed_requires_review():
    config = """
config system interface
    edit "port1"
        set speed future-hardware-speed
    next
end
"""

    ...
```

Expected:

```python
assert interface.source_speed is None
assert interface.source_attributes["speed"] == "future-hardware-speed"

assert interface.requires_manual_review is True
assert any(
    "speed" in reason.lower()
    for reason in interface.review_reasons
)
```

**Do not silently guess an unknown FortiOS speed.**

---

## 8. Add Excel integration test

**File**

```text
tests/test_excel_exporter.py
```

Add a FortiGate pipeline test with:

```text
set speed 10000full
```

Then check:

```python
assert values["Speed"] == "10000"
assert values["Duplex"] == "full"
```

Also verify:

```python
assert "speed=10000full" in values["Additional Settings"]
```

This proves both semantic extraction and original source preservation.

---

## 9. Update FortiGate extraction documentation

### File 1

```text
documentation/FORTIGATE_CONFIG_EXTRACTION_REFERENCE.md
```

Update the `system interface` section with something similar to:

```markdown
### Interface speed

`set speed` is parsed as a typed FortiGate interface field.

Recognized FortiOS speed tokens are decomposed into the IR interface
`source_speed` and `source_duplex` fields while the exact FortiGate token
remains in `source_attributes`.

Examples:

- `100full` -> speed `100`, duplex `full`
- `1000auto` -> speed `1000`, duplex `auto`
- `5000auto` -> speed `5000`, duplex `auto`
- `10000full` -> speed `10000`, duplex `full`

Unrecognized hardware-dependent values are preserved without coercion and
require manual review.
```

### File 2

```text
documentation/IR_DATA_STRUCTURE.md
```

Clarify that `IRInterface.source_speed` and `source_duplex` can now be populated by FortiGate as well as PAN-OS.

---

# Files Codex should change

| Full repository path | Change |
|---|---|
| `src/fwmigrate/parsers/fortigate/model.py` | Add typed `FGInterface.speed` |
| `src/fwmigrate/parsers/fortigate/transformer.py` | Decode FortiOS speed; populate `source_speed` / `source_duplex`; fix review classification |
| `tests/test_fortigate_interface_speed.py` | **New** focused speed tests |
| `tests/test_excel_exporter.py` | Verify FortiGate Speed/Duplex Excel output |
| `documentation/FORTIGATE_CONFIG_EXTRACTION_REFERENCE.md` | Document speed semantics |
| `documentation/IR_DATA_STRUCTURE.md` | Document FortiGate population of existing speed fields |

### No structural change required

```text
src/fwmigrate/ir/core.py
src/fwmigrate/report/excel_exporter.py
```

`IRInterface` already has `source_speed` / `source_duplex`, and the Excel exporter already has `Speed` / `Duplex` columns.  

## Codex acceptance criteria

After implementation:

```text
set speed 10000full
```

must produce:

```text
FGInterface.speed           = "10000full"

IRInterface.source_speed    = "10000"
IRInterface.source_duplex   = "full"

source_attributes["speed"]  = "10000full"
```

and Excel:

```text
Speed  = 10000
Duplex = full
Additional Settings still contains speed=10000full
```

A recognized `speed` value by itself must **no longer cause `PARTIALLY_NORMALIZED` / Manual Review**. An unrecognized hardware-dependent value must still be preserved and flagged rather than guessed. This addresses the actual semantic-mapping gap without weakening the project's conservative extraction behavior.