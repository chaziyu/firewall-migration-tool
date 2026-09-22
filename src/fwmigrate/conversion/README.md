# Future conversion boundary

This package reserves the directional conversion boundary. It currently has no
vendor implementations and is not used by source extraction or reporting.

```text
VendorSourceConfig
→ VendorDerivedViews
→ pair-specific converter
→ TargetVendorConfig
→ target validation
→ target renderer
```

Future pairs may include:

- `cisco_asa_to_fortigate`
- `juniper_srx_to_fortigate`
- `cisco_ftd_to_fortigate`
- `checkpoint_to_fortigate`

Conversion fixtures remain available for future pair-specific work. Do not add
generic source/target models, shared mapping tables, or an IR replacement here.
