# Future migration-planning boundary

This package reserves the directional migration-planning boundary. It is not
used by source extraction or reporting.

```text
VendorSourceConfig
→ VendorDerivedViews
→ pair-specific migration planner
→ pair-specific MigrationPlan
→ plan validation
→ target command renderer
```

`MigrationPlan` is not a complete target configuration. It contains only
supported generated items plus partial, manual-review, and unsupported findings.

Future pairs may include:

- `cisco_asa_to_fortigate`
- `juniper_srx_to_fortigate`
- `cisco_ftd_to_fortigate`
- `checkpoint_to_fortigate`

Migration fixtures remain available for future pair-specific work. Do not add
generic source/target models, shared mapping tables, or an IR replacement here.
