# Firewall Migration Tool Documentation

This directory is the maintained documentation entry point for the project.

## Documentation map

| Area | Use it for |
|---|---|
| [How-to guides](how-to/user-guide.md) | Running the tool and completing operational workflows |
| [Architecture](explanation/architecture.md) | Understanding the system design and repository boundaries |
| [Safety model](explanation/safety-model.md) | Zero-silent-loss and fail-closed engineering rules |
| [IR reference](reference/ir/ir-schema.md) | Current canonical IR contract and schema authority |
| [Extraction model](reference/ir/extraction-model.md) | Source accounting and extraction status behavior |
| [Vendor references](reference/vendors/fortigate/extraction-reference.md) | Vendor-specific extraction contracts and limitations |
| [Generated capabilities](generated/capabilities.md) | Runtime-registered source/target plugins and formats |
| [Generated extraction statuses](generated/extraction-statuses.md) | Executable extraction-status vocabulary |
| [Architecture decisions](decisions/README.md) | Long-lived design decisions |
| [Performance baseline](development/performance-baseline.md) | Repeatable performance measurements and optimization gates |
| [Archive](archive/README.md) | Historical plans and superseded detailed snapshots |

## Authority model

For **project behavior**, use this order of authority:

1. executable source code;
2. regression tests;
3. generated documentation derived from code;
4. maintained Markdown reference material.

For **vendor behavior**, use this order:

1. official vendor documentation and API references;
2. official release notes;
3. sanitized, validated source samples;
4. project interpretation.

Documentation must not claim a feature is supported only because vendor syntax exists. Implementation, source accounting, target-generation safety, and tests are separate concerns.

## Version terminology

The project deliberately separates these terms:

- **Tested version**: a version for which repository evidence records explicit validation.
- **Reference version**: a vendor version whose official documentation was used when implementing or auditing behavior.
- **Latest vendor version checked**: the newest release reviewed for documentation freshness. This is **not** an automatic compatibility claim.

Current vendor-version metadata is maintained in [`metadata/vendors.yml`](metadata/vendors.yml).

## Document lifecycle

Active documents use lowercase kebab-case filenames and are recorded in [`metadata/documents.yml`](metadata/documents.yml). Supported lifecycle values are `current`, `draft`, `deprecated`, and `archived`.

Historical phase plans and old detailed snapshots are retained under `archive/` so implementation history does not appear to be the current contract.

## Generated documentation

Do not edit files under `generated/` directly. Regenerate and validate them with:

```bash
python scripts/docs/generate_docs.py
python scripts/docs/generate_docs.py --check
python scripts/docs/validate_docs.py
```

The generator reads `PluginRegistry`, `IR_SCHEMA_VERSION`, and `ExtractionStatus` directly from executable code.

## Contribution rule

When behavior changes, update code and tests first. Then update the relevant maintained document and regenerate code-derived documentation. Never change parser or generator semantics only to make an outdated document true.
