# NAT analysis implementation and validation

## Files changed for this analysis pass

| File | Change |
|---|---|
| `src/fwmigrate/analysis/__init__.py` | Introduces the reporting-analysis package. |
| `src/fwmigrate/analysis/nat_models.py` | Typed, vendor-neutral inventory, policy summary, coverage and diagnostic results. |
| `src/fwmigrate/analysis/intervals.py` | Inclusive IPv4 interval union, intersection, subtraction and cardinality without enumerating hosts. |
| `src/fwmigrate/parsers/fortigate/nat_analysis.py` | Scoped references, static effective states, ordered coverage, source allocation checks, VIP service matching and NAT-001 through NAT-012 diagnostics. |
| `src/fwmigrate/parsers/fortigate/builtin_services.py` | Predefined service recognition and conservative known TCP/UDP baseline; explicit source definitions override defaults. |
| `src/fwmigrate/parsers/fortigate/nat.py` | Calls analysis after existing extraction, recognizes valid advanced pools and Phase 1 tunnel references, removes blanket unrelated-VIP SNAT warnings. |
| `src/fwmigrate/parsers/fortigate/model.py` | Retains and validates advanced pool source-range/block fields. |
| `src/fwmigrate/extraction/models.py` | Reporting-only analysis companion, schema 1.2. |
| `src/fwmigrate/ir/core.py` | Adds configured, nullable effective and analysis-status fields without changing enabled or generation guards. |
| `src/fwmigrate/report/excel_exporter.py` | Separates extraction/traffic coverage and extraction/configuration diagnostics; adds policy summaries, inventory relationships, rule states and summary counts. |
| `tests/test_fortigate_nat_analysis.py` | Diagnostics, boundary cases, API parity, workbook/API checks and optional supplied-file regression. |
| `tests/fixtures/fortigate/nat_analysis_synthetic.conf` | Repository-owned synthetic fixture for the original ten requested scenarios. |
| `tests/test_fortigate_nat_extraction.py` | Updates worksheet-name assertions; preserves existing extraction tests. |
| `documentation/IR_DATA_STRUCTURE.md` | Documents additive IR reporting semantics. |
| `documentation/EXTRACTION_DATA_MODEL.md` | Documents analysis versus extraction accounting. |
| `documentation/NAT_EXTRACTION.md` | Documents flow, supported behavior, diagnostics, actual fixture discrepancies and limitations. |
| `dist/Firewall Migration Tool.exe` | Rebuilt application, verified by a workbook-export smoke test. |

Other pre-existing worktree edits were preserved. The supplied Downloads `.conf`
was read, not modified or copied into the repository. Nothing was committed,
pushed or deployed.

## Flow

```text
file / mocked live API
  -> existing FortiGate parser and source accounting
  -> existing NAT extraction and IR normalization
  -> relationships -> effective state -> ordered traffic coverage -> diagnostics
  -> reporting companion + additive IR state
  -> Excel (before migration optimization)
```

## Verified on 2026-09-09

- 111 focused NAT regressions passed, with `FWMIGRATE_NAT_TEST_CONFIG` pointing
  to the supplied `fortigate_nat_focus_test_FortiOS74.conf`.
- The full suite: 227 passed, 45 failed due to missing `examples/` fixtures,
  1 skipped. The full migration matrix is therefore not certified.
- Packaged Windows executable: successful synthetic Excel export, with checks
  for 12 configured rules, 9 effective, 7 traffic rows, 10 diagnostic rows and
  the renamed extraction-coverage sheet. Temporary test server was stopped.
- `git diff --check` passed.

The supplied file yields 12 configured / 6 effective / 5 not effective /
1 unknown, 4 PASS / 2 WARN / 1 FAIL traffic rows, and 3 PASS / 7 WARN / 4 FAIL
diagnostics. The reason it does not match the original reference totals is
documented in [NAT extraction](NAT_EXTRACTION.md#supplied-focus-fixture-september-2026).

These are static configuration results, not a 100% correctness guarantee for
arbitrary FortiOS configurations. Central-policy composition, dynamic matches,
unknown scopes, routing, sessions, VPN selectors and target generation still
require explicit review or separate validation.
