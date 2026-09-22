The branch is much cleaner now. `src/fwmigrate/ir/` and `src/fwmigrate/parsers/` are gone, PAN-OS is under `vendors/`, and `conversion/` is only a future directional boundary. I would stop structural deletion now and move into **vendor-native hardening**.

Recommended next order:

1. **Fix remaining boundary violations**
   - FTD: remove `config.unresolved_references = ...`; keep it only in `FTDDerivedViews`.
   - Remove source-model fields such as `migration_status` where they only came from the old migration architecture.
   - ASA: replace the `deepcopy(config) → validate_references()` workaround with genuinely read-only reference resolution.

2. **Clean shared extraction terminology**
   - `ExtractionStatus.NORMALIZED` / `PARTIALLY_NORMALIZED`
   - `MigrationImpact`
   - `object_count_normalized`
   
   Move toward source-oriented terms such as:
   ```text
   EXTRACTED
   PARTIAL
   SOURCE_ONLY
   UNSUPPORTED
   UNKNOWN
   PARSE_ERROR
   ```
   Shared `extraction/` should describe extraction evidence, not migration readiness.

3. **Strengthen each vendor differently**
   - FortiGate: keep as reference architecture; avoid unnecessary changes.
   - ASA: introduce clearer `relationships/` logic, especially references/ACL/interface/NAT relationships.
   - FTD: preserve `cli/`, `fmc/`, `fdm/`; strengthen source-plane authority/completeness.
   - Juniper: keep handlers/resolvers; gradually replace `dict[str, Any]` derived records with typed relationship models.
   - Check Point: highest need for typed source models instead of relying mainly on generic `CheckPointSourceRecord`; later separate `management/` and `gaia/`.
   - PAN-OS: highest semantic-development priority. Current `PANOSConfig` is still mostly generic XML records. Rebuild typed PAN-OS extraction gradually before expanding Excel.

4. **Standardize responsibility, not directory shape**
   Target conceptually:
   ```text
   source
   → VendorConfig
   → relationships / transforms
   → VendorDerivedViews
   → validation
   → preview / Excel
   ```
   Do not force every vendor to have identical module names.

5. **Then improve Excel vendor by vendor**
   Do not make Excel drive the models.
   ```text
   explicit VendorConfig fields
   + genuine DerivedViews
   + validation
   + source/unsupported appendix
   → vendor Excel
   ```

6. **Keep `conversion/` untouched for now**
   Its current README/contracts are appropriate:
   ```text
   VendorSourceConfig
   → pair-specific converter
   → TargetVendorConfig
   ```
   Do not implement mappings or generic target models yet.

7. **Add architecture regression tests**
   Enforce:
   ```text
   source models are not mutated by derived/validation
   source_reporting has no firewall semantic models
   vendor Excel only consumes its own vendor state
   vendors do not depend on conversion/
   web.py treats vendor results as opaque
   no actual secrets in source/raw/preview/Excel
   ```

So the next milestone I would use is **“source architecture stabilization”**, not more folder cleanup. The most valuable work now is FTD/ASA boundary cleanup, shared terminology cleanup, then Check Point and PAN-OS model maturity.