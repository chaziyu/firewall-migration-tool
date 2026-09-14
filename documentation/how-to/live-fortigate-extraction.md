# Live FortiGate Extraction

## Scope

The current live-source workflow acquires a FortiGate configuration over SSH for source inventory. It does not make all FortiGate semantics portable and it is not a general live-migration source for every vendor.

```text
FortiGate SSH
    -> SourceSnapshot
    -> FortiGateSourceParser.extract()
    -> ExtractionResult + IRConfig
    -> source inventory workbook
```

## Web workflow

Start the application:

```bash
fwmigrate serve --port 5000
```

Then use **Extract Data to Excel → Input Method: Live Firewall**.

The workflow performs a connection test and then pulls a complete source snapshot. The collector executes `get system status` and `show full-configuration` through a non-PTY SSH channel.

## CLI workflow

```bash
fwmigrate-live-fortigate \
  --host 192.0.2.10 \
  --username admin \
  --verify-host-key \
  --output fortigate_source_inventory.xlsx
```

The password can be prompted without echoing it.

## Completeness

`SourceSnapshot.complete` means the collection passed transport/content checks. It does not mean every source semantic was normalized. Parser completeness is represented by `ExtractionResult` and the statuses in [`../generated/extraction-statuses.md`](../generated/extraction-statuses.md).

## Security

Credentials are not part of the preserved source snapshot or workbook metadata. The raw source configuration must not be returned to the browser as an ordinary API payload. Real-device validation should be performed with representative FortiOS versions, models, VDOM modes, and administrator permission profiles before making version-specific collection claims.
