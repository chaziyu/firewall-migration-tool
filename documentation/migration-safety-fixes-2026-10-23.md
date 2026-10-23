# PAN-OS migration safety corrections — 2026-10-23

Baseline: `066f505964405cfaa86ea8fb7fa2b3da1155123a`, including the newer main-branch
Node/runtime and extraction-tab changes. This change fixes the concrete SRX/FMC
defects from the Plan migration review. It does not implement the remaining
cross-vendor automation roadmap or add live deployment capabilities.

## Corrected behavior

| Area | Correction | Regression evidence |
| --- | --- | --- |
| PAN-OS to FMC services | `application-default` blocks the policy and its successors instead of becoming an unrestricted service. Explicit `any` remains distinct. | Native XML through review, approval rejection and exported request inspection. |
| PAN-OS to SRX dependencies | Each policy depends on its zones/interfaces and the preceding active policy in that zone pair. Disabled rules do not interrupt predecessor closure. | Approving a later allow includes the earlier Drop and topology; blocked topology/predecessors reject approval; unrelated zone pairs stay independent. |
| PAN-OS to SRX scheduling | A named schedule, including `always`, is never treated as unrestricted. Only the existing version-verified omitted PAN-OS 11.1 behavior is eligible, with provenance. | A native daily 09:00–17:00 schedule named `always` blocks output. Missing/other source versions stay blocked. |
| PAN-OS to SRX routes | Output preserves planned Junos preference alongside next hop and metric. | Explicit preference 100 survives approval and native export; exact snapshot reuse accepts 100 and rejects 101. |
| FMC application | The historical shell filename wraps structured Python HTTPS requests. Returned IDs are substituted in JSON bodies and URL paths. Source strings remain data. | Execute the exact exported Python program with stubbed HTTPS transport, compare each request with the approved specification, and check shell syntax where Bash is available. |
| FMC target identity | No default manager, domain UUID or ownership name. Manager hostname/IP and valid UUID must be supplied before approval; native snapshot UUID must match. | Backend missing/malformed target checks, native-domain mismatch rejection, Flask approval denial and frontend fresh-workspace checks. |

## Compatibility and application

- SRX/FTD draft, approval and artifact envelopes now use version 2. Old envelopes
  require a new review and approval. Mapping proposal formats remain unchanged.
  Previously downloaded files cannot be revoked.
- `cisco_fmc_curl.sh` remains the exported filename. Its manual invocation is now
  `bash cisco_fmc_curl.sh [TOKEN_FILE]` and requires Python 3.11+. Without a token
  file, it prompts privately. Tokens are not passed as command-line arguments or
  included in generated artifacts or progress messages.
- The script binds the reviewed host/domain, verifies TLS, refuses redirects,
  preflights the complete binding sequence, validates returned UUIDs, and stops
  on HTTP/connection/JSON/binding errors without automatic retries. Reconcile
  partial changes before retrying. It does not authenticate, assign interfaces
  or policy, publish, or deploy.
- Existing FMC caller/tests that relied on automatic target values must supply
  explicit mappings. The CLI accepts these through its existing `--zone-map`
  YAML argument. Missing values produce a blocked review with zero operations.

## Verification scope

Regression coverage lives in `test_traffic_safety.py`,
`test_application_safety.py`, the existing pair pipeline and Flask API suites,
and `panosFtdWorkflow.test.mjs`. Tests use sanitized repository fixtures and
synthetic values. No customer configuration, firewall or FMC connection is
required. Live acceptance, traffic equivalence for unsupported features and
device activation remain unverified.

Final local checks: **3,180 Python tests passed, 2 skipped, 16 subtests passed**.
The full run used localhost permissions for the Gunicorn startup check; an
earlier restricted run could not create its listening socket. Both Gunicorn
checks also passed in isolation. Ruff, compileall and whitespace checks passed.
Frontend `npm test` passed all 24 test files, including the new fresh-target
case; ESLint and the TypeScript/Vite production build passed on Node 24.22.1.
The existing production bundle-size warning remains. Python compatibility
versions beyond the local interpreter remain covered by repository CI.

The applicable source-default authority is the existing
[PAN-OS 11.1 security-rule reference](https://docs.paloaltonetworks.com/ngfw/help/11-1/policies/policies-security/building-blocks-in-a-security-policy-rule).
Current capabilities and remaining manual work are in the
[migration support matrix](migration-support-matrix.md).
