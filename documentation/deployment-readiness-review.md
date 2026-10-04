# Deployment readiness remediation

The 2026-10-02 review used commit `10b884f0`. This follow-up applies the
confirmed CI repairs on top of `fdbb3163` (which already includes customer-data
hardening). Passing CI does not establish production deployment readiness.

## Applied CI repairs

- Candidate commit rejects missing, expired, mismatched and changed sessions
  through a typed exception with fixed public messages and stable `error_code`
  values. Unexpected `ValueError` details stay out of responses and logs.
  Session failures remain HTTP 400 and do not connect to a firewall.
- Snyk uses job-scoped `secrets.SNYK_TOKEN`. Set repository variable
  `SNYK_ENABLED=true` only after approving transfer of source and analysis to
  Snyk; the default is skipped. Pull requests never run with the Snyk token.
  Dependencies are installed before scanning. Exit 1 means vulnerability
  findings and fails the final policy step; scanner/configuration failures
  fail their scan step. Generated code SARIF is uploaded even after failure.
  Persistent monitor/report publishing has been removed. Snyk account access,
  actual scan results and whether this repository has applicable IaC still
  require validation by the approved service owner.
- Python 3.12 CI tests the constrained release dependencies with collection and
  deployment packages and runs `pip check`. Container and
  desktop jobs depend on this check as well as the existing matrix.

## Remaining release requirements

These repairs do not resolve every architecture or deployment finding:

- Use a controlled internal reporting/export pilot with network actions disabled
  at the trusted gateway and restricted egress. Loopback peer checks
  still cannot distinguish a local client from a same-host reverse proxy.
- Bind live commit to device candidate state using device-supported locking,
  dirty-candidate handling and drift checks. Until lab verification is complete,
  block web commit; process-local locks and signed artifacts are insufficient.
- Provide private HTTPS/SSO/MFA ingress, individual authorization and audit
  identity, destination allowlists, deliberate CSRF protection and rate limits.
- Govern browser/WebView profiles, retained workspaces, downloads, swap, crash
  dumps, proxy buffering and backups under customer-data retention rules.
  Bounded application memory uploads do not control those external stores.
- Establish concurrency and memory limits using representative load tests;
  long-running work still occupies request threads.
- Verify the actual container and Windows installer. Rust locking, signed
  bundles, clean standard-user installation/launch/import/export/uninstall,
  WebView2 handling and sidecar startup deadline/cleanup remain release work.

No customer configuration or real-device deployment is
needed to validate these CI repairs. Company controls and lab-device checks
remain prerequisites for production approval.
