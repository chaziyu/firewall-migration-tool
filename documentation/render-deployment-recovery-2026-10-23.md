# Render deployment recovery — 23 October 2026

Service: `firewall-migration-tool` (`srv-dap2ha60tbcc7385tbr0`), in the user-confirmed CHA ZI YU workspace, Singapore. Source branch: `main`.

The builds for `e5da3708` and `fb9852a1` succeeded, but their replacement instances failed during Gunicorn startup:

```text
ImportError: cannot import name 'object_description_issue' from
'fwmigrate.conversion.fortigate_to_palo_alto.target.name_validation'
```

The helper exists in the committed source. The same startup command also succeeds in a fresh Python 3.14.7 environment with the constrained production dependencies; Render uses Python 3.14.3. This evidence does not establish a Python compatibility defect. The subsequent unchanged-commit deployment succeeded after clearing Render's build cache, implicating stale cached artifacts. The exact cached file or bytecode responsible was not inspected.

## Recovery

- Kept the previous live release serving while diagnosing the failed replacements.
- Triggered a clear-cache deployment of the same application commit, `fb9852a17adfa13207af05cb5c1a781b4835a1a2`.
- Recovery deploy: `dep-dbdbrfd9fdbs73aj04q0`; status **live** at **09:53:59 Asia/Kuala_Lumpur** on 23 October 2026.
- Gunicorn started and listened on `0.0.0.0:10000`; Render's `HEAD /` and `GET /` probes returned HTTP 200.
- No service commands, environment variables, instance counts, plans, application code or firewall settings were changed.

## Verification

- Local Gunicorn configuration/startup regressions: **2 passed**.
- Fresh constrained Python 3.14.7 environment: dependency compatibility check passed, description-helper import passed, and the actual Render Gunicorn command passed its configuration check.
- Fresh Gunicorn HTTP smoke checks returned 200 for `/`, `/api/vendors`, and `/api/migration/pairs` locally.
- Render reported the recovery deployment as live. Its runtime logs show successful root-page probes and no new `ImportError`, traceback, startup error or nonzero-exit messages in the checked interval.
- The public URL could not be fetched directly through the available web-fetch tool, and the cloud runtime's outbound policy does not list that hostname. Production HTTP evidence comes from Render's recorded probes; no full production browser/API workflow is claimed.

## If this symptom returns

First compare the failed deploy's commit, first startup traceback and committed source. A successful frontend/dependency build does not prove the Python application can import. Reproduce the configured Gunicorn launch in a clean environment. If the committed helper exists and the clean launch succeeds, use **Clear build cache & deploy** on the intended service, monitor the resulting deploy ID until it is live, and verify HTTP readiness plus recent runtime logs. Avoid unrelated dependency downgrades or port changes when the first failure is an import error.

References: [Render deploy lifecycle and clearing build cache](https://render.com/docs/deploys), [Render health checks](https://render.com/docs/health-checks). This documentation-only commit uses `[skip render]` so recording the incident does not replace the verified live application.
