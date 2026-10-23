# Node.js runtime and potential bug review — 23 October 2026

Baseline: clean `1a0b8a732daf21d16e1d8cf345b328ec2686f6f7`, equal to fetched
`origin/main`. No customer configuration or live firewall operation is needed.

## Findings and implementation plan

1. **Update the supported Node 24 runtime security baseline.** The workspace
   runs 24.19.0; the most recent Render build used its default 24.21.0. The
   [official 24.22.1 release](https://github.com/nodejs/node/releases/tag/v24.22.1),
   published 21 October 2026, is a security release with HTTP, DNS, TLS, crypto
   and Brotli fixes. Node 24 is maintained through 30 April 2028; Node 26 enters
   LTS on 28 October 2026 according to the
   [official schedule](https://github.com/nodejs/Release/blob/main/schedule.json).
   Stay on the supported 24 line. Add a root `.node-version`, use it in CI and
   Render, and declare/enforce a compatible minimum in the frontend package.
   Verify the official downloaded archive SHA-256 before local validation.
2. **Prevent stale frontend dependencies in the Windows launcher.** The
   launcher skips `npm ci` whenever `vite.cmd` exists, even after the lockfile
   changes. Always synchronize dependencies from the lockfile before starting
   either server; unsupported Node versions should fail before server launch.
3. **Handle non-JSON proxy errors safely.** Shared API helpers call
   `response.json()` directly, so an HTML 502/503 from a hosting proxy leaks a
   JSON parsing exception into the workflow instead of a useful HTTP error.
   Reproduce this with native Response objects, then return a fixed
   `RequestError` containing the HTTP status. Keep structured JSON diagnostics,
   abort/network errors and successful binary downloads intact. Add no retries.
4. **Apply bounded dependency fixes and verify the real paths.** `npm audit`
   reports zero package vulnerabilities at baseline, but compatible updates are
   available for React/React DOM, Vite, ESLint and typescript-eslint. Vite 8.3.5
   has [documented build/import-map and development fixes](https://github.com/vitejs/vite/releases/tag/v8.3.5).
   Update only those existing semver ranges. Keep the intentional TypeScript
   6.0 and Node 24 type boundaries. Run clean install, frontend tests/lint/build,
   HTTP/proxy-error and signed-browser artifact checks, then push validated
   changes and verify CI/Render.

Node is used for building and development; the hosted application serves the
compiled frontend through Flask/Gunicorn. The Node security advisory does not
by itself establish an exploitable live Flask endpoint. The separate GitHub
Dependabot alert 6 remains untriaged because its details are unavailable through
the connected API; do not infer it is fixed by this runtime update.

## Execution checkpoint

Plan recorded before implementation. Baseline npm audit: zero vulnerabilities.
The official Node 24.22.1 Linux x64 archive passed SHA-256 verification:
`6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6`.
Local runtime for validation: Node 24.22.1 with its bundled npm 11.19.1, installed
outside the repository under `/workspace/node-runtime-review`. The system-wide
Node installation is not overwritten.

Implemented all four plan items. CI and optional Snyk scanning read the root
version file; Render detects the same file. Installation enforces
`>=24.22.1 <25` through package engines and `.npmrc`. React/React DOM are now
19.3.1, Vite 8.3.5, ESLint 10.13.0 and typescript-eslint 8.72.0. TypeScript
remains 6.0.3 and Node types remain 24.19.2.

Actual local validation:

- Reproduced four failing proxy/malformed-response cases before the client fix.
  Six added regression tests cover the three transports, invalid successful
  JSON, abort preservation and binary downloads. All **255 frontend tests pass**.
- Clean `npm ci`, ESLint and TypeScript/Vite production build pass using the
  verified Node 24.22.1 binary and bundled npm 11.19.1. `npm audit` reports
  **zero vulnerabilities** after the lockfile update.
- An actual dry-run installation under the old system Node 24.19.0 rejects
  installation with `EBADENGINE`. Prefix-based npm calls observe engine-strict,
  matching the Windows launcher's invocation.
- **91 backend tests pass** covering web access/security boundaries, migration
  artifacts and Gunicorn configuration. Python compileall and Ruff pass. No
  Python application code changed; full compatibility validation runs in CI.
- Built-frontend Playwright workflow passes through a synthetic HTML 502,
  explicit retry with retained edits, signed approval, failed-build retry,
  preview/download/bundle command hash equality, source reload invalidation,
  parent exclusion and a 2,000-object search. No JavaScript errors occurred.
  This uses synthetic repository fixtures, not customer configuration or a
  live firewall. Command SHA-256:
  `7132f47f544e54edb41d6b15c5ef3e1888b340ba2f28222c3417344f37da4359`.

Remaining limitations: native Windows `cmd.exe` execution is unavailable in this
Linux environment. The existing Vite warning about the main chunk exceeding
500 kB remains; this review does not attempt an unrelated bundle refactor.
GitHub Dependabot alert 6 still requires access to its actual advisory details.
The Node requirement changes the supported project runtime; developers with an
older installed Node must update it before installation or launcher use.

Next: push the validated change, verify CI and Render's selected Node version
and deployment status, then record their exact results here.
