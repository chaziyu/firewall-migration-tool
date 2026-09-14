# Safety Model

## Scope

Firewall migration can change traffic enforcement. The project therefore treats incomplete semantic conversion as a safety problem, not a formatting problem.

## Normative rules

The terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used normatively in this document.

### Zero silent loss

Migration-relevant source configuration MUST be either represented or explicitly source-accounted. Present source data MUST NOT disappear merely because the canonical IR cannot represent it.

### Fail closed

Missing, malformed, ambiguous, or unresolved semantics MUST NOT be converted into broader behavior. Examples include inventing:

- `any` for a missing selector;
- `allow` for a missing action;
- `/0` or `/32` for an invalid network;
- an enabled state that was not proven by source evidence;
- a zone, interface, route, or NAT behavior from naming assumptions.

### Preserve evidence

Unsupported and vendor-specific behavior SHOULD retain sanitized provenance sufficient for review. Withholding unsafe target output is valid behavior; withholding without audit evidence is not.

### Dependency taint

A policy, NAT rule, group, route, or other object that depends on unsafe or unresolved semantics MUST inherit the review/safety boundary when the target cannot reproduce the dependency exactly.

### Secret protection

Passwords, usable PSKs, private keys, tokens, API keys, password hashes, and equivalent credentials MUST NOT be exposed in ordinary reports, source inventories, test fixtures, logs, or documentation examples.

### Optimization does not repair semantics

Optimization MUST NOT convert an unsafe or incomplete source rule into a broader deployable rule. Extraction/accounting happens before optional optimizer pruning.

### Normalization is mandatory and separate

Normalization MUST run for every migration before optional optimization. It
MUST be target-independent, deterministic, provenance-preserving, and
normally idempotent. It may perform only proven semantic canonicalization or
rewrites; unresolved intent MUST remain preserved and reported for review.

Optimization MUST remain optional and MUST NOT repair required semantics,
perform target conversion, or make an unsafe migration appear safe. Target
specific transformation belongs in generators.

### Target capability boundary

A canonical object MAY be useful for analysis while still being unsafe for a particular target. Target generators MUST enforce their own capability checks and withhold semantics they cannot reproduce safely.

## Historical safety plans

Earlier PAN-OS and Check Point phase documents introduced several of these rules. Those implementation narratives are archived; this document and the executable code/tests now carry the current cross-vendor contract.

## Verification

Safety-sensitive parser changes require semantic assertions covering canonical IR and extraction/accounting behavior. Generator changes require target semantic and withholding assertions. Shared IR changes require the affected vendor suites plus the full test suite.
