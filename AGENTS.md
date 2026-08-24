# AGENTS.md

## Project Overview

Firewall Migration Tool is a Python and Terraform platform for migrating
enterprise firewall configurations between multiple vendors.

Supported vendor families include:

- Fortinet FortiGate / FortiOS
- Palo Alto Networks PAN-OS / Panorama
- Cisco ASA / Firepower
- Check Point R80/R81
- Juniper SRX / JunOS

The core architectural principle is an M × N migration model using a
Vendor-Neutral Intermediate Representation (IR).

Source vendor configuration must be normalized into IR before target-specific
configuration is generated.

Do not implement direct source-to-target converters.

---

## Architecture

The intended data flow is:

    Source configuration or live API
                |
                v
        Source Parser/API Client
                |
                v
             IRConfig
                |
                v
      Normalization / Validation
                |
                v
          Target Generator
            /         \
           v           v
    Native Config   Terraform
                       |
                       v
                Deployment Engine
                       |
                       v
                 Target Device

Primary architectural layers:

- `src/fwmigrate/parsers/`
  Source-vendor parsing and live API ingestion.

- `src/fwmigrate/ir/`
  Vendor-neutral canonical data models.

- `src/fwmigrate/generators/`
  Target-vendor native configuration and Terraform generation.

- `src/fwmigrate/core/`
  Plugin registration and shared core behavior.

- `src/fwmigrate/engine/`
  Terraform execution and migration runtime.

- `src/fwmigrate/web.py`
  Web/API orchestration.

- `src/fwmigrate/main.py`
  CLI entry point.

- `tests/`
  Unit, integration, parser, generator, IR, and multi-vendor tests.

See `documentation/` for detailed project and IR documentation.

---

## Core Architectural Rules

### 1. Preserve the M × N architecture

Source parsers must not contain target-vendor generation logic.

Target generators must not depend on source-vendor parser structures.

The contract between source and target layers is the vendor-neutral IR.

Preferred:

    Vendor source -> IR -> Vendor target

Do not introduce:

    FortiGate -> PANOS converter
    FortiGate -> Cisco converter
    PANOS -> Juniper converter

unless there is an explicitly documented exceptional reason.

---

### 2. IR is the canonical contract

All source parsers and live API clients must produce valid IR models.

All target generators should consume IR rather than source-vendor-specific
objects.

When changing an IR model:

1. Check all source parsers.
2. Check all target generators.
3. Check serializers/reports.
4. Update tests.
5. Update IR documentation when semantics change.

Do not silently change the meaning of an existing IR field.

---

### 3. Use the plugin registry

Prefer vendor discovery through `PluginRegistry`.

Do not add large vendor-specific `if/elif` chains to web or CLI orchestration
when the behavior belongs in a parser, generator, API client, or deployer.

Vendor-specific implementation belongs inside the corresponding plugin layer.

---

## Firewall Migration Safety Invariants

Firewall migration correctness is security-sensitive.

The following rules are mandatory.

### Never silently broaden access

A conversion must never silently transform a restrictive rule into a broader
rule.

Examples of dangerous transformations include:

- specific source -> `any`
- specific destination -> `any`
- specific service -> `any`
- deny -> allow
- disabled rule -> enabled rule
- scoped zone -> unrestricted zone
- NAT restriction -> unrestricted translation

If an object/reference cannot be translated safely:

1. preserve the restriction where possible;
2. emit a warning/error;
3. disable or quarantine the affected rule when necessary;
4. require manual review.

Do not silently substitute `any`.

---

### Never silently discard security semantics

Unsupported features must be reported.

Examples include:

- security profiles / UTM
- application control
- user identity
- dynamic address groups
- Internet service databases
- unusual NAT types
- VPN parameters
- routing constructs
- schedules
- vendor-specific policy behavior

Use explicit warnings or compatibility results.

"Generated successfully" must not imply semantic equivalence when features
were omitted or approximated.

---

### Do not fabricate live-device data

Live API clients must return configuration actually retrieved from the target
device.

Do not use placeholder addresses, zones, policies, or interfaces to make an
unimplemented API client appear successful.

If extraction is not implemented, fail explicitly or return a documented
unsupported/not-implemented result.

---

## Source Parser Rules

A source parser is responsible for translating vendor-specific configuration
into IR.

It should:

1. parse the source configuration;
2. preserve source identifiers where useful;
3. normalize values into IR;
4. report malformed/unsupported constructs;
5. resolve or report object references;
6. avoid target-vendor assumptions.

Parsing failures must be visible.

Do not convert malformed input into an apparently successful empty
configuration.

---

## Live API Ingestion Rules

Live API clients should follow a common lifecycle:

    connect
       |
       v
    authenticate
       |
       v
    validate connection
       |
       v
    discover/retrieve configuration
       |
       v
    normalize to IR
       |
       v
    validate IR

API clients must:

- use reasonable timeouts;
- handle pagination where required;
- handle API errors explicitly;
- avoid logging credentials or API tokens;
- cleanly distinguish authentication failure from parsing failure;
- validate retrieved data before reporting success.

Unit tests must not require access to real firewall devices.

Use mocked API responses or fixtures for automated tests.

---

## IR Rules

IR objects should represent firewall intent rather than vendor syntax.

Examples:

- address objects
- address groups
- services
- service groups
- zones
- interfaces
- security policies
- NAT rules
- routes
- VPNs
- schedules
- security profiles

Vendor-specific syntax should remain in parser/generator layers whenever
possible.

IR object references must be validated before generation.

Prefer explicit models over unstructured dictionaries.

---

## Target Generator Rules

A target generator converts IR into target-vendor artifacts.

Generators should:

- consume IR only;
- produce deterministic output;
- validate target capability limitations;
- report unsupported or approximated mappings;
- preserve policy ordering when semantically relevant;
- produce stable object names;
- avoid silently weakening policy restrictions.

Native generation and Terraform generation should remain logically separate
output modes where possible.

---

## Terraform and Live Deployment Safety

Terraform execution can modify production security infrastructure.

Treat deployment operations as destructive/high-impact operations.

The normal lifecycle is:

    generate
       |
       v
    terraform init
       |
       v
    terraform validate
       |
       v
    terraform plan
       |
       v
    human review / approval
       |
       v
    terraform apply
       |
       v
    post-deployment validation

Do not bypass the plan/review stage.

Do not automatically apply Terraform from unit tests.

Do not connect to or modify real firewalls during ordinary automated tests.

Do not hard-code credentials, tokens, passwords, API keys, or device secrets.

Do not print secrets into:

- logs
- exceptions
- Terraform output
- reports
- API responses
- test fixtures

Sensitive Terraform variables must remain marked sensitive where applicable.

---

## Vendor-Neutral Deployment

Deployment orchestration should eventually be target-vendor-neutral.

Prefer:

    deployer = registry.get_deployer(target_vendor)

over target-specific orchestration such as:

    if target_vendor == "palo_alto":
        ...
    elif target_vendor == "fortigate":
        ...

Vendor-specific credentials, validation, diagnostics, and deployment behavior
belong in the target deployer/plugin implementation.

---

## Setup

Python requirement:

    Python 3.10+

Install the package for development:

    pip install -e ".[dev]"

Optional vendor integrations can be installed as needed:

    pip install -e ".[dev,cisco,checkpoint,juniper,reports]"

---

## Running Tests

Run the complete test suite:

    pytest tests/ -v

For a focused change, run the relevant test module first, then the full suite.

Examples:

    pytest tests/test_multi_vendor_matrix.py -v
    pytest tests/ -v

Any change to:

- IR
- parsers
- generators
- normalization
- deployment behavior

must include or update relevant tests.

Do not declare a migration feature complete based only on non-empty generated
artifacts. Where practical, test semantic values.

---

## Testing Philosophy

Prefer semantic assertions.

Weak:

    assert artifacts

Better:

    assert generated_policy.action == expected_action
    assert generated_policy.sources == expected_sources
    assert generated_policy.destinations == expected_destinations

For parser tests, verify:

    source fixture -> expected IR

For generator tests, verify:

    IR fixture -> expected target semantics

Where practical, use round-trip validation:

    source
      -> source parser
      -> IR
      -> target generator
      -> target parser
      -> IR
      -> semantic comparison

---

## Adding a New Vendor

A new vendor should normally provide:

1. source parser;
2. parser registration;
3. live API client, if supported;
4. target generator;
5. Terraform generator/deployer, if supported;
6. fixtures;
7. parser tests;
8. generator tests;
9. compatibility matrix tests;
10. documentation.

Adding vendor N must not require implementing converters from every existing
vendor.

The purpose of IR is to keep growth approximately M + N instead of M × N
source-target converter implementations.

---

## Code Change Guidelines

Before changing code:

1. identify the architectural layer responsible for the behavior;
2. inspect nearby tests;
3. inspect the relevant IR models;
4. avoid duplicating vendor-neutral logic inside vendor plugins.

When fixing a bug:

1. add or identify a reproducing test;
2. make the smallest architecture-consistent fix;
3. run targeted tests;
4. run the full test suite when practical.

Avoid unrelated refactoring during a targeted bug fix.

---

## Documentation

Keep detailed design information under `documentation/`.

Update documentation when changing:

- IR schemas;
- supported vendor features;
- unsupported features;
- migration semantics;
- public CLI behavior;
- live API support;
- Terraform deployment behavior.

Do not claim a vendor capability is supported merely because a class or stub
exists.

Documentation should reflect functional implementation and test coverage.

---

## Security

Treat uploaded firewall configuration as sensitive data.

Configuration files may contain:

- internal IP addresses;
- network topology;
- VPN information;
- usernames;
- API endpoints;
- security policy;
- potentially embedded credentials.

Do not unnecessarily log raw configuration.

Never commit real customer configurations or credentials as test fixtures.

Use sanitized synthetic fixtures.

---

## Definition of Done

A change is complete when:

- architecture boundaries remain intact;
- relevant tests pass;
- new behavior has tests;
- unsupported mappings are explicit;
- no security policy is silently broadened;
- secrets are not exposed;
- documentation is updated when behavior changes;
- generated Terraform validates where applicable.