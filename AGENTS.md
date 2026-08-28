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

    Source configuration file
                |
                v
          Source Parser
                |
                v

             IRConfig

                |

                v

      Normalization / Validation

                |

                v

          Target Generator

             /     \

            v       v

    Native Config   Terraform

                    |

                    v

            Deployment Engine

                    |

                    v

              Target Device

Primary architectural layers:

- `src/fwmigrate/parsers/`

  Source-vendor configuration parsing.

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

All source parsers must produce valid IR models.

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

when the behavior belongs in a parser, generator, or deployer.

Vendor-specific implementation belongs inside the corresponding plugin layer.

---

## Authoritative Data Model Documentation

Before modifying any parser, IR model, Excel exporter, generator, optimizer, validator, or migration/deployment logic, review the following documentation.

### Vendor-Neutral Migration IR

The authoritative specification for portable cross-vendor firewall semantics is:

* `documentation/IR_DATA_STRUCTURE.md`

The executable Python IR implementation is located under:

* `src/fwmigrate/ir/`

`IR_DATA_STRUCTURE.md` defines the intended canonical representation for concepts including:

* metadata and provenance

* scopes, VDOMs, virtual systems, and similar configuration contexts

* system settings

* interfaces and network topology

* address objects and groups

* services and service groups

* applications

* security policies

* NAT

* routing

* VPN

* schedules

* security profiles

* identity and AAA

* certificates and PKI

* high availability

* SD-WAN

* QoS

* network services

* management-plane configuration

* logging and telemetry

* vendor extensions

* unsupported/residual configuration references

The canonical IR represents firewall intent rather than vendor CLI, XML, JSON, or Terraform syntax.

Source parsers must normalize portable firewall semantics into this IR.

Target generators must consume this IR rather than source-vendor-specific parser models.

Do not introduce direct source-to-target converters.

---

### Complete Source Extraction Model

The authoritative specification for accounting for the complete source firewall configuration is:

* `documentation/EXTRACTION_DATA_MODEL.md`

This document defines how configuration discovered from uploaded configuration files

must be classified and recorded.

Every migration-relevant source configuration element must be assigned one of the documented extraction states, including:

* `NORMALIZED`

* `PARTIALLY_NORMALIZED`

* `EXTRACT_ONLY`

* `VENDOR_EXTENSION`

* `UNSUPPORTED`

* `IGNORED_BY_POLICY`

* `PARSE_ERROR`

Relevant source configuration must never disappear silently.

The extraction result is broader than the canonical migration IR.

Conceptually:

```

Source Configuration

        |

        v

  ExtractionResult

        |

   +----+--------------------+

   |                         |

   v                         v

Canonical IR          Extraction Accounting

                       |

                       +-- Extract-only data

                       +-- Vendor extensions

                       +-- Unsupported items

                       +-- Residual/raw sections

                       +-- Parsing warnings/errors

                       +-- Extraction coverage

```

The canonical IR is used for:

* target configuration conversion;

* Terraform generation;

* migration;

* semantic validation.

The complete extraction result is used for:

* source inventory;

* Excel export;

* extraction coverage;

* troubleshooting;

* unsupported-feature reporting;

* migration review and audit.

---

## Data Model Source-of-Truth Rules

Use the following hierarchy when working on data-model-related code:

1. `documentation/IR_DATA_STRUCTURE.md`

   defines the intended vendor-neutral semantics.

2. `documentation/EXTRACTION_DATA_MODEL.md`

   defines complete source-configuration accounting and extraction behavior.

3. `src/fwmigrate/ir/`

   contains the executable Pydantic implementation.

4. Vendor parser models under `src/fwmigrate/parsers/`

   represent vendor-specific syntax before normalization.

If documentation and implementation disagree:

* do not silently choose one;

* determine whether the implementation or specification is outdated;

* update the appropriate source;

* update tests;

* keep documentation and executable models synchronized.

Do not consider documentation alone proof that a feature is implemented.

Verify the executable models, parser/generator implementation, and tests.

---

## Parser Development Requirement

Before modifying a source parser:

1. Read `documentation/EXTRACTION_DATA_MODEL.md`.

2. Read the relevant portions of `documentation/IR_DATA_STRUCTURE.md`.

3. Inspect the corresponding executable IR models.

4. Identify which source configuration sections are:

   * normalized;

   * partially normalized;

   * extract-only;

   * vendor-specific;

   * unsupported.

5. Add or update extraction coverage tests.

6. Ensure no migration-relevant source configuration is silently discarded.

The parser quality target is:

```

zero silent loss

```

This does not mean every vendor feature must be automatically migratable.

It means every migration-relevant source feature must be either:

```

correctly normalized

    OR

explicitly accounted for and reported.

```

---

## Excel Extraction Requirement

Excel extraction must follow:

* `documentation/EXTRACTION_DATA_MODEL.md` for extraction/accounting behavior;

* `documentation/IR_DATA_STRUCTURE.md` for normalized IR fields.

Do not create independent vendor-to-Excel parsing logic.

Preferred architecture:

```

Config File

          |

          v

         Parser

          |

          v

  ExtractionResult

          |

   +------+------+

   |             |

   v             v

Canonical IR  Extraction metadata

   |             |

   +------+------+

          |

          v

    Excel Exporter

```

The Excel exporter must not reinterpret raw vendor syntax.

Where possible, normalized worksheets should be generated from canonical IR.

Extraction-only, unsupported, residual, coverage, and vendor-specific information should come from `ExtractionResult`.

Excel generation must occur before migration-only optimization or pruning if the workbook is intended to represent the original source configuration.

Sensitive information such as passwords, private keys, PSKs, and credential material must not be exported in plaintext.

---

## IR Schema Change Checklist

Any change to the canonical IR must consider all of the following:

\* [ ] Update executable IR/Pydantic models.

\* [ ] Update `documentation/IR_DATA_STRUCTURE.md`.

\* [ ] Review all affected source parsers.

\

\* [ ] Review normalization and validation.

\* [ ] Review target generators.

\* [ ] Review Terraform generators/deployers.

\* [ ] Review Excel/report exporters.

\* [ ] Update semantic tests.

\* [ ] Update fixtures where required.

\* [ ] Preserve backward compatibility where practical.

\* [ ] Do not silently change the meaning of an existing field.

Any change to source extraction/accounting must also:

\* [ ] Update `documentation/EXTRACTION_DATA_MODEL.md`.

\* [ ] Update section/coverage classification.

\* [ ] Update residual/unsupported handling.

\* [ ] Update Excel extraction coverage tests.

---

## FortiGate Parser Work

For current FortiGate parser development, both documents are mandatory references:

* `documentation/IR_DATA_STRUCTURE.md`

* `documentation/EXTRACTION_DATA_MODEL.md`

FortiGate parser work must distinguish:

```

FortiGate syntax

     |

     v

FortiGate parsed model

     |

     +-------> Extraction accounting

     |

     v

Canonical migration IR

```

Do not force every FortiGate setting into the canonical IR.

Use:

* canonical IR for portable firewall intent;

* extract-only structures for useful non-portable settings;

* vendor extensions for FortiGate-specific functionality;

* unsupported/residual records for recognized configuration that cannot yet be modeled.

A FortiGate parser change is not complete merely because parsing succeeds.

It must demonstrate that relevant source configuration is either normalized or explicitly accounted for.

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

Never use `/0`, `/32`, `any`, or another valid network as a fallback for
invalid source IP/netmask syntax. Preserve sanitized source evidence and
require manual review.

Do not map vendor administrative distance into generic route metric. Preserve
distinct routing semantics and source-only route settings.



## IR Rules

The detailed canonical IR schema is defined in:

- `documentation/IR_DATA_STRUCTURE.md`

The complete extraction/accounting model is defined in:

- `documentation/EXTRACTION_DATA_MODEL.md`

Do not treat the abbreviated examples in this file as the complete schema.
When implementing or changing data structures, the two documentation files
above are the authoritative design references, and `src/fwmigrate/ir/`
contains the executable implementation.

### Canonical IR purpose

Canonical IR represents portable firewall intent rather than vendor CLI, XML,
JSON, API payloads, or Terraform syntax.

Serialized canonical IR must carry `IRConfig.schema_version`.
Backward-compatible additive serialized changes require a minor increment;
breaking serialized changes require a major increment. Never infer IR
compatibility from the application version or source-vendor version.

Portable concepts include, but are not limited to:

- metadata and provenance;
- scopes such as VDOMs, VSYS, device groups, domains, and logical systems;
- system settings that have meaningful cross-vendor representation;
- interfaces, subinterfaces, zones, VLANs, VRFs, virtual routers, and tunnels;
- addresses, address groups, services, service groups, applications, schedules,
  tags, dynamic/external lists, and Internet-service concepts;
- security, authentication, decryption, PBF, DoS, QoS, and related policies;
- SNAT, DNAT, PAT, static NAT, twice NAT, central NAT, NAT64, and NAT46;
- static and dynamic routing, policy routing, route policy, and redistribution;
- IPsec/IKE, remote-access, and SSL-VPN intent;
- security profiles and profile groups;
- identity and AAA;
- certificates and PKI metadata;
- high availability and clustering;
- SD-WAN;
- QoS and traffic shaping;
- network services;
- management-plane settings;
- logging and telemetry.

Do not force a vendor-specific feature into canonical IR if doing so would
misrepresent its semantics.

### ExtractionResult purpose

The source parser must produce enough information to construct an
`ExtractionResult` as defined in `documentation/EXTRACTION_DATA_MODEL.md`.

Every migration-relevant source configuration element must be classified as
one of:

- `NORMALIZED`
- `PARTIALLY_NORMALIZED`
- `EXTRACT_ONLY`
- `VENDOR_EXTENSION`
- `UNSUPPORTED`
- `IGNORED_BY_POLICY`
- `PARSE_ERROR`

No migration-relevant configuration may disappear silently.

### Vendor-specific and unsupported data

Use vendor extensions or residual/unsupported records when a source feature
cannot be represented safely in canonical IR.

Preserve enough source provenance to identify where the original configuration
came from, including source IDs, names, scope, paths, or raw section references
where appropriate.

Do not fabricate values to make an incomplete mapping appear successful.

### Reference integrity

IR object references must be validated before generation.

Examples include:

- policy -> address/address-group references;
- policy -> service/service-group references;
- policy -> zone/interface references;
- NAT -> object/interface/pool references;
- VPN Phase 2 -> Phase 1/tunnel references;
- route -> interface/VRF references;
- profile/group membership references.

Unresolved references must be reported explicitly and must not silently become
`any`, a default zone, or another permissive value.

Prefer explicit typed models over unstructured dictionaries for migration-
relevant semantics.

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
- new behavior has semantic tests;
- parser changes account for all migration-relevant source configuration;
- extraction coverage is updated where parser behavior changes;
- unclassified migration-relevant configuration is zero for covered fixtures;
- unsupported, partially normalized, extract-only, and vendor-specific items are explicit;
- unresolved references are reported rather than silently widened;
- no security policy is silently broadened;
- no parser or API client fabricates topology, policy, NAT, VPN, or object data;
- secrets are not exposed in logs, reports, Excel, API responses, or fixtures;
- `documentation/IR_DATA_STRUCTURE.md` is updated when canonical IR semantics change;
- `documentation/EXTRACTION_DATA_MODEL.md` is updated when extraction/accounting behavior changes;
- executable Pydantic models and documentation remain synchronized;
- Excel extraction remains based on canonical IR plus `ExtractionResult`, not separate vendor-to-Excel parsers;
- generated Terraform validates where applicable;
- live deployment changes preserve plan/review/approval safeguards.

For parser work, "done" means **zero silent loss**, not necessarily 100% automatic
migration support. A source feature may remain unsupported, but it must be
identified, preserved/reported as required, and visible to the operator.
