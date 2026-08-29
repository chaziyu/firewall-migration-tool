JUNIPER SRX SAFETY HARDENING IMPLEMENTATION PLAN

STATUS
Implementation correction pass required after commit f7579fb.
Architecture remains frozen.
No architectural redesign.
Scope is limited to closing remaining safety invariant gaps found during verification.
Do not broaden into unrelated parser refactoring.

PRIMARY OBJECTIVES

1. Eliminate every remaining path that can expose source secrets.
2. Eliminate every remaining target-generation fabrication.
3. Ensure NAT unknown or unresolved semantics can never become migration-ready.
4. Complete logical-system and tenant reference isolation, not only object-name isolation.
5. Complete deactivate/activate propagation across every extracted domain.
6. Close remaining ACCESS-DENIED and ICMP partial-normalization gaps.
7. Preserve current public parser API and existing M x N architecture.
8. Keep all existing 834 passing tests green while adding focused regression coverage.

GLOBAL IMPLEMENTATION RULES

Repository:
chaziyu/firewall-migration-tool

Base commit:
f7579fb

Architecture:
Frozen.

Do not redesign:
tokenizer -> context normalization -> handlers -> source model -> activation state -> resolver -> transformer -> ExtractionResult

Safety invariants:

No source secret may appear in:
ExtractionResult
SourceInventoryItem
SourceCommand
UnsupportedItem
JuniperSRXConfig
source_attributes
audit entries
logs
generated files

No target generator may invent:
IP addresses
prefix lengths
route next hops
zones
actions
services
address objects
security profiles
NAT translations
default profile names
universal matches

Unknown, unresolved, incomplete, scoped, disabled, or non-portable semantics must be:
PARTIALLY_NORMALIZED
EXTRACT_ONLY
UNSUPPORTED
or PARSE_ERROR

and must require manual review where they can affect migration behavior.

Never convert an unresolved or restrictive source construct into a broader portable construct.

PHASE 1
COMPLETE SECRET SANITIZATION FOR UNSUPPORTED COMMANDS

Files:
src/fwmigrate/parsers/juniper_srx/coverage.py
src/fwmigrate/parsers/juniper_srx/parser.py
src/fwmigrate/parsers/juniper_srx/extraction.py
tests/test_juniper_srx_coverage.py
tests/test_juniper_srx_vpn.py
new or existing secret-sanitization tests

Problem:

coverage.py sanitizes SourceCommand.key and SourceCommand.values, but UnsupportedItem.source_name is still built from original JunosCommand.tokens.

Current unsafe pattern:

source_name = " ".join(c.tokens[:4])

JunosCommand.tokens also remain unsanitized in config.unsupported_commands, making parse_raw() capable of exposing plaintext secret values.

Required implementation:

1. Add one canonical helper for sanitized command token access.

Example responsibility:

sanitize_tokens(tokens) -> sanitized token list

All serialized or persistent command representations must use sanitized tokens.

2. Update coverage.py.

Use safe_tokens for:
SourceCommand.key
SourceCommand.values
UnsupportedItem.source_name
any other serialized command-derived field

Do not use c.tokens directly when building ExtractionResult.

3. Update parser unsupported-command storage.

Do not append the original secret-bearing JunosCommand object directly to:

config.unsupported_commands

Store either:
a sanitized copy of JunosCommand
or
a dedicated safe source representation containing sanitized tokens only.

Preferred rule:

JunosCommand.tokens may contain raw values only during immediate parse execution.
Any command persisted beyond tokenizer/dispatch must contain sanitized tokens.

4. Ensure raw_sanitized remains the only raw-command representation that can escape the parser pipeline.

5. Add unsupported secret-bearing test cases.

Required examples:

set snmp community SuperSecretCommunity
set system root-authentication encrypted-password "$6$secret"
set system radius-server 10.0.0.1 secret RadiusSecret
set system tacplus-server 10.0.0.2 secret TacacsSecret
unknown-hierarchy password ExampleSecret

Assertions:

serialized = result.model_dump_json()

No original secret string exists in serialized.

parse_raw serialization also contains no original secret string.

UnsupportedItem.source_name contains [REDACTED] where appropriate.

raw_capture remains sanitized.

Phase 1 acceptance:

No plaintext secret can be recovered from ExtractionResult or parse_raw() for supported or unsupported commands.

PHASE 2
REMOVE STUB_UNSUPPORTED TARGET FABRICATION

Files:
src/fwmigrate/generators/juniper_srx/cli_generator.py
tests/test_juniper_srx_generator_safety.py

Problem:

CLI generator still contains an early STUB_UNSUPPORTED emission path before the withholding check.

Current unsafe behavior conceptually:

if addr.type == STUB_UNSUPPORTED and addr.value:
    emit addr.value
    continue

IRAddress.value can itself return:

198.19.255.254/32

Therefore the forbidden synthetic address remains reachable.

Required implementation:

1. Delete all STUB_UNSUPPORTED emission logic.

2. Handle STUB_UNSUPPORTED only through withholding.

Expected output:

# Address <name> withheld: unsupported source address semantics require manual review

3. Never access addr.value for STUB_UNSUPPORTED during emission.

4. Do not change the shared IR fallback in this Juniper remediation unless required by another architecture decision.
The Juniper generator must be safe regardless of how shared IR represents stub values.

Tests:

Create IRAddress with:

type = AddressType.STUB_UNSUPPORTED
stub_value = None

Assert:

198.19.255.254/32 not in output

No set security address-book command is generated for the stub.

A withholding comment is generated.

Repeat with stub_value explicitly populated.
Still withhold because STUB_UNSUPPORTED is not target-safe.

Phase 2 acceptance:

Juniper CLI generation cannot produce a synthetic stub address under any STUB_UNSUPPORTED input.

PHASE 3
NAT UNKNOWN MATCH AND UNRESOLVED REFERENCE HARDENING

Files:
src/fwmigrate/parsers/juniper_srx/model.py
src/fwmigrate/parsers/juniper_srx/handlers/nat.py
src/fwmigrate/parsers/juniper_srx/transformer.py
src/fwmigrate/parsers/juniper_srx/resolver.py
tests/test_juniper_srx_nat.py

Problem A:

Unknown NAT match conditions are currently inserted into source_addresses as fabricated strings.

Unsafe pattern:

rule.match.source_addresses.append("_".join(body_toks[1:]))

This converts unknown syntax into a fake address value.

Required model change:

Extend JuniperNATMatch with explicit preservation fields.

Example:

unknown_match_conditions: list[str]
source_attributes: dict[str, Any]

Do not overload:
source_addresses
destination_addresses
protocols
ports
applications

with unknown syntax.

Handler behavior:

Unknown NAT match:

preserve sanitized source syntax in unknown_match_conditions
set command status PARTIALLY_NORMALIZED
set requires_manual_review = True

Do not append anything to canonical match lists.

Transformer behavior:

If unknown_match_conditions is non-empty:

requires_manual_review = True
migration_status = PARTIALLY_NORMALIZED
add explicit review reason
preserve unknown conditions in source_attributes

Problem B:

Undefined NAT pools can currently produce apparently valid translation modes.

Required source NAT behavior:

If action type is pool and referenced source pool does not exist:

source_translation_mode may remain POOL for source fidelity
source_pool_references retains original pool name
translated_sources remains empty
requires_manual_review = True
migration_status = PARTIALLY_NORMALIZED
review reason:
Unresolved source NAT pool: <name>

Required destination NAT behavior:

If destination pool reference does not exist:

destination_pool_references retains original pool name
translated_destinations remains empty
requires_manual_review = True
migration_status = PARTIALLY_NORMALIZED
review reason:
Unresolved destination NAT pool: <name>

Problem C:

NAT action may be missing or unknown.

Required behavior:

Missing source/destination NAT translation action:
manual review
PARTIALLY_NORMALIZED
never infer interface NAT, pool NAT, or off

Unknown action:
preserve exact sanitized source action
manual review
PARTIALLY_NORMALIZED

Problem D:

Static NAT mapped-port and prefix-name semantics need explicit partial handling.

If exact IR mapping is incomplete:

preserve:
prefix-name
mapped-port
reverse behavior
source context

manual review remains mandatory.

Tests:

Undefined source NAT pool.
Undefined destination NAT pool.
Unknown restrictive match condition.
Unknown NAT action.
Source-port restriction.
Destination-port restriction.
Protocol restriction.
Interface context.
Routing-instance context.
Static NAT mapped-port.
Static NAT prefix-name.

Assertions:

All unsafe rules require manual review.
migration_status is PARTIALLY_NORMALIZED.
No unknown match text appears as a fake source or destination address.
No unresolved pool rule is safe_for_target_generation.

Phase 3 acceptance:

No NAT rule with unknown, unresolved, or unrepresented semantics can become migration-ready.

PHASE 4
COMPLETE CONTEXT-AWARE CANONICAL REFERENCE REWRITING

Files:
src/fwmigrate/parsers/juniper_srx/resolver.py
src/fwmigrate/parsers/juniper_srx/transformer.py
src/fwmigrate/parsers/juniper_srx/model.py if helper metadata is required
tests/test_juniper_srx_contexts.py
tests/test_juniper_srx_address_sets.py
tests/test_juniper_srx_policies.py
tests/test_juniper_srx_nat.py

Problem:

Non-root object definitions are prefixed, but not all references are rewritten consistently.

This can create broken IR such as:

IRAddress:
LS1__srv

IRAddressGroup:
LS1__servers

member:
srv

or:

IRZone:
LS1__trust

IRInterface.zone:
trust

or:

IRService:
LS1__web

IRPolicy.service:
web

Required design:

Create one shared context canonicalization helper.

Recommended API:

canonicalize_name(context_name, name)

Behavior:

root:
name

non-root:
<context>__<name>

For scoped book objects:

canonicalize_book_object(context_name, book_name, name)

Examples:

root global srv:
srv

root book DMZ srv:
DMZ__srv

LS1 global srv:
LS1__srv

LS1 book DMZ srv:
LS1__DMZ__srv

Do not duplicate naming logic across transformer methods.

Required reference rewriting:

1. Zones

Definition:
LS1__trust

References:
IRInterface.zone -> LS1__trust
IRPolicy.from_zone -> LS1__trust
IRPolicy.to_zone -> LS1__untrust
NAT from_zone/to_zone -> namespaced values

2. Addresses

Policy resolved source/destination references must use the same canonical name as emitted IRAddress or IRAddressGroup.

3. Address groups

Nested or direct members must be context-prefixed correctly.

Resolver.expand_address_set() must produce canonical members based on context.

Do not return unprefixed member names from non-root contexts.

4. Services

Application references in policies must become:

LS1__app_web

when application is defined within LS1.

5. Service groups

Members must be rewritten to the context-prefixed service or service-group canonical name.

6. Schedules

Policy schedule references must point to:

LS1__schedule_name

when the schedule belongs to LS1.

7. NAT

Address-name references must use namespaced canonical IR names for the context.

8. Routes

Already prefixed names are acceptable, but source object references must remain consistent.

9. VPN

If VPN names or referenced profiles are normalized into canonical IR in non-root contexts, apply consistent context namespacing or withhold if exact semantics cannot be represented.

10. Cross-context references

Never resolve LS1 objects from LS2.

Context resolvers must operate only inside their own JuniperContextConfig.

Tests:

Create LS1 and LS2 with identical names for:

zone trust
address srv
address-set servers
application web
application-set web_group
scheduler business_hours
policy P1
NAT rule r1

Verify:

LS1 references only LS1-prefixed objects.

LS2 references only LS2-prefixed objects.

No unprefixed dangling references remain.

Run IR reference validation if available.

Phase 4 acceptance:

Every canonical object definition and reference in non-root contexts uses the same deterministic namespace.

PHASE 5
COMPLETE ACTIVATION AND DEACTIVATION SEMANTICS

Files:
src/fwmigrate/parsers/juniper_srx/parser.py
src/fwmigrate/parsers/juniper_srx/model.py
src/fwmigrate/parsers/juniper_srx/transformer.py
tests/test_juniper_srx_activation.py
domain-specific tests where useful

Existing implementation already covers:

interfaces
interface units
addresses
address sets
applications
application sets
policies
global policies
schedulers
routes
NAT rules
IPsec VPN model

Remaining requirement:

Ensure disabled state affects transformed canonical semantics safely.

Domain rules:

Interfaces:
status = False

Addresses:
requires_manual_review = True
source_attributes["disabled"] = True
target withheld

Address groups:
requires_manual_review = True
source_attributes["disabled"] = True

Applications:
requires_manual_review = True
source_attributes["disabled"] = True

Application sets:
requires_manual_review = True
source_attributes["disabled"] = True

Policies:
disabled = True
target generators must not accidentally activate them

Schedulers:
source_attributes["disabled"] = True
any referencing policy must require manual review or preserve disabled schedule semantics safely

Routes:
enabled = False
requires_manual_review as appropriate

NAT:
disabled = True
ensure target generators do not emit active translation

VPN:
Current issue:
vpn.disabled is set in source model but ignored by _transform_vpn().

Required behavior:

If VPN is deactivated:
either do not create migration-ready IRVPNTunnel
or create IRVPNTunnel with explicit source disabled provenance and manual review if canonical IR has no disabled VPN field

Never emit it as active without warning.

IKE policy/gateway/proposal:

Activation evaluation currently focuses mainly on IPsec VPN objects.

Extend activation-state handling to:
IKE proposals
IKE policies
IKE gateways
IPsec proposals
IPsec policies

If a VPN depends on any deactivated component:
VPN must require manual review or remain extract-only.

Zones:

Add activation-state handling for:

security zones security-zone <zone>

If deactivated:
preserve the zone but mark source disabled state.
Any policy or interface depending on it requires review.

Tests:

deactivated application-set
deactivated scheduler referenced by policy
deactivated NAT rule
deactivated IPsec VPN
deactivated IKE gateway
deactivated IKE policy
deactivated IPsec policy
deactivated zone
reactivate after parent deactivation
parent deactivate then child activate behavior according to implemented JunosActivationState semantics

Phase 5 acceptance:

No deactivated source object can silently become an active target object.

PHASE 6
REMOVE REMAINING TARGET GENERATOR DEFAULT FABRICATION

Files:
src/fwmigrate/generators/juniper_srx/cli_generator.py
tests/test_juniper_srx_generator_safety.py

Problem:

UTM generation still uses:

pg.antivirus or "default"
pg.url_filtering or "default"

This invents valid target configuration.

Required behavior:

Do not emit default profile names unless they were explicitly represented in canonical IR as intended target semantics.

If profile group lacks required profile details:

withhold the affected UTM configuration
emit explicit review comment

Example:

# Security profile group <name> withheld: antivirus profile missing

Do not emit:

anti-virus http-profile default

unless "default" was explicitly present in the IR source intent.

Audit generator for other "or default" patterns.

Search within Juniper generator for:

or "default"
or 'default'
fallback addresses
fallback zones
fallback services
fallback actions
fallback next hops
fallback masks
hardcoded synthetic values

Remove or withhold each unsafe case.

Tests:

security profile group with missing antivirus
security profile group with missing URL filter
explicit profile named default must still be allowed when source/IR explicitly contains "default"

Phase 6 acceptance:

Juniper target generator emits only explicit portable IR values.

PHASE 7
STRUCTURAL ACCESS-DENIED DETECTION

Files:
src/fwmigrate/parsers/juniper_srx/extraction.py
src/fwmigrate/parsers/juniper_srx/tokenizer.py
tests/test_juniper_srx_tokenizer.py
tests/test_juniper_srx_coverage.py

Problem:

Current implementation detects any exact token equal to ACCESS-DENIED.

This can misclassify legitimate data such as:

set ... description "ACCESS-DENIED"

Required behavior:

Detection must be context-aware.

Do not mark ACCESS-DENIED when token is a user-data value belonging to known free-text fields such as:

description
comment
message

Detect ACCESS-DENIED when it appears in a position where Junos substitutes hidden configuration values.

Preferred implementation:

has_access_denied_token(tokens) should examine token path and value index, not simply any matching token.

At minimum:

if previous semantic key is description or another known free-text field:
do not treat value as hidden configuration

otherwise:
exact ACCESS-DENIED token may be classified as hidden content

Tests:

description "ACCESS-DENIED" -> normal description

pre-shared-key ACCESS-DENIED -> hidden/manual review

encrypted-password ACCESS-DENIED -> hidden/manual review

address value ACCESS-DENIED -> unsupported/manual review

Phase 7 acceptance:

ACCESS-DENIED detection identifies hidden configuration without false-positive matching legitimate descriptions.

PHASE 8
COMPLETE ICMP PARTIAL SEMANTICS

Files:
src/fwmigrate/parsers/juniper_srx/transformer.py
tests/test_juniper_srx_applications.py

Problem:

Unknown symbolic icmp-type is handled, but unknown symbolic icmp-code must receive the same treatment.

Required behavior:

If term.icmp_code is not None and resolve_icmp_code(term.icmp_code) returns None:

requires_manual_review = True
migration_status = PARTIALLY_NORMALIZED
preserve original source value in source_unmodeled_semantic_settings
add review reason

Never silently convert unknown ICMP code to None while treating service as fully normalized.

Tests:

known symbolic ICMP code -> numeric mapping and NORMALIZED

unknown symbolic ICMP code -> PARTIALLY_NORMALIZED + manual review + source preservation

Phase 8 acceptance:

Unknown ICMP type or code can never disappear silently.

PHASE 9
EXPAND GENERATOR SAFETY TEST MATRIX

Files:
tests/test_juniper_srx_generator_safety.py

Add explicit test cases for:

STUB_UNSUPPORTED without stub value
STUB_UNSUPPORTED with explicit stub value
missing route next hop
manual-review routing-instance route
manual-review NAT rule
unresolved NAT pool
disabled NAT rule
disabled VPN if represented
partial service
unknown ICMP value
missing policy dimensions
unresolved policy reference
any-ipv4
any-ipv6
security profile with missing child profile
non-root logical-system object

Address-family universal invariant:

any-ipv4 must never be silently emitted as dual-family any.

any-ipv6 must never be silently emitted as dual-family any.

If Junos target syntax directly preserves these values:
emit exact keyword.

If a target path cannot preserve family semantics:
withhold.

Phase 9 acceptance:

Every previously identified fabrication or broadening class has a direct regression test.

PHASE 10
ZERO-SILENT-LOSS AND SERIALIZATION AUDIT

Files:
tests/test_juniper_srx_coverage.py
tests/test_juniper_srx_vpn.py
possibly new tests/test_juniper_srx_security.py

Add generic helper:

assert_no_secret_leak(result, secret_values)

Implementation concept:

serialized = result.model_dump_json()

for secret in secret_values:
    assert secret not in serialized

Apply to:

supported IKE PSK
unsupported SNMP community
unsupported password hierarchy
radius secret
tacacs secret
encrypted password

Add command-accounting assertions for new malformed and partial scenarios.

Every input command must still have one status:

NORMALIZED
PARTIALLY_NORMALIZED
EXTRACT_ONLY
VENDOR_EXTENSION
UNSUPPORTED
IGNORED_BY_POLICY
PARSE_ERROR

No command can remain status None after build_extraction_result.

Phase 10 acceptance:

All added security fixtures satisfy both:
zero silent loss
zero plaintext secret retention

EXECUTION ORDER

Implement in this order:

1. Secret sanitization of unsupported commands
2. STUB_UNSUPPORTED withholding
3. NAT unknown/unresolved hardening
4. Context canonical reference rewriting
5. Activation/deactivation completion
6. Generator default removal
7. ACCESS-DENIED structural detection
8. ICMP code hardening
9. Generator safety matrix expansion
10. Full extraction serialization audit

Do not combine unrelated refactoring with these fixes.

VERIFICATION COMMANDS

After each phase:

python -m pytest tests -k juniper_srx -v

Focused security tests:

python -m pytest tests/test_juniper_srx_coverage.py -v
python -m pytest tests/test_juniper_srx_vpn.py -v
python -m pytest tests/test_juniper_srx_activation.py -v
python -m pytest tests/test_juniper_srx_nat.py -v
python -m pytest tests/test_juniper_srx_contexts.py -v
python -m pytest tests/test_juniper_srx_applications.py -v
python -m pytest tests/test_juniper_srx_generator_safety.py -v

Cross-generator safety:

python -m pytest tests/test_zone_generator_safety.py -v

Multi-vendor:

python -m pytest tests/test_multi_vendor_matrix.py -v

Full regression before commit:

python -m pytest tests -v

FINAL ACCEPTANCE CRITERIA

Do not mark remediation complete unless all conditions below are true.

1. No secret from any supported or unsupported Junos command appears anywhere in ExtractionResult or parse_raw serialization.

2. No STUB_UNSUPPORTED object can generate 198.19.255.254/32 or any other synthetic Junos address.

3. Unknown NAT match syntax is never inserted into canonical address fields.

4. Undefined NAT pools always force PARTIALLY_NORMALIZED and manual review.

5. NAT rules with unrepresented port, protocol, interface, routing-instance, static, or unknown semantics are not target-safe.

6. Logical-system and tenant object references use the exact same canonical namespace as their definitions.

7. No cross-context object resolution is possible.

8. Deactivated interfaces, policies, addresses, groups, applications, schedules, routes, NAT rules, VPNs, and dependent VPN components cannot silently migrate as active.

9. Juniper target generators contain no fabricated "default" profile fallback.

10. Legitimate description "ACCESS-DENIED" is not misclassified.

11. Unknown ICMP type and code both force partial/manual-review handling.

12. any-ipv4 and any-ipv6 are never broadened to dual-stack any.

13. assert_no_silent_loss passes for all Juniper fixtures.

14. Full repository regression passes.

15. git status is clean after commit.

RECOMMENDED COMMIT MESSAGE

fix(juniper_srx): close remaining extraction and generator safety gaps

FINAL STATUS AFTER SUCCESSFUL IMPLEMENTATION

ARCHITECTURE: FROZEN
IMPLEMENTATION: COMPLETE
ZERO SILENT LOSS: VERIFIED
SECRET SANITIZATION: VERIFIED
TARGET FABRICATION: ELIMINATED
CONTEXT ISOLATION: VERIFIED
FULL REGRESSION: PASSED