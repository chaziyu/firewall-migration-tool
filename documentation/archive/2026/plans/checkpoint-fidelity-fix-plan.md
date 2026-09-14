# Check Point Policy and NAT Fidelity Fix Plan

## Scope

This change addresses parser/extraction gaps identified during the R81 review for:

- Access Control package/layer relationships;
- inline-layer parent/child relationships;
- manual versus automatic NAT identification;
- automatic NAT object settings;
- identity/no-translation NAT ordering semantics;
- NAT package, install-target, proxy-ARP and object relationship evidence.

It does not flatten Check Point-specific semantics into portable IR when doing so
would change enforcement behavior.

## Safety basis

Check Point Ordered Layers are not equivalent to one flat firewall rule list.
An Accept result in an earlier Ordered Layer continues evaluation in the next
Ordered Layer. Inline-layer child rules are also constrained by their parent
rule. Therefore flattening these rules into ordinary portable `IRPolicy` rows
can broaden access.

Check Point NAT also has behavior that requires source ordering context:

- Manual NAT is first-match among Manual rules.
- Automatic NAT can apply a source and destination automatic rule together.
- Automatic Network/Address Range NAT creates an identity/no-translation rule
  for intranet traffic before its translation rule.

The parser therefore preserves these structures as explicit source evidence and
blocks unsafe automatic generation when an omitted identity rule would affect
later NAT behavior.

Official behavior references:

- Check Point R81 Security Management Administration Guide, "Configuring the NAT Policy".
- Check Point R81 Security Management Administration Guide, "Working with Automatic NAT Rules".
- Check Point Security Management Administration Guide, "Ordered Layers and Inline Layers".

## Implementation

### 1. Policy hierarchy

`src/fwmigrate/parsers/checkpoint/fidelity.py` annotates existing policy package
and access-layer records with:

- ordered-layer position;
- package UID/name relationship;
- inline layer parent layer UID/name;
- parent rule UID/number;
- child layer rule UIDs;
- relevant global-assignment relationships.

The existing source inventory rows are enriched instead of adding duplicate
policy records.

### 2. Automatic NAT object settings

Existing Host/Network/Address Range inventory rows with `nat-settings` receive a
structured `checkpoint-automatic-nat` view containing:

- automatic NAT enablement evidence;
- hide/static method;
- translated IPv4/IPv6 address evidence;
- hide-behind mode;
- install targets;
- proxy-ARP evidence;
- original raw `nat-settings`.

### 3. NAT rule origin and relationships

Existing NAT rule inventory and canonical NAT rows are correlated with:

- `checkpoint-nat-origin`: `manual`, `automatic`, or `unknown`;
- `checkpoint-enforcement-mode`;
- Check Point rule UID;
- domain/package context;
- native rule sequence;
- `install-on` targets;
- proxy-ARP evidence;
- automatic-NAT owning object references where authoritative evidence exists.

Object NAT configuration alone is not treated as proof that an arbitrary rule
is auto-generated.

### 4. Identity/no-translation NAT

Rules whose translated source, destination and service are all `Original` are
classified as `checkpoint-nat-semantic = identity` and
`checkpoint-ordering-barrier = true`.

They remain source-accounted rather than being converted into a fake translation
rule. Canonical NAT rules after such a barrier record the preceding identity
rule references and require manual review. The extraction result is marked not
safe for automatic generation because dropping the identity rule can cause a
later translation to affect traffic that Check Point intentionally excludes.

## Intentionally not flattened

These remain partial/source-preserved until the portable IR has an enforcement
model capable of representing them without semantic loss:

- multiple Check Point Ordered Layers as one effective Access policy;
- Inline Layer parent-condition plus child-rule evaluation;
- effective MDS global/local policy evaluation order;
- complex Time recurrence/multiple windows;
- service INSPECT/session behavior that has no portable equivalent;
- VSX target-scope semantics beyond preserved interface/VS identity.

This is intentional safety behavior, not silent parser loss.
