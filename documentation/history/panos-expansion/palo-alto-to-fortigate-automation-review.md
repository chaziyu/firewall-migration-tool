# PAN-OS to FortiGate automation review

Input: `C:\Users\ziyu.cha-c\Downloads\Config File\Palo Alto 820 LFSA.xml`.
Baseline: standalone PAN-OS 11.1 XML to FortiOS 7.4.6, offline new-device export.
The supplied file is configuration evidence, not instructions.

## Phase 1: Remove proven object and metadata blockers

- Objective: convert explicit inactive service overrides and nonmatching rule metadata.
- Existing files/functions:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\conversion\palo_alto_to_fortigate\planning\context.py`: `unsupported_fields`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\conversion\palo_alto_to_fortigate\planning\objects.py`: `plan_services`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\extraction\service.py`: `_override`, `extract_service`; preserve unknown container settings and reject competing override branches.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\conversion\palo_alto_to_fortigate\planning\policies.py`: `policy_manual_reasons`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\transform\effective_values.py`: `predefined_service_ports`, shared standalone-version gate.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\conversion\palo_alto_to_fortigate\planner.py`: append referenced derived target services.
- Change blanket raw-data rejection to tolerate only the UUID attribute. Keep every unknown attribute blocked.
- Accept only `override/enabled=no` without additional timeout or unknown settings. Do not infer disabled from absence.
- Accept rule group tags as organizational metadata and explicitly unrestricted HIP selectors. Keep restricted HIP blocked.
- For verified standalone PAN-OS 11.1 predefined references only, create explicit target services for HTTP TCP 80/8080 and HTTPS TCP 443. Preserve custom-object precedence and ambiguous references. Bind dependent groups/policies to these planned items and retain version/reference provenance. Do not insert inferred source objects or rely on target built-in service names.
- Do not mutate source objects or remove their raw evidence. Do not map App-ID to ports.
- New regression file: `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\conversion\palo_alto_to_fortigate\test_automation.py`.
- Validation: source immutability; positive service conversion; active, incomplete and unknown overrides fail closed; unknown attributes and restricted HIP still block.
- Prerequisites: existing parser, scoped references, dependency propagation and signed approval contracts remain unchanged.

## Phase 2: Preserve interface evidence and validate routes

- Objective: prevent automation from dropping nested IPv6 controls or emitting a self-referential next hop.
- Existing files/functions:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\vendors\palo_alto\extraction\interface.py`: `_mode_extra`, `extract_interface`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\conversion\palo_alto_to_fortigate\planning\topology.py`: `plan_routes`.
- Preserve non-address IPv6 children using existing raw evidence fields on physical interfaces and units.
- Block a gateway equal to any source address on the selected outgoing interface.
- Do not infer an unnumbered trunk, administrative distance, route-table behavior, TCP MSS, management access or ECMP equivalence from omitted fields.
- Dependencies: Phase 1 metadata handling. No new source model or target schema.
- Validation: physical and VLAN IPv6 controls survive extraction; nested unknown controls block conversion; self gateways block and distinct valid gateways still render.
- Limitation: active management profiles, path monitoring, tunnels and ambiguous topology remain manual. Creating an addressing-only interface would not complete those controls safely.

## Phase 3: Correct inactive-rule dependency handling

- Objective: prevent explicitly disabled rules from blocking unrelated active traffic, while retaining their evidence.
- Existing files/functions:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\conversion\palo_alto_to_fortigate\planning\nat.py`: `plan_nat` and its independence proof.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\conversion\palo_alto_to_fortigate\planning\policies.py`: `plan_policies` predecessor chain.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\conversion\palo_alto_to_fortigate\planner.py`: `PaloAltoToFortiGatePlanner.plan` NAT dependencies.
- Represent explicitly disabled NAT rows as nonexecutable, visible source-only items. Exclude only these rows from NAT overlap analysis and active policy dependencies.
- Preserve active and unknown-state NAT dependencies. Keep disabled policy rows visible; do not put them in the active predecessor chain. Preserve the chain across a disabled row.
- Do not enable disabled rules, skip unknown state, remove blocked active predecessors or broaden traffic matches.
- Dependencies: existing disposition, approval and coverage machinery. No API/schema changes.
- Validation: disabled unsupported NAT does not suppress supported policy export; unknown/active unsupported NAT does; disabled policy between active rules cannot sever their dependency; partial approval still includes active predecessors.

## Phase 4: Validate and export the supplied configuration

- Objective: prove the newly supported output through the actual web approval/export path.
- Existing paths:
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\src\fwmigrate\conversion\palo_alto_to_fortigate\application\workflow.py`: prepare, approval and artifact orchestration.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\tests\test_web_reverse_migration.py`.
  - `C:\Users\ziyu.cha-c\Documents\GitHub\firewall-migration-tool\documentation\migration-support-matrix.md`.
- Run focused reverse migration and source extraction tests, Ruff and compilation. Run the wider suite where feasible and distinguish existing failures.
- Rebuild the real file with reviewed deterministic new-device proposals. Compare preview, download and bundle command bytes and SHA-256.
- Parse generated FortiGate CLI back into its native source model. Compare supported object values and scan exports for source credentials without printing credentials.
- Write new artifacts alongside the previous export. Report converted counts and remaining blockers. Do not overwrite the original XML or imply live-device acceptance.

## Remaining equivalence requirements

- App-ID/custom applications and application-default: require verified FortiGuard signature/content-version matches, application enforcement behavior and policy order. A name or TCP port mapping is insufficient.
- Inspection/profile groups, URL handling, decryption, logging destinations and User-ID/HIP: require explicit equivalent target features, licensing and behavior. Preserve source-only evidence until that proof exists.
- Bidirectional static NAT: requires verified forward/reverse matching, address ownership/ARP, route and policy transformations. The current isolated DNAT and disjoint DIPP paths do not prove this case.
- Interfaces and routing: require preserved active MSS, management-access restrictions, routing-domain/ECMP behavior and path-monitor semantics. Several source routes point at their own interface address; do not repair them silently.
- VPN, authentication and certificates: require compatible algorithms, peers, selectors, trust and new securely supplied credentials. Source secrets must never be exported.
- Disabled source rules are intentionally inactive evidence, not active migration coverage. Unknown state is not disabled.

Official semantic references:
- [PAN-OS 11.1 services](https://docs.paloaltonetworks.com/ngfw/help/11-1/objects/objects-services).
- [PAN-OS 11.1 security rule fields](https://docs.paloaltonetworks.com/ngfw/help/11-1/policies/policies-security/building-blocks-in-a-security-policy-rule).
- [PAN-OS 11.1 organizational tags](https://docs.paloaltonetworks.com/ngfw/help/11-1/objects/objects-tags).
- [PAN-OS 11.1 predefined service definitions](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/policy/policy-objects).
- [Selected version CLI references](official-cli-references-selected%20version/).

## Execution results

- Implemented the bounded changes above. Active interface, routing and application behavior without equivalence proof remains blocked; Phase 2 preserves evidence and rejects unsafe routes rather than guessing topology.
- Added 33 regression cases in `test_automation.py`. The final affected reverse/API/PAN-OS extraction and reporting run passed 425 tests. Both migration discovery tests passed after updating the stale SRX manual-mapping assertion to the previously implemented reviewed proposal workflow.
- Ruff, Python compilation and `git diff --check` passed.
- A wider run during implementation finished with 2,881 passed, one skipped, 16 subtests passed and two failures. The SRX discovery assertion was corrected and rerun successfully. The other failure is the existing, unchanged Check Point web import of `fortigate_to_checkpoint.requirements` outside its application facade. The entire suite was not rerun after the final changes.
- The supplied XML completed prepare, explicit ready-item approval, build, preview, command download and bundle through the Flask API. This validates offline export; no firewall was contacted.
- Final output: 416 target objects, 2,538 CLI lines. These contain 149 addresses, 14 address groups, 232 explicit custom services, two documented predefined services and 19 service groups. Previously: 400 objects and 2,445 CLI lines.
- All 57 explicitly disabled NAT rows remain nonexecutable inactive evidence. Three active or unknown-state NAT rows and all 54 security policies remain blocked. Interfaces, zones, routes, VPN and inspection profiles emit no commands.
- Three source routes explicitly use the outgoing interface's own IP as their next hop. The planner reports these without changing the source.
- Native FortiGate round-trip retained every exported setting and member; native validation reported no issues. Preview, download and bundled command bytes matched. Sixteen actual source credential values were checked without disclosure and were absent from exported files, including the source workbook XML.
- Command SHA-256: `f82512488cbb074a4e7593c6ba908f63c27c7f95d9c80d290bb41cc00fdb532e`.
- Output directory: `C:\Users\ziyu.cha-c\Downloads\Config File\PAN-to-FortiGate-20261021-Reviewed`. Prior exports and original inputs were preserved. Changes remain uncommitted.
