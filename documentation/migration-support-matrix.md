# Migration Support Matrix

Authoritative capability, scope, destination-comparison, and usage reference for all nine directional migration workflows.

> **Important**: All workflows produce **partial, directional offline exports** (`deployment_available=False` across all pairs). A successful export is not a complete replacement firewall configuration and does not perform live device push, commit, publish, or policy installation.

---

## Supported Migration Pairs

| Source Vendor | Target Vendor | Pair ID | Target Baseline | Format | Primary Emitted Files | Destination Comparison |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **FortiGate** | **Palo Alto PAN-OS** | `fortigate_to_palo_alto` | PAN-OS 11.1 | `.set` | `palo_alto_config.set`, `migration_report.json` | Optional native PAN-OS XML (`CREATE` / `CONFIGURE` / `REUSE` / `BLOCK`) |
| **PAN-OS** | **FortiGate** | `palo_alto_to_fortigate` | FortiOS 7.4.6 (NAT / profile-based NGFW) | `.conf` (`cli`) | `fortigate_config.conf`, `migration_report.json` | Optional native FortiGate config (`REUSE`, `CREATE`, unreferenced-port `CONFIGURE`) |
| **PAN-OS** | **Juniper SRX** | `palo_alto_to_juniper_srx` | Junos 25.2R1 standalone (root) | `.set` | `juniper_config.set`, `migration_report.json` | Optional family-complete Junos snapshot for exact reuse |
| **PAN-OS** | **Cisco ASA** | `palo_alto_to_cisco_asa` | ASA 9.20 routed single-context | `.cfg` | `asa_config.cfg`, `migration_report.json` | Optional native ASA snapshot for exact object reuse; traffic stays blocked |
| **PAN-OS** | **Check Point** | `palo_alto_to_checkpoint` | R81 Management API 1.8.1 + Gaia | `.json` + `.sh` + `.clish` | `checkpoint_management_operations.json`, `checkpoint_bindings.json`, `checkpoint_management.sh`, `gaia_config.clish`, `migration_decisions.json`, `migration_report.json` | Optional native Management JSON for address/group UID reuse; existing policy & Gaia blocked |
| **PAN-OS** | **Cisco FTD** | `palo_alto_to_cisco_ftd` | FMC REST API 7.7.0 (FMC-managed) | `.json` + `.sh` + `.txt` | `cisco_fmc_operations.json`, `cisco_fmc_bindings.json`, `cisco_fmc_curl.sh`, `ftd_application_instructions.txt`, `migration_decisions.json`, `migration_report.json` | Optional FMC REST export bundle (`domain_id` match) for exact object/zone reuse; existing policy blocked |
| **FortiGate** | **Cisco ASA** | `fortigate_to_cisco_asa` | ASA 9.20 routed single-context | `.cfg` | `asa_config.cfg`, `migration_report.json`, `migration_decisions.json`, `target_mapping.yaml`, `source_inventory.xlsx` | Optional native ASA snapshot for object/interface reuse; existing NAT blocks traffic |
| **FortiGate** | **Juniper SRX** | `fortigate_to_juniper_srx` | Junos 25.2R1 standalone | `.set` | `juniper_config.set`, `migration_report.json`, `migration_decisions.json`, `target_mapping.yaml` | Optional Junos snapshot for exact reuse & empty-policy verification |
| **FortiGate** | **Check Point** | `fortigate_to_checkpoint` | R81 Management API 1.8.1 + Gaia | `.json` + `.sh` + `.clish` | `checkpoint_management_operations.json`, `checkpoint_bindings.json`, `checkpoint_management.sh`, `gaia_config.clish`, `migration_decisions.json`, `migration_report.json` | Optional Management JSON for object UID reuse and cleanup-only Drop rulebase insertion |

---

## Workflow & Security Contract

### Unified Web Workflow

All nine pairs follow the four-stage workspace flow: **Source → Target setup → Review conversion → Download**.

1. **Source**: Upload a vendor-native configuration (or sanitized collection snapshot).
2. **Target setup**: Select source scope (e.g., FortiGate VDOM or PAN-OS VSYS), target mode/baseline options, interface/zone/router mappings, and optional destination snapshot evidence. Saving draft edits does not grant approval.
3. **Review conversion**: Inspect coverage, dependency chains, target conflicts, and exact candidate operations/commands, then explicitly sign **Approve**.
4. **Download**: Export deterministic commands/specs, `migration_report.json`, and the ZIP bundle.

Workspace state lives in memory for the active server session; editing source, scope, options, target evidence, or selections immediately revokes prior approvals and artifacts.

### Dispositions & Source Accounting

- **Render dispositions**:
  - `CREATE`: Emit creation commands/requests for verified missing target items.
  - `CONFIGURE`: Emit explicitly approved additive changes on an existing compatible target resource.
  - `REUSE`: Satisfy via matching existing target evidence without emitting creation commands.
  - `BLOCK`: Emit nothing; dependency blockers propagate deterministically before rendering.
- **Source coverage states**:
  - `RENDERED`: Selected source evidence contributes to exported output.
  - `REUSED`: Selected target evidence satisfies the item without creation output.
  - `DEPENDENCY_BLOCKED`: Planned item blocked by unresolved prerequisites or an atomic group member.
  - `MANUAL`: Unrepresented source feature or item with an individual semantic blocker.
  - `PENDING` / `NOT_APPROVED`: Eligible item not selected for the current artifact.
- Reports retain `export_is_complete_migration: false`. Coverage accounting tracks source records rather than traffic equivalence.

### Approval, Signing & Snapshot Rules

- **Signed approval binding**: Web exports require a current HMAC-signed approval envelope (24-hour TTL) bound to source SHA-256, destination SHA-256, target options/scope, selected items, and full dependency closure.
- **Single immutable artifact**: Preview, single-file download, and ZIP bundle consume the exact same `RenderedMigration` (matching file list, count, and SHA-256).
- **CLI material boundary**: `fwmigrate migrate` runs without web design approval and outputs unapproved review material.
- **Destination snapshots**: Optional destination uploads are sanitized by the native reporter and require explicit operator completeness metadata (`target_evidence` with `context`, `version`, `mode`, and `complete_families`). Missing tables never prove absence, and snapshot comparison never establishes hardware fit, capacity, licensing, cabling, or live device acceptance.
- **Secret redaction**: Passwords, hashes, PSKs, private keys, API keys, tokens, shared secrets, and sensitive SNMP communities are redacted across all inputs, snapshots, previews, Excel workbooks, reports, and exports.

---

## Pair Coverage & Usage

### FortiGate to Palo Alto PAN-OS

- **Target baseline**: PAN-OS 11.1 (`palo_alto_config.set`, `migration_report.json`).
- **Scope & Objects**:
  - Maps explicit FortiGate VDOMs to target PAN-OS VSYS, virtual routers, interfaces, and zones without guessing missing ownership.
  - Separates explicit source state from FortiOS 7.2.13 documented defaults (omitted policy action `deny`, VIP `static-nat`, Phase 2 PFS `enable` and lifetime `43200s`), recording firmware version and reference provenance.
  - Supports deterministic bounded object naming, `ssl-ssh-profile` `no-inspection` handling, device-scoped management profiles (with permitted management CIDRs), site-to-site `tunnel.N` interface proposals, scoped user/group mappings, and unnumbered static routes over planned tunnels.
  - Supports non-secret IPsec crypto profiles (AES-128/256-CBC with SHA-256/384/512) while keeping gateway authentication, peer identity, Phase 2 selectors, and secrets manual.
- **NAT & Routing**:
  - Expands supported SNAT and VIP service unions into bounded single-service rules; supports isolated single-policy combined overload-pool SNAT + static VIP, single TCP/UDP VIP port translation, and flat VIP-group destinations when member settings are valid and disjointness is proven.
  - Custom all-protocol services, unverified port-preservation controls, decryption profiles, DHCP/route-priority/VRF differences, IPv6/mixed-family policy matches, and Central-SNAT/NGFW-mode VDOM controls remain manual.
- **Target Comparison**:
  - Offline mode proposes `ethernet1/N` ports without PAN-OS XML.
  - Destination-aware mode compares against native PAN-OS XML (`REUSE`, `CONFIGURE`, `CREATE`, `BLOCK`) and optionally scopes physical port proposals to PA-820 hardware (`ethernet1/1`–`ethernet1/12`).
- **CLI**:

  ```bash
  fwmigrate migrate \
    --source-vendor fortigate --target-vendor palo_alto \
    --input fortigate.conf --output out --format set \
    [--zone-map mapping.yaml] [--target-config panos.xml] \
    [--target-device SERIAL] [--target-intent intent.yaml] \
    [--automation-mode VERIFIED_AND_DERIVED]
  ```

---

### Palo Alto PAN-OS to FortiGate

- **Target baseline**: FortiOS 7.4.6, NAT operating mode, profile-based NGFW (`fortigate_config.conf`, `migration_report.json`).
- **Scope & Objects**:
  - Converts one standalone VSYS; preserves shared object identity while keeping Panorama/template inheritance and ambiguous precedence manual.
  - Derives documented standalone PAN-OS 11.1 rule defaults (rule type, logging, source-user, absent schedule) and predefined HTTP (`TCP 80/8080`) / HTTPS (`TCP 443`) services with explicit provenance.
  - Converts IPv4 subnet/range/FQDN addresses, static address groups, TCP/UDP port intervals, static service groups, inactive `<override><no/></override>` service timeouts, one-time and uniform recurring schedules (with confirmed timezone match), primary IPv4 L3 ethernet/VLAN interfaces, L3 zones (explicit intrazone deny), and ordered L3/L4 `application any` security policies (with active-predecessor dependency chains).
- **NAT & Routing**:
  - Target must use (or declare) Central NAT mode; generated commands do not alter device mode.
  - Dynamic-IP-and-port SNAT supports sole interface IP or literal pool IP when direct IPv4 source prefixes are pairwise disjoint. Disabled NAT rules remain visible as non-executable `inactive_nat` evidence.
  - Single isolated static address-only DNAT (`/32` public object, literal mapped host, one ingress, connected post-NAT zone, explicit VIP proxy-ARP choice, empty target traffic tables) generates a VIP and policy with `match-vip-only enable`.
  - Static IPv4 routes target VRF 0; self-referential next-hop gateways are blocked. App-ID, `application-default`, inspection profiles, port-translated/dynamic/bidirectional NAT, combined SNAT+DNAT, and non-disjoint NAT remain manual.
- **Target Comparison**:
  - Optional native FortiGate config validates firmware/operating/NGFW/NAT/VDOM compatibility (`REUSE` on exact match, `CREATE` on explicitly empty table, `CONFIGURE` only on verified unreferenced `0.0.0.0 0.0.0.0` ports).
- **CLI & Mapping Shape**:

  ```bash
  fwmigrate migrate \
    --source-vendor palo_alto --target-vendor fortigate \
    --input panos.xml --output out --format cli \
    [--zone-map fortigate-mapping.yaml] [--target-config fortigate.conf]
  ```

  ```yaml
  source_scope: vsys:vsys1:device:fw1
  vdom: root
  interfaces:
    ethernet1/1: port1
    ethernet1/2: port2
  zones:
    trust: inside
    untrust: outside
  routers: {}
  profile:
    fortios_version: 7.4.6
    operating_mode: nat
    ngfw_mode: profile-based
    nat_mode: central
    vdom_mode: single
    ports: [port1, port2]
  timezone: ""
  policy_settings: {}
  ```

---

### Palo Alto PAN-OS to Juniper SRX

- **Target baseline**: Junos 25.2R1 standalone, confirmed root context (`juniper_config.set`, `migration_report.json`).
- **Scope & Objects**:
  - Converts one standalone VSYS with proposed physical ports, logical units, VLAN tags, and security zones.
  - Ordered L3/L4 policies bind zone/interface dependencies and every active predecessor in the same zone pair (disabled rules do not sever the chain).
  - Only verified standalone PAN-OS 11.1 omitted-schedule behavior is treated as unrestricted; all named schedules (including `always`) stay blocked.
  - Static routes emit planned Junos preference, metric, and next hop.
- **NAT & Manual**: App-ID, named schedules, policy/NAT/routing ambiguity, inspection profiles, and self-referential gateways remain blocked.
- **Target Comparison**: Optional family-complete Junos 25.2R1 snapshot enables exact `REUSE` (including exact static-route preference); populated or ambiguous policy placement remains blocked.
- **CLI & Application**:

  ```bash
  fwmigrate migrate \
    --source-vendor palo_alto --target-vendor juniper_srx \
    --input panos.xml --output out --format set \
    [--zone-map mapping.yaml] [--target-config junos.set]
  ```

  Load the reviewed `.set` file, run `commit check`, and commit explicitly on the device.

---

### Palo Alto PAN-OS to Cisco ASA

- **Target baseline**: ASA 9.20 routed single-context (`asa_config.cfg`, `migration_report.json`).
- **Scope & Objects**:
  - Converts one standalone VSYS with explicit target ports, `nameif` values, security levels (`0–100`), and complete connected/static routing evidence.
  - Supports explicit TCP/UDP rules without inspection/logging, bounded ACE expansion, explicit unlogged `intrazone-default` / `interzone-default` Drop handling, and whole-destination egress proof.
  - Interfaces, security controls, routes, ACL rules, final denies, bindings, and activation form one atomic approval unit.
- **NAT & Manual**: Empty-target, routing-completeness, capacity, and return-routing attestations require explicit confirmation; active/unknown NAT, named schedules, App-ID, FQDN/IPv6, and topology ambiguity remain blocked.
- **Target Comparison**: Optional native ASA snapshot supports exact address/port object reuse; existing-target traffic placement stays blocked.
- **CLI & Application**:

  ```bash
  fwmigrate migrate \
    --source-vendor palo_alto --target-vendor cisco_asa \
    --input panos.xml --output out --format cfg \
    [--zone-map mapping.yaml] [--target-config asa.cfg]
  ```

  Review, apply, validate, and save manually on the ASA.

---

### Palo Alto PAN-OS to Check Point

- **Target baseline**: Check Point R81 Management API 1.8.1 + separate Gaia output (`checkpoint_management_operations.json`, `checkpoint_bindings.json`, `checkpoint_management.sh`, `gaia_config.clish`, `migration_decisions.json`, `migration_report.json`).
- **Scope & Objects**:
  - Converts one standalone VSYS into a fresh policy package, access layer, and explicit Drop cleanup anchor (with `install-on` targets and management domain reviewed in mapping).
  - Converts explicit IPv4 hosts, subnets, ranges (`add-host`, `add-network`, `add-address-range`), static address groups (`add-group`), and TCP/UDP services split into atomic port/range objects and groups (`add-service-tcp`, `add-service-udp`, `add-service-group`).
  - Unrestricted-zone L3/L4 policies (`from any`, `to any`, `application any`) with explicit allow/drop and unlogged defaults map to ordered access rules bound via response UIDs (`{$response_binding:...}`).
- **NAT & Manual**: Zone-constrained policies, active/unknown NAT, App-ID, named schedules, inspection/logging profiles, and Gaia interface/static-route commands remain blocked.
- **Target Comparison**: Optional native Management API 1.8.1 export supports exact address and address-group UID reuse (auto-rule NAT disabled); existing policy insertion and Gaia stay blocked.
- **CLI & Application**:

  ```bash
  fwmigrate migrate \
    --source-vendor palo_alto --target-vendor checkpoint \
    --input panos.xml --output out --format json \
    [--zone-map mapping.yaml] [--target-config cp_mgmt.json]
  ```

  Log in to Management separately, execute `bash checkpoint_management.sh /path/to/existing-session.json` (requires `mgmt_cli` and `jq`), then publish and install policy manually.

---

### Palo Alto PAN-OS to Cisco FTD

- **Target baseline**: Cisco FMC REST API 7.7.0, FMC-managed FTD (`cisco_fmc_operations.json`, `cisco_fmc_bindings.json`, `cisco_fmc_curl.sh`, `ftd_application_instructions.txt`, `migration_decisions.json`, `migration_report.json`).
- **Scope & Objects**:
  - Requires one standalone VSYS, explicit FMC manager hostname/IP, and valid `domain_id` UUID (never guessed).
  - New-target mode creates a fresh Access Control Policy container (`/policy/accesspolicies`) and default rule.
  - Converts IPv4 hosts/subnets/ranges (`/object/networks`, `/object/rangeobjects`), static address groups (`/object/networkgroups`), atomic TCP/UDP port objects (`/object/protocolportobjects`) and port groups (`/object/portobjectgroups`), security zones (`/object/securityzones`), and ordered L3/L4 universal access rules (`/policy/accesspolicies/{acp_id}/accessrules`) when `intrazone-default` and `interzone-default` are unlogged Drop.
- **NAT & Manual**: FDM and FTD device CLI modes fail closed. `application-default`, App-ID, active/unknown NAT, named schedules, logging/inspection profiles, device interface assignments, and static routes remain blocked. Blocked predecessors block dependent rules.
- **Target Comparison**: Optional native FMC REST export bundle (`fmc-rest-bundle`) with matching `domain_id` supports exact network, port, and security zone ID reuse; existing policy insertion stays blocked.
- **CLI & Application**:

  ```bash
  fwmigrate migrate \
    --source-vendor palo_alto --target-vendor cisco_ftd \
    --input panos.xml --output out --format json \
    [--zone-map mapping.yaml] [--target-config fmc_bundle.json]
  ```

  Execute manually with Python 3.11+:

  ```bash
  bash cisco_fmc_curl.sh [TOKEN_FILE]
  ```

  Without `TOKEN_FILE`, the script prompts privately (do not pass a token as an argument). It keeps TLS verification enabled, rejects redirects, binds response IDs, and stops on error without retrying. Reconcile partial changes before re-running, then assign interfaces/policies and deploy in FMC manually.

---

### FortiGate to Cisco ASA

- **Target baseline**: ASA 9.20 routed single-context, one FortiGate VDOM (`asa_config.cfg`, `migration_report.json`, `migration_decisions.json`, `target_mapping.yaml`, `source_inventory.xlsx`).
- **Scope & Objects**:
  - Converts IPv4 `ipmask` and `iprange` addresses, static address/service groups (`group-object`), explicit TCP/UDP destination-port services, physical Ethernet interfaces (`nameif`, security level, IPv4, up/down state), IPv4 static routes with mapped egress, recurring weekly time ranges (matching source/target timezone confirmation), ordered ingress extended ACLs, and per-interface default-deny ACLs.
  - ASAv VLAN subinterfaces require explicit platform/capacity confirmation, a mapped physical parent, unique tag, and explicit state; child approval includes its parent.
  - `access-group` bindings emit only when complete destination binding evidence confirms no existing binding on the interface.
- **NAT & Manual**:
  - Supports one constrained static source NAT case (`no-proxy-arp`): one active HTTPS policy between distinct IPv4 hosts, `destination any`, one ingress interface, one-to-one pool, explicit `fixedport` and `port-preserve`, disabled pool proxy ARP, confirmed routed return, and complete empty destination traffic evidence (forming one atomic approval group).
  - PAT, VIP/DNAT, destination interfaces other than `any`, central SNAT, inspection, and uncertain NAT ordering stay blocked.
- **Target Comparison**: Optional native ASA snapshot supports exact address and physical-interface reuse; existing target NAT or bindings block traffic export until independence is proven.
- **CLI & Application**:

  ```bash
  fwmigrate migrate \
    --source-vendor fortigate --target-vendor cisco_asa \
    --input fortigate.conf --output out --format cfg \
    [--zone-map mapping.yaml] [--target-config asa.cfg]
  ```

  Review hardware fit, routing adjacency, ARP, and licensing, then apply, validate, and save manually.

---

### FortiGate to Juniper SRX

- **Target baseline**: Junos 25.2R1 standalone (`juniper_config.set`, `migration_report.json`, `migration_decisions.json`, `target_mapping.yaml`).
- **Scope & Objects**:
  - Proposes `ge-0/0/N` ports, source-tag VLAN units, root placement, and zones for interfaces outside FortiGate zones.
  - Converts IPv4 objects/groups (verifying interface-bound address consumers; `FABRIC_DEVICE` stays manual), TCP/UDP, numeric IP protocols `1–254`, explicit ICMP type/code, unrestricted IP services (`application any`), and static routes (retaining distance as Junos preference).
  - Uses verified FortiOS 7.2.13 header defaults (retained with provenance) when firmware matches explicitly.
  - vSRX VLAN output requires explicit platform/capacity confirmation and a tagged-only `0.0.0.0 0.0.0.0` physical parent with no direct zone/policy/route membership.
- **NAT & Manual**:
  - Supports a constrained fixed-pool SNAT case (`port no-translation`): one source host, one active policy, builtin `all`/`ALL`, one translated IPv4 address, explicit fixed-port preservation, disabled proxy ARP, and confirmed routed return (atomic approval group).
  - Interface PAT, central SNAT, VIP/DNAT, FQDN runtime cache, host-inbound administrative services, and UTM/identity stay manual.
- **Target Comparison**: Optional Junos snapshot supports exact reuse and absence checks; new policy output requires family-complete empty policy evidence (local default `deny-all` permitted) with no NAT or routing-instance ambiguity.
- **CLI & Application**:

  ```bash
  fwmigrate migrate \
    --source-vendor fortigate --target-vendor juniper_srx \
    --input fortigate.conf --output out --format set \
    [--zone-map mapping.yaml] [--target-config junos.set]
  ```

  Load the reviewed `.set` file, run `commit check`, and commit explicitly on the device.

---

### FortiGate to Check Point

- **Target baseline**: Check Point R81 Management API 1.8.1 + separate Gaia Clish (`checkpoint_management_operations.json`, `checkpoint_bindings.json`, `checkpoint_management.sh`, `gaia_config.clish`, `migration_decisions.json`, `migration_report.json`).
- **Scope & Objects**:
  - Converts one selected FortiGate VDOM.
  - Management API: IPv4 hosts, networks, ranges (`add-host`, `add-network`, `add-address-range`), explicit IPv6 `ipprefix` hosts/networks (`add-host` / `add-network` with IPv6 fields; IPv6 policies/groups/NAT stay manual), explicit TCP/UDP custom services (`add-service-tcp`, `add-service-udp`), leaf-expanded static groups, and ordered IPv4 access rules when interfaces are `any`, schedule is `always`, and NAT/UTM are explicitly disabled.
  - New-target mode creates a fresh package (`add-package`), access layer, and Drop cleanup anchor; existing-target mode inserts above a confirmed Drop cleanup rule.
  - Gaia Clish: Explicit enabled IPv4/IPv6 static routes with destination and same-family gateway when blackhole is disabled and no device/VRF/distance/dynamic-gateway selector is present.
- **NAT & Manual**: Interface-bound rules, non-`always` schedules, NAT, central SNAT, inline layers, and UTM/identity stay blocked. Management and Gaia planes are independent; Management snapshots do not verify Gaia routes.
- **Target Comparison**: Optional native Management JSON snapshot supports exact object UID reuse (auto-NAT disabled) and cleanup-only Drop layer verification.
- **CLI & Application**:

  ```bash
  fwmigrate migrate \
    --source-vendor fortigate --target-vendor checkpoint \
    --input fortigate.conf --output out --format json \
    [--zone-map mapping.yaml] [--target-config cp_mgmt.json]
  ```

  Execute Management templates manually with an existing API session (`bash checkpoint_management.sh /path/to/existing-session.json` using `mgmt_cli` and `jq`), then publish, install policy, and save Gaia configuration separately.

---

## Official Vendor References

Pinned selected vendor references maintained in this repository:

- [FortiGate Selected CLI References](official-cli-references-selected%20version/FortiGate%20Selected%20CLI%20References.md) (FortiOS 7.4.6)
- [Palo Alto Selected CLI References](official-cli-references-selected%20version/Palo_Alto_Selected_CLI_References.md) (PAN-OS 11.1)
- [Cisco ASA Selected Configuration References](official-cli-references-selected%20version/Cisco_ASA_Selected_Configuration_References.md) (ASA 9.20)
- [Cisco FTD Selected Configuration References](official-cli-references-selected%20version/Cisco_FTD_Selected_Configuration_References.md) (FMC REST API 7.7.0)
- [Juniper Selected CLI References](official-cli-references-selected%20version/Juniper_Selected_CLI_References.md) (Junos 25.2R1)
- [Check Point R81 Selected CLI and Management API References](official-cli-references-selected%20version/Check_Point_R81_Selected_CLI_and_Management_API_References.md) (R81 Management API 1.8.1)

External vendor baselines referenced during implementation:

- [FortiOS 7.2.13 CLI Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/9b85aed5-fafc-11f0-8b43-d2943efe5b2f/FortiOS-7.2.13-CLI_Reference.pdf) and [FortiOS 7.4.6 CLI Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/cb8d6b09-b8b3-11ef-9411-ae1fcf29f169/FortiOS-7.4.6-CLI_Reference.pdf)
- [PAN-OS 11.1 CLI Hierarchy](https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-1-configure-cli-command-hierarchy) and [PAN-OS NAT Policy Rules](https://docs.paloaltonetworks.com/ngfw/networking/nat/nat-policy-rules)
- [Cisco ASA 9.20 Access Rules](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/access-rules.html) and [ASA 9.20 NAT Basics](https://www.cisco.com/c/en/us/td/docs/security/asa/asa920/configuration/firewall/asa-920-firewall-config/nat-basics.html)
- [Cisco FMC REST API Quick Start 7.7.0](https://www.cisco.com/c/en/us/td/docs/security/firepower/770/api/fmc/fmc-rest-api-quick-start-770.html)
- [Juniper Junos Security Policy Overview](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/concept/policy-overview.html) and [Custom Applications](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/application-edit-applications-srx.html)
- [Check Point Management API v1.8.1](https://sc1.checkpoint.com/documents/latest/APIs/index.html#web/add-address-range~v1.8.1) and [Gaia R81 IPv4 Static Routes](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_Gaia_AdminGuide/Topics-GAG/IPv4-Static-Routes-Gaia-Clish.htm)
