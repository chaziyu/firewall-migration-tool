# High-Level Migration Plan: `firewall-config-reader` (v2.4.5) → `firewall-migration-tool`

- **Source Reference:** `d:\Documents\GitHub\firewall-config-reader` (branch `feat/local-and-desktop-launcher`, v2.4.5 — FastAPI + HTML/CSS/JS + Desktop)
- **Target Project:** `d:\Documents\GitHub\firewall-migration-tool` (branch `feat/config-reader-layout-redesign` — Flask + React/Vite + Desktop)
- **Vendor Scope:** **FortiGate** and **Palo Alto** (including **Palo Alto TSF `.zip`** archives) only
- **Out of Scope (Parked for Later):** Live Collection, Plan Migration workflows, and the remaining 4 vendors (Cisco ASA, Cisco FTD, Juniper SRX, Check Point) — backend code remains intact and untouched

---

## 1. Objective

Bring all features and the unified workspace layout from the edited senior project (`firewall-config-reader` v2.4.5) into `firewall-migration-tool`, while:
1. Preserving `firewall-migration-tool`'s Flask + React/Vite + Desktop architecture and strict semantic pipeline (`Parser → VendorConfig → DerivedViews → Validation → Preview/Excel`).
2. Simplifying UI decoration and visual chrome so network/security engineers can scan and audit configurations quickly without visual clutter.
3. Focusing extraction and analysis parity exclusively on **FortiGate** and **Palo Alto** (plus Palo Alto **TSF**).

---

## 2. Current Baseline vs. Feature Gap Matrix

### Already Present in `firewall-migration-tool` (Needs Layout Alignment & Parity Verification)
- **Security & Health Core:**
  - Hardware & Firmware Lifecycle (EoL/EoS) checker (`source_reporting/lifecycle.py`, `LifecycleCard.tsx`, `/api/lifecycle`)
  - Public Management & VIP Exposure Check + local-only live TCP/TLS/SSH reachability probe (`source_reporting/exposure.py`, `/api/source/exposure-probe`)
  - Certificate Expiry Inspector (`source_reporting/certificates.py`)
  - Quick Security Audit, Cleanup & Hygiene, Posture (`vendors/{fortigate,palo_alto}/security_audit.py`, `SecurityAuditPanel.tsx`, `/api/source/audit`)
  - Standalone HTML / Print-to-PDF Audit Report export (`/api/source/audit-report`)
- **Where-Used Search:** Backend + `WhereUsedPanel.tsx` (`/api/source/where-used`) — currently a collapsible `<details>` bar rather than a global `Ctrl+K` modal.
- **Site-to-Site IPSec VPN Inspector:** `vendors/{fortigate,palo_alto}/vpn_inspector.py` + `VpnInspectorView.tsx`.
- **AI Config Assistant:** `web_support/chat_service.py` + `ConfigChatWidget.tsx` + `/api/chat`.
- **Desktop & Exports:** Auto-updater (`UpdateChecker.tsx`), Windows Desktop direct Downloads saving (`desktop_downloads.py`), vendor-native Excel (`fast`/`full`) and CSV exports.

### Missing from `firewall-migration-tool` (To Be Migrated)

| # | Feature in `firewall-config-reader` (v2.4.5) | Source Reference Module(s) | Target Scope & Summary |
| :--- | :--- | :--- | :--- |
| 1 | **Preventive Maintenance (PM) Lookup** | `backend/pm_checklist_service.py` | Automated backup-config PM checklist for FG & PA (firmware/EoS/FFR, GMT+8 & NTP, log managers, interfaces, routing, VPN, HA, management access, 90-day PAN-OS log filter) with status filtering and CSV/Excel export. |
| 2 | **End-to-End Packet Flow Simulator (`Trace Packet`)** | `backend/packet_trace_service.py` | Step-by-step packet trace for FG & PA: Ingress/RPF → DNAT/VIP → LPM Egress Route → Security Policy → Outbound SNAT/IP Pool. |
| 3 | **Policy Lookup / Policy Match Simulator** | `backend/policy_lookup_service.py`, `backend/routes/config_api.py` | 5-tuple traffic simulator for FG & PA with top-down first-match evaluation, shadowed-rule awareness, and implicit deny detection. |
| 4 | **Longest-Prefix-Match (LPM) Route Lookup** | `backend/route_lookup_service.py` | Destination IP lookup against FG static routes and PA Virtual Routers. |
| 5 | **Firewall-Aware Structural Config Diff** | `backend/config_diff_service.py` | Upload a second config snapshot to compare structural additions, removals, and modifications across Policies, NAT/VIPs, Static Routes, VPNs, and Interfaces. |
| 6 | **FortiGate SSL-VPN → Dial-up IPSec Assistant** | `backend/ssl_to_ipsec_service.py` | FortiGate-only offline readiness audit (certs, SAML, Web Mode), GUI/Wizard parameter reference, copyable draft IKEv2 CLI (Phase 1, Phase 2, cloned `ssl.root` policies), and FortiClient cutover checklist. |
| 7 | **Palo Alto TSF (`.zip`) Explorer** | `tsf/{extractor,indexer,search,file_preview}.py`, `backend/routes/tsf_api.py`, `templates/tsf.html`, `static/js/tsf.js` | Secure ZIP extraction (Zip Slip, symlink, and executable screening) with live progress polling, split-pane directory tree, filename search, background full-text content search, paginated line-numbered file viewer with jump-to-match, and raw file download. |
| 8 | **Global `Ctrl+K` Quick Search Modal** | `templates/workspace.html`, `static/js/workspace.js` | Topbar shortcut opening a modal wired to `/api/source/where-used` from any section. |
| 9 | **v2.4.4–v2.4.5 FG/PA Parser Refinements** | `parsers/fortigate/*`, `parsers/paloalto/*`, `backend/view_models/*` | Audit and close any remaining extraction gaps (e.g., FortiGate Log Settings & Threat Weight, Mgmt/Ports overview, admin/interface parser refinements, PAN-OS HA/device detail parity). |

---

## 3. Target Architecture & Responsibility Boundaries

All migrated features will follow `firewall-migration-tool`'s `AGENTS.md` architecture rules:

- **Keep Flask + React/Vite + `pywebview` Desktop:** Do not introduce FastAPI or Jinja2 templates into `firewall-migration-tool`.
- **Keep semantics in backend vendor modules (React = presentation only):**
  - Build PM Lookup, Policy Lookup, Route Lookup, Packet Trace, Config Diff, and SSL-to-IPSec on top of `VendorConfig` and `DerivedViews` (avoiding brittle raw-text regex parsing wherever typed models exist).
  - Never mutate `VendorConfig` after extraction, never invent defaults for missing fields, and preserve secret redaction across all new endpoints and exports.
- **Planned Backend Additions (`src/fwmigrate/`):**
  - `src/fwmigrate/tsf/` — `extractor.py`, `indexer.py`, `search.py`, `file_preview.py` (with session TTL cleanup, size limits, and archive security checks).
  - `src/fwmigrate/web_api/tsf.py` — `/api/tsf/upload`, `/api/tsf/progress/<job_id>`, `/api/tsf/status`, `/api/tsf/tree`, `/api/tsf/file`, `/api/tsf/search`, `/api/tsf/download`.
  - `src/fwmigrate/web_api/simulators.py` — `/api/source/policy-lookup`, `/api/source/route-lookup`, `/api/source/packet-trace`, `/api/source/config-diff`.
  - Extend `src/fwmigrate/web_api/diagnostics.py` (or dedicated route modules) for `/api/source/pm-lookup`, `/api/source/pm-lookup/export`, and `/api/source/ssl-to-ipsec`.
- **Non-Destructive Parking:**
  - Leave `src/fwmigrate/collection/`, `src/fwmigrate/conversion/`, and `src/fwmigrate/vendors/{cisco_asa,cisco_ftd,juniper_srx,checkpoint}/` completely untouched.

---

## 4. Frontend Layout Redesign & Visual Simplification

### Layout Structure (Following `firewall-config-reader` v2.4.5)
1. **Clean Auto-Detect Landing Page:**
   - Compact header + 3 supported-input cards:
     - **Palo Alto Networks** (`.xml`, PAN-OS 10.x+)
     - **FortiGate** (`.conf` / `.cfg` / `.txt`, FortiOS 6.x / 7.x)
     - **Palo Alto TSF** (`.zip`, Technical Support File archive)
   - Single drag-and-drop upload zone with automatic vendor/TSF detection (no manual vendor dropdown required for FG/PA/TSF).
2. **Unified Workspace Shell:**
   - **Left Sidebar (Sole Top-Level Navigation):**
     - `Overview`
     - `Security & Health`
     - `PM Lookup`
     - `Policies & NAT`
     - `Objects`
     - `Interfaces & Network`
     - `Security Profiles`
     - `VPN`
     - `Users & Auth`
     - `WiFi & Switch` *(FortiGate only)*
     - `System & Logs`
     - *(Optional collapsible/secondary `Diagnostics & Coverage` for source inventory / extraction coverage if desired)*
     - **Sidebar Footer:** `↑ Load new config` button, Desktop auto-updater status, and app version.
   - **Slim Topbar:**
     - Left: Sidebar toggle + `Vendor / Active Section` breadcrumb + loaded filename.
     - Right: `Search (Ctrl+K)` · `Audit Report` · `Export to Excel` · `Light / Dark`.
   - **Main Content Area:**
     - Horizontal sub-tabs *only* for subsections inside the selected sidebar section (e.g., under `Policies & NAT`: Security, NAT, Policy Lookup, Hygiene).
   - **Floating AI Config Assistant:** Kept in the bottom-right corner once a config is loaded.

### Visual Simplification Guidelines (Engineer-First Readability)
- **Eliminate duplicate navigation:** Remove the sticky top-level horizontal `report-tabs` bar from `SourceReport.tsx` so the sidebar is the single source of top-level navigation.
- **Declutter the topbar & sidebar:** Remove `Mode` selector (Collection/Migration), `ZoomControl`, and `ThemeColorPicker` from the main workspace bar so engineers have a clean, distraction-free header.
- **Flatten surfaces & reduce visual noise:**
  - Replace heavy gradient hero banners, glowing hover shadows, pulsing status dots, and stacked competing badges with crisp `1px` bordered flat cards and consistent label/value grids.
  - Minimize or replace repetitive emojis on headings/tabs with clean text or subtle monochrome icons.
- **High-density, scannable tables:**
  - Monospace styling for IPs, CIDR subnets, ports, policy IDs, and VLAN tags.
  - Reserve color accents strictly for operational meaning (`Allow/Pass`, `Deny/Fail/Disabled`, `Warn`, `Info`).
  - Keep search, column filter, scope/VDOM filter, CSV export, and row detail inspection compact and aligned on a single toolbar row.

---

## 5. Phased Implementation Roadmap

### Phase 1 — Layout Redesign, Landing Flow & Visual Simplification
- Refactor `AppLayout.tsx`, `PageHeader.tsx`, `Sidebar.tsx`, `SourceConfiguration.tsx`, and `SourceReport.tsx` to the unified v2.4.5 shell with simplified styling.
- Implement the auto-detect FG / PA / TSF landing page (hiding or parking Collection, Migration, and the other 4 vendors in the UI).
- Move `Audit Report` and `Export to Excel` into the slim topbar and add the **Global `Ctrl+K` Quick Search Modal** backed by `/api/source/where-used`.

### Phase 2 — PM Lookup & FG/PA Parser Parity
- Port `pm_checklist_service.py` onto `VendorConfig` + `DerivedViews` for FortiGate and Palo Alto.
- Add `/api/source/pm-lookup` (and Excel/CSV export) and the `PM Lookup` sidebar section with status filters and legend.
- Audit and close remaining v2.4.4–v2.4.5 FG/PA extraction gaps (FortiGate Log Settings & Threat Weight, Mgmt/Ports overview, admin/interface refinements, PAN-OS HA/device fields).

### Phase 3 — Traffic Simulators & Structural Config Diff
- Port backend services and Flask routes under `web_api/simulators.py`:
  - **Policy Lookup / Policy Match Simulator** (`Policies & NAT`)
  - **LPM Route Lookup** (`Interfaces & Network`)
  - **End-to-End Packet Flow Simulator (`Trace Packet`)** (`Overview`)
  - **Firewall-Aware Structural Config Diff** (`Overview`)
- Build clean, low-clutter React panels for each simulator/tool.

### Phase 4 — FortiGate SSL-VPN → Dial-up IPSec Assistant
- Port `ssl_to_ipsec_service.py` onto FortiGate `VendorConfig`.
- Add `/api/source/ssl-to-ipsec` and a dedicated sub-tab under `VPN` alongside the existing Site-to-Site VPN Inspector.

### Phase 5 — Palo Alto TSF (`.zip`) Explorer
- Port `tsf/` (`extractor.py`, `indexer.py`, `search.py`, `file_preview.py`) into `src/fwmigrate/tsf/` with session cleanup and security screening.
- Add `src/fwmigrate/web_api/tsf.py` routes and wire `.zip` uploads from the auto-detect landing page.
- Build the React split-pane **TSF Explorer** (progress bar, collapsible directory tree, filename/content search toggle, paginated line-numbered file viewer with jump-to-match, and raw file download).

### Phase 6 — Verification & Desktop/Web Packaging
- Run full backend verification (`python -m compileall -q src tests scripts`, `ruff check src tests scripts`, `python -m pytest -q`).
- Run full frontend verification (`npm test`, `npm run lint`, `npm run build` in `src/frontend`).
- Verify end-to-end flows in both local web mode and Windows Desktop (`pywebview`) with real FortiGate `.conf`, Palo Alto `.xml`, and Palo Alto TSF `.zip` samples.

---

## 6. Open Alignment Questions for Next Discussion

1. **Collection, Migration & Other 4 Vendors in UI:** Completely hide `Live Collection`, `Plan Migration`, and Cisco/Juniper/Check Point from the UI for now (keeping backend code untouched), or keep a subtle toggle to access them?
2. **Icons vs. Emojis:** In the simplified UI, prefer minimal monochrome line icons (or text-only headers) instead of emojis on sidebar items and section titles?
3. **Excel Export:** Keep `firewall-migration-tool`'s existing vendor-native `fast`/`full` Excel exporter behind the topbar `Export to Excel` button (plus a dedicated PM Lookup Excel export inside `PM Lookup`)?
4. **TSF in Hosted (`public`) Mode:** Allow TSF `.zip` uploads in both `public` and `local`/Desktop modes (with a safe size cap), or restrict large TSF archives to `local`/Desktop mode only?
