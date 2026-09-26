document.addEventListener("DOMContentLoaded", () => {
  // =========================================================================
  // Application State
  // =========================================================================
let currentFile = null;
let currentRenderedArtifactId = null;
let currentArtifactCommandCount = 0;
let currentArtifactSha256 = null;
let migrationPlanRevision = 0;
let migrationPlanNeedsRebuild = false;
  let currentPlanItems = [];
  let currentRecommendations = [];
  let currentDecisionSet = { decisions: [] };
  let currentDecisionDocument = null;
  let decisionContext = {};
  let decisionCandidates = {};
  let reviewSummary = {};
  let automationRunSummary = null;
  let reviewGroups = [];
  let autoDecisionResults = {};
  let architectureQuestions = [];
  let aiAssistAvailable = false;
  let aiProposals = [];
  let aiExplanation = null;
  let aiAnalysisRevision = 0;
  let aiAnalysisInFlight = false;
  let aiAnalysisCompleteRevision = -1;
  let aiReviewReady = false;
  let ruleSuggestions = [];
  let activeReviewQueue = "READY_TO_CONFIRM";
  let currentPreviewId = null;
  let currentTargetPreviewId = null;
  let selectedTargetDevice = "";
  let targetRevision = 0;
  let targetWarnings = {};
  let targetFindings = [];
  let targetPlanFindings = [];
  let decisionEvidence = {};
  let evidenceSummary = {};
  let supportGuidance = [];
  let targetEvidence = null;
  let selectedSourceVendor = "fortigate";
  let selectedTargetVendor = "palo_alto";
  let offlineTargetVendor = "palo_alto";
  let activeMode = "download"; // 'download', 'live', 'collect', or 'report'
  let currentPolicies = [];
  let currentReport = null;
  let sourceReady = false;
  let sourceFailed = false;
  let sourceRevision = 0;
  let previewController = null;
  const busyButtons = new Set();

  const MODE_COPY = {
    report: [
      "Configuration Report",
      "Review source details and download Excel.",
    ],
    download: [
      "Plan migration",
      "",
    ],
    collect: ["Live Collection", "Collect configuration directly from a supported device."],
    live: [
      "Live migration",
      "",
    ],
  };

  // Vendor metadata specifications for dynamic API credential forms & guides
  const VENDOR_CONFIGS = {
    fortigate: {
      name: "Fortinet FortiGate",
      icon: "🛡️",
      fileAccept: ".conf,.cfg,.txt",
      dropText:
        "Supports FortiOS <code>.conf</code>, <code>.cfg</code>, or <code>.txt</code> backup files",
    },
    palo_alto: {
      name: "Palo Alto Networks",
      icon: "🔥",
      protocol: "PAN-OS XML / REST API (HTTPS /api/)",
      desc: "Connects to PAN-OS XML API to retrieve active candidate/running configurations and security rulebases.",
      defaultPort: 443,
      authTypes: [
        { id: "apikey", label: "PAN-OS API Key" },
        { id: "userpass", label: "Admin Username & Password" },
      ],
      fileAccept: ".xml,.txt,.conf",
      dropText:
        "Supports Palo Alto Networks PAN-OS <code>.xml</code> or <code>.txt</code> configuration exports",
      fields: [
        {
          id: "api-host",
          label: "PAN-OS IP / Hostname",
          type: "text",
          required: true,
          placeholder: "192.168.1.1 or panorama.corp.local",
          col: "col-8",
        },
        {
          id: "api-port",
          label: "HTTPS Port",
          type: "number",
          required: true,
          value: 443,
          col: "col-4",
        },
        {
          id: "api-vsys",
          label: "Virtual System (VSYS)",
          type: "text",
          required: false,
          value: "vsys1",
          placeholder: "vsys1",
          col: "col-6",
        },
        {
          id: "api-token",
          label: "PAN-OS API Key",
          type: "password",
          required: true,
          placeholder: "LUFRPT14MW5xV05xWDV...",
          col: "col-6",
          authType: "apikey",
        },
        {
          id: "api-username",
          label: "Admin Username",
          type: "text",
          required: true,
          placeholder: "admin",
          col: "col-6",
          authType: "userpass",
        },
        {
          id: "api-password",
          label: "Admin Password",
          type: "password",
          required: true,
          placeholder: "••••••••",
          col: "col-6",
          authType: "userpass",
        },
        {
          id: "api-insecure",
          label:
            "Allow Self-Signed TLS Certificates (Disable SSL Verification)",
          type: "checkbox",
          checked: false,
          col: "col-12",
        },
      ],
    },
    cisco_asa: {
      name: "Cisco ASA",
      icon: "🌐",
      protocol: "SSH",
      desc: "Collects the running configuration over SSH.",
      defaultPort: 22,
      authTypes: [{ id: "userpass", label: "SSH Credentials" }],
      fileAccept: ".cfg,.txt,.conf",
      dropText:
        "Supports Cisco ASA <code>.cfg</code> or <code>.txt</code> configuration files",
    },
    cisco_ftd: {
      name: "Cisco FTD / FMC",
      fileAccept: ".json,.txt",
      dropText: "Supports FMC REST export JSON files",
    },
    checkpoint: {
      name: "Check Point",
      icon: "🔒",
      protocol: "Check Point Management Web API (/web_api/)",
      desc: "Queries Check Point R80/R81 SmartCenter Web API to extract network objects, rulebases, and NAT tables.",
      defaultPort: 443,
      authTypes: [{ id: "userpass", label: "Management Admin Credentials" }],
      fileAccept: ".json,.txt",
      dropText:
        "Supports Check Point R80/R81 <code>.json</code> database dumps or export files",
      fields: [
        {
          id: "api-host",
          label: "Management Server IP / Hostname",
          type: "text",
          required: true,
          placeholder: "192.168.1.10",
          col: "col-8",
        },
        {
          id: "api-port",
          label: "HTTPS Port",
          type: "number",
          required: true,
          value: 443,
          col: "col-4",
        },
        {
          id: "api-username",
          label: "Admin Username",
          type: "text",
          required: true,
          placeholder: "admin",
          col: "col-6",
        },
        {
          id: "api-password",
          label: "Admin Password",
          type: "password",
          required: true,
          placeholder: "••••••••",
          col: "col-6",
        },
        {
          id: "api-domain",
          label: "Domain (MDS / Multi-Domain)",
          type: "text",
          required: false,
          placeholder: "Default",
          col: "col-12",
        },
        {
          id: "api-insecure",
          label:
            "Allow Self-Signed TLS Certificates (Disable SSL Verification)",
          type: "checkbox",
          checked: false,
          col: "col-12",
        },
      ],
    },
    juniper_srx: {
      name: "Juniper SRX",
      icon: "🌲",
      protocol: "Junos SSH CLI",
      desc: "Collects Junos configuration in set format over SSH.",
      defaultPort: 22,
      authTypes: [{ id: "userpass", label: "SSH Admin Credentials" }],
      fileAccept: ".set,.conf,.txt",
      dropText:
        "Supports JunOS SRX <code>.set</code>, <code>.conf</code>, or <code>.txt</code> files",
      fields: [
        {
          id: "api-host",
          label: "JunOS Device IP / Hostname",
          type: "text",
          required: true,
          placeholder: "192.168.1.1 or srx.corp.local",
          col: "col-8",
        },
        {
          id: "api-port",
          label: "SSH Port",
          type: "number",
          required: true,
          value: 22,
          col: "col-4",
        },
        {
          id: "api-username",
          label: "Admin Username",
          type: "text",
          required: true,
          placeholder: "admin",
          col: "col-6",
        },
        {
          id: "api-password",
          label: "Admin Password",
          type: "password",
          required: true,
          placeholder: "••••••••",
          col: "col-6",
        },
      ],
    },
  };

  // =========================================================================
  // DOM Elements Cache
  // =========================================================================
  // Mode Switcher Tabs
  const tabDownload = document.getElementById("tab-download");
  const tabReport = document.getElementById("tab-report");
  const tabLive = document.getElementById("tab-live");
  const tabCollect = document.getElementById("tab-collect");
  const developmentBanner = document.getElementById("development-banner");
  const modeDownloadForm = document.getElementById("mode-download-form");
  const modeLiveForm = document.getElementById("mode-live-form");
  const reportContainer = document.getElementById("report-container");
  const reportOverview = document.getElementById("report-overview");
  const reportData = document.getElementById("report-data");
  const reportSummary = document.getElementById("report-summary");
  const reportScopeSummary = document.getElementById("report-scope-summary");
  const reportObjectTabs = document.getElementById("report-object-tabs");
  const reportSearch = document.getElementById("report-search");
  const reportScopeFilter = document.getElementById("report-scope-filter");
  const reportSeverityFilter = document.getElementById("report-severity-filter");
  const reportTableHead = document.getElementById("report-table-head");
  const reportTableBody = document.getElementById("report-table-body");
  const reportTable = document.querySelector(".report-table");
  const reportTableWrap = document.querySelector(".report-table-wrap");
  const reportTableCaption = document.getElementById("report-table-caption");
  const reportRowCount = document.getElementById("report-row-count");
  const reportScrollHint = document.getElementById("report-scroll-hint");
  const reportEmpty = document.getElementById("report-empty");
  const reportPager = document.getElementById("report-pager");
  const reportPageStatus = document.getElementById("report-page-status");
  const reportPagePrevious = document.getElementById("report-page-previous");
  const reportPageNext = document.getElementById("report-page-next");
  const validationSummary = document.getElementById("validation-summary");
  const validationGroupsPanel = document.getElementById("validation-groups-panel");
  const validationDetailsHeading = document.getElementById("validation-details-heading");
  const validationActiveFilter = document.getElementById("validation-active-filter");
  const validationActiveFilterLabel = document.getElementById("validation-active-filter-label");
  const validationFilterClear = document.getElementById("validation-filter-clear");
  const reportDetailModal = document.getElementById("report-detail-modal");
  const reportDetailTitle = document.getElementById("report-detail-title");
  const reportDetailBody = document.getElementById("report-detail-body");
  const reportDetailClose = document.getElementById("report-detail-close");
  let reportDetailTrigger = null;
  let activeReportSection = "overview";
  let activeObjectSection = "addresses";
  let reportPage = 1;
  let activeValidationGroup = "";
  const REPORT_PAGE_SIZE = 100;

  // Ingestion Method Tabs
  const btnIngestFile = document.getElementById("btn-ingest-file");
  const btnIngestSnapshot = document.getElementById("btn-ingest-snapshot");
  const liveContainer = document.getElementById("ingest-live-container");
  let ingestMode = "file";
  const collectionCapabilities = {};
  const vendorCapabilities = {};
  const collectionGuides = {
    fortigate: "Live collection is unavailable for FortiGate. Export a FortiOS configuration backup and use Upload Config.",
    palo_alto: "Live collection is unavailable for PAN-OS. Export an XML configuration and use Upload Config.",
    cisco_asa: "Connect directly to the ASA over SSH. The collector runs 'show running-config' and uses that output as the source. The SSH host key must already be trusted, and the account needs permission to read the running configuration.",
    juniper_srx: "Connect directly to the SRX over SSH. The collector runs 'show configuration | display set' and uses the set-format output as the source. The SSH host key must already be trusted, and the account needs permission to read the configuration.",
    cisco_ftd: "Connect to Firepower Management Center over HTTPS, not to the FTD device. The collector authenticates to the FMC REST API and reads objects, access policies and rules, and NAT policies and rules. Enter a domain name or UUID when FMC has multiple domains; certificate verification is enabled by default.",
    checkpoint: "Connect to the Check Point management server over HTTPS. The collector reads Management API objects and policy data; enter the policy package and access layer to include their scoped data. To also collect gateway settings, provide the optional Gaia SSH host and credentials. Certificate verification is enabled by default; incomplete API or Gaia results are reported as partial collection.",
  };

  async function loadCollectionCapabilities() {
    try {
      const response = await fetch("/api/vendors");
      const data = await readJson(response, "Could not load vendors");
      for (const source of data.sources || []) {
        vendorCapabilities[source.vendor_id] = source;
        if (source.live_collection) collectionCapabilities[source.vendor_id] = source.collection;
      }
      renderCollectionFields();
      syncWorkspace();
    } catch (_) { /* File upload remains available. */ }
  }

  function renderCollectionFields() {
    const container = document.getElementById("collection-fields");
    const status = document.getElementById("collection-status");
    const guideButton = document.getElementById("btn-collection-guide");
    const guide = document.getElementById("collection-guide");
    const actions = document.querySelector("#ingest-live-container .button-row");
    if (!container) return;
    container.replaceChildren();
    const capability = collectionCapabilities[selectedSourceVendor];
    document.getElementById("collection-guide-title").textContent = `${sourceVendorSelect.options[sourceVendorSelect.selectedIndex]?.text || selectedSourceVendor} live collection`;
    document.getElementById("collection-guide-details").textContent = collectionGuides[selectedSourceVendor] || "Live collection is unavailable for this vendor. Upload a configuration file instead.";
    document.getElementById("collection-guide-workflow").classList.toggle("hidden", !capability);
    document.getElementById("btn-test-collection").disabled = !capability;
    document.getElementById("btn-collect-configuration").disabled = !capability;
    guideButton?.classList.toggle("hidden", !capability);
    container.classList.toggle("hidden", !capability);
    actions?.classList.toggle("hidden", !capability);
    if (!capability) {
      guide?.classList.add("hidden");
      guideButton?.setAttribute("aria-expanded", "false");
      status.textContent = "Live collection is unavailable for this vendor.";
      status.classList.remove("hidden");
      return;
    }
    status.classList.add("hidden");
    for (const field of capability.connection_fields) {
      const label = document.createElement("label");
      label.className = "form-group " + (field.type === "checkbox" ? "col-12" : "col-6");
      const title = document.createElement("span");
      title.textContent = field.label;
      const input = document.createElement("input");
      input.id = `collection-${field.name}`;
      input.dataset.collectionField = field.name;
      input.type = field.type;
      input.required = !!field.required;
      if (field.type === "checkbox") input.checked = field.default === true;
      else if (field.default !== undefined) input.value = field.default;
      if (field.type === "number") { input.min = "1"; input.max = "65535"; }
      if (field.type === "password") input.autocomplete = "new-password";
      label.append(title, input);
      container.append(label);
    }
  }
  document.getElementById("btn-collection-guide")?.addEventListener("click", (event) => {
    const guide = document.getElementById("collection-guide");
    const expanded = event.currentTarget.getAttribute("aria-expanded") === "true";
    event.currentTarget.setAttribute("aria-expanded", String(!expanded));
    guide.classList.toggle("hidden", expanded);
  });

  // Vendor Selection Dropdowns
  const sourceVendorSelect = document.getElementById("source-vendor-select");
  const targetVendorSelect = document.getElementById("target-vendor-select");
  const targetVendorGroup = document.getElementById("target-vendor-group");
  const vendorSelectorGrid = document.getElementById("vendor-selector-grid");

  // File Ingest Dropzone
  const dropzone = document.getElementById("file-dropzone");
  const fileInput = document.getElementById("file-input");
  const dropzoneSubtext = document.getElementById("dropzone-subtext");
  const selectedFileCard = document.getElementById("selected-file-card");
  const selectedFilename = document.getElementById("selected-filename");
  const selectedFilesize = document.getElementById("selected-filesize");
  const btnRemoveFile = document.getElementById("btn-remove-file");
  const targetConfigFile = document.getElementById("target-config-file");
  const targetConfigRemove = document.getElementById("target-config-remove");
  const targetConfigStatus = document.getElementById("target-config-status");
  const targetDeviceGroup = document.getElementById("target-device-group");
  const targetDeviceSelect = document.getElementById("target-device-select");

  // Optimizer Panel Stats
  const optimizerPanel = document.getElementById("optimizer-panel");
  const statTotalRules = document.getElementById("stat-total-rules");
  const statTotalObjects = document.getElementById("stat-total-objects");
  const statErrors = document.getElementById("stat-errors");
  const statWarnings = document.getElementById("stat-warnings");

  // Mode A Components
  const btnGenerateBundle = document.getElementById("btn-generate-bundle");
  const btnDownloadBundle = document.getElementById("btn-download-bundle");
  const btnDownloadSet = document.getElementById("btn-download-set");
  const btnExtractExcel = document.getElementById("btn-extract-excel");
  const excelProfile = document.getElementById("excel-profile");

  // Mode B Target Form & Diagnostics
  const panHost = document.getElementById("pan-host");
  const panPort = document.getElementById("pan-port");
  const panUser = document.getElementById("pan-user");
  const panPass = document.getElementById("pan-pass");

  const btnPushCandidate = document.getElementById("btn-push-candidate");
  const btnValidateCandidate = document.getElementById("btn-validate-candidate");
  const btnCommitCandidate = document.getElementById("btn-commit-candidate");
  let candidatePushed = false;
  let candidateValidated = false;

  // Terminal
  const terminalStreamBody = document.getElementById("terminal-stream-body");
  const termAutoscroll = document.getElementById("term-autoscroll");
  const btnClearTerm = document.getElementById("btn-clear-term");
  const btnCopyTerm = document.getElementById("btn-copy-term");

  // Toast Container & Error Banner
  const toastContainer = document.getElementById("toast-container");
  const errorBanner = document.getElementById("error-message");

  function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
  }

  function count(value) {
    return Math.max(0, Number(value) || 0);
  }

  const reportColumns = {
    interfaces: [["display_name", "Topology", "topology"], ["kind", "Kind", "compact"], ["ip", "IP / Remote Gateway", "address"], ["zone", "Zone", "compact"], ["parent", "Parent"], ["aggregate", "Aggregate"], ["physical_interfaces", "Physical Interfaces"], ["attached_tunnels", "Attached Tunnels"], ["status", "Status", "compact"], ["review", "Review", "notes"]],
    addresses: [["name", "Name"], ["value", "Value", "address"], ["type", "Type", "compact"], ["address_family", "Family", "compact"], ["associated_interface", "Interface"], ["review", "Review", "notes"]],
    address_groups: [["name", "Name"], ["members", "Members"], ["address_family", "Family", "compact"], ["exclude_members", "Excluded"], ["review", "Review", "notes"]],
    services: [["name", "Name"], ["protocol", "Protocol", "compact"], ["port", "Port", "compact"], ["source_port", "Source Port", "compact"], ["generated", "Generated", "compact"], ["review", "Review", "notes"]],
    service_groups: [["name", "Name"], ["members", "Members"], ["generated", "Generated", "compact"], ["review", "Review", "notes"]],
    policies: [["policy_id", "ID", "compact"], ["name", "Name"], ["source_interfaces", "From"], ["destination_interfaces", "To"], ["source_addresses", "Source"], ["source_addresses_ipv6", "Source IPv6"], ["destination_addresses", "Destination"], ["destination_addresses_ipv6", "Destination IPv6"], ["services", "Service"], ["schedule", "Schedule"], ["action", "Action", "compact"], ["nat", "NAT", "compact"], ["review", "Review", "notes"]],
    nat: [["policy_id", "Policy ID", "compact"], ["policy_name", "Policy"], ["translation_type", "Type", "compact"], ["translated_addresses", "Address", "address"], ["egress_interfaces", "Egress"], ["review", "Review", "notes"]],
    routes: [["route_id", "ID", "compact"], ["destination", "Destination", "address"], ["gateway", "Gateway", "address"], ["device", "Device"], ["distance", "Distance", "compact"], ["status", "Status", "compact"], ["review", "Review", "notes"]],
    vpn: [["kind", "Type", "compact"], ["name", "Name"], ["attachment", "Interface / Phase 1"], ["peer", "Gateway / Selectors", "address"], ["crypto", "IKE / Proposal"], ["topology", "Topology"], ["review", "Review", "notes"]],
    validation: [["severity", "Severity", "compact"], ["domain", "Domain"], ["object_name", "Object"], ["field", "Field"], ["message", "Issue", "notes"]],
  };

  function reportCell(value) {
    if (value === null || value === undefined || value === "") return "—";
    if (Array.isArray(value)) return value.length ? value.join(", ") : "—";
    if (typeof value === "boolean") return value ? "Yes" : "No";
    return String(value);
  }

  function showReportDetails(row, triggerElement) {
    if (!reportDetailModal || !reportDetailBody) return;
    if (reportDetailTitle) reportDetailTitle.textContent = row.policy_id != null ? `Policy ${row.policy_id}` : row.name || row.display_name || row.object_name || "Row details";
    const list = document.createElement("dl");
    Object.entries(row).forEach(([key, value]) => {
      if (/raw_extra|password|secret|credential|token|private.?key|psk/i.test(key)) return;
      const term = document.createElement("dt");
      term.textContent = key.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
      const detail = document.createElement("dd");
      if (Array.isArray(value)) {
        if (value.length) {
          const items = document.createElement("ul");
          value.forEach((item) => { const entry = document.createElement("li"); entry.textContent = reportCell(item); items.appendChild(entry); });
          detail.appendChild(items);
        } else detail.textContent = "—";
      } else detail.textContent = reportCell(value);
      list.append(term, detail);
    });
    reportDetailBody.replaceChildren(list);
    openReportDetailModal(triggerElement);
  }

  function openReportDetailModal(triggerElement) {
    reportDetailTrigger = triggerElement;
    reportDetailModal?.classList.remove("hidden");
    reportDetailClose?.focus();
  }

  function closeReportDetailModal(restoreFocus = true) {
    reportDetailModal?.classList.add("hidden");
    if (restoreFocus && reportDetailTrigger?.isConnected) reportDetailTrigger.focus();
    reportDetailTrigger = null;
  }

  function navigateToValidationTarget(row) {
    const targets = {
      interface: ["interfaces"], address: ["objects", "addresses"], address6: ["objects", "addresses"],
      address_group: ["objects", "address_groups"], service: ["objects", "services"], service_group: ["objects", "service_groups"],
      policy: ["policies"], route: ["routes"], static_route: ["routes"], static_route6: ["routes"],
      vpn: ["vpn"], ipsec_phase1: ["vpn"], vpn_phase2: ["vpn"],
    };
    const target = targets[row.domain];
    if (!target || !row.object_name) return false;
    activeReportSection = target[0];
    if (target[1]) activeObjectSection = target[1];
    reportPage = 1;
    activeValidationGroup = "";
    document.querySelectorAll("[data-object-section]").forEach((button) => button.classList.toggle("active", button.dataset.objectSection === activeObjectSection));
    if (reportScopeFilter) reportScopeFilter.value = row.scope || row.vdom || "";
    if (reportSearch) reportSearch.value = String(row.object_name);
    closeReportDetailModal(false);
    renderReport();
    const match = [...(reportTableBody?.rows || [])].find((tr) => [...tr.cells].some((cell) => cell.textContent.trim() === String(row.object_name)));
    if (match) { match.classList.add("report-row-highlight"); match.scrollIntoView({ block: "center", behavior: "smooth" }); }
    return true;
  }

  function reportRows(section) {
    const sections = currentReport?.sections || {};
    if (section === "interfaces") return sections.interface_topology || sections.interfaces || [];
    if (section === "objects") return sections[activeObjectSection] || [];
    if (section === "vpn") return [
      ...(sections.vpn_tunnels || []).map((row) => ({ ...row, kind: "Tunnel", attachment: row.interface, peer: row.remote_gateway || row.ike_gateways, crypto: row.ike_version || row.ipsec_crypto_profile, topology: row.topology_path })),
      ...(sections.vpn_phase2 || []).map((row) => ({ ...row, kind: "Phase 2", attachment: row.phase1, peer: [["IPv4 src", row.source_range], ["IPv4 dst", row.destination_range], ["IPv6 src", row.source_range6], ["IPv6 dst", row.destination_range6]].filter(([, value]) => value).map(([label, value]) => `${label}: ${value}`).join(" → "), crypto: row.proposal, topology: [] })),
    ];
    return sections[section] || [];
  }

  function renderReportTable() {
    if (!currentReport || activeReportSection === "overview") return;
    const columnKey = activeReportSection === "objects" ? activeObjectSection : activeReportSection;
    let columns = reportColumns[columnKey] || [];
    const search = reportSearch?.value.trim().toLowerCase() || "";
    const scope = reportScopeFilter?.value || "";
    const severity = reportSeverityFilter?.value || "";
    const sectionRows = reportRows(activeReportSection);
    const rows = sectionRows.filter((row) => {
      if (activeReportSection === "validation" && activeValidationGroup &&
          JSON.stringify([row.severity, row.domain, row.field, row.message]) !== activeValidationGroup) return false;
      if (scope && (row.scope || row.vdom) !== scope) return false;
      if (severity && row.severity !== severity) return false;
      return !search || Object.values(row).some((value) => reportCell(value).toLowerCase().includes(search));
    });
    const identityColumns = new Set(["name", "policy_id", "policy_name", "object_name", "display_name", "route_id", "destination", "id", "severity", "domain"]);
    columns = columns.filter(([key]) => identityColumns.has(key) || rows.some((row) => reportCell(row[key]) !== "—"));
    const pageCount = Math.max(1, Math.ceil(rows.length / REPORT_PAGE_SIZE));
    reportPage = Math.min(reportPage, pageCount);
    const start = (reportPage - 1) * REPORT_PAGE_SIZE;
    const visibleRows = rows.slice(start, start + REPORT_PAGE_SIZE);
    const head = document.createElement("tr");
    columns.forEach(([key, label, layout = "text"]) => {
      const th = document.createElement("th");
      th.scope = "col";
      th.textContent = label;
      th.dataset.column = key;
      th.className = `report-cell-${layout}`;
      head.appendChild(th);
    });
    reportTableHead?.replaceChildren(head);
    const body = document.createDocumentFragment();
    visibleRows.forEach((row) => {
      const tr = document.createElement("tr");
      tr.tabIndex = 0;
      tr.addEventListener("click", () => {
        if (activeReportSection === "validation") { navigateToValidationTarget(row); return; }
        showReportDetails(row, tr);
      });
      tr.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); tr.click(); }
      });
      columns.forEach(([key, , layout = "text"]) => {
        const td = document.createElement("td");
        td.dataset.column = key;
        td.className = `report-cell-${layout}`;
        td.textContent = reportCell(row[key]);
        if (columnKey === "interfaces" && key === "ip") {
          td.textContent = reportCell(row[key]).replace(/\s+/g, "\n");
        }
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    reportTableBody?.replaceChildren(body);
    if (reportTable) reportTable.dataset.section = columnKey;
    const sectionLabel = document.querySelector(
      activeReportSection === "objects"
        ? `[data-object-section="${activeObjectSection}"]`
        : `[data-report-section="${activeReportSection}"]`,
    )?.textContent.trim() || "Configuration";
    if (reportTableCaption) reportTableCaption.textContent = `${sectionLabel} report`;
    if (reportRowCount) {
      reportRowCount.textContent = rows.length
        ? `${start + 1}–${Math.min(start + REPORT_PAGE_SIZE, rows.length)} of ${rows.length} ${rows.length === 1 ? "row" : "rows"}`
        : `0 of 0 rows`;
    }
    reportTableWrap?.classList.toggle("hidden", rows.length === 0);
    reportEmpty?.classList.toggle("hidden", rows.length > 0);
    reportPager?.classList.toggle("hidden", rows.length <= REPORT_PAGE_SIZE);
    if (reportPageStatus) reportPageStatus.textContent = `Page ${reportPage} of ${pageCount}`;
    if (reportPagePrevious) reportPagePrevious.disabled = reportPage <= 1;
    if (reportPageNext) reportPageNext.disabled = reportPage >= pageCount;
    requestAnimationFrame(syncTableOverflow);
  }

  function renderValidationSummary() {
    if (!validationSummary) return;
    const groups = new Map();
    reportRows("validation").forEach((row) => {
      const key = JSON.stringify([row.severity, row.domain, row.field, row.message]);
      const group = groups.get(key) || { row, count: 0 };
      group.count += 1;
      groups.set(key, group);
    });
    const fragment = document.createDocumentFragment();
    const severityOrder = { error: 0, warning: 1 };
    [...groups.entries()]
      .sort(([, left], [, right]) =>
        (severityOrder[String(left.row.severity).toLowerCase()] ?? 2) -
        (severityOrder[String(right.row.severity).toLowerCase()] ?? 2) || right.count - left.count
      )
      .forEach(([key, { row, count: total }]) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "validation-group";
        button.classList.toggle("active", key === activeValidationGroup);
        button.dataset.validationGroup = key;
        button.setAttribute("aria-pressed", String(key === activeValidationGroup));
        const severity = document.createElement("span");
        severity.className = `validation-badge validation-badge-${String(row.severity || "other").toLowerCase()}`;
        severity.textContent = (row.severity || "Issue").toUpperCase();
        const count = document.createElement("span");
        count.className = "validation-badge validation-count";
        count.textContent = String(total);
        const message = document.createElement("span");
        message.className = "validation-group-message";
        message.textContent = row.message || row.field || row.domain || "Validation finding";
        button.append(severity, count, message);
        fragment.appendChild(button);
      });
    validationSummary.replaceChildren(fragment);
    const inValidation = activeReportSection === "validation";
    validationGroupsPanel?.classList.toggle("hidden", !inValidation || groups.size === 0);
    validationDetailsHeading?.classList.toggle("hidden", !inValidation);
    validationActiveFilter?.classList.toggle("hidden", !inValidation || !activeValidationGroup);
    if (activeValidationGroup) {
      const selected = groups.get(activeValidationGroup);
      if (validationActiveFilterLabel) validationActiveFilterLabel.textContent = `Filtered by: ${selected?.row.message || selected?.row.field || selected?.row.domain || "Validation finding"}`;
    }
  }

  function syncTableOverflow() {
    if (!reportTableWrap) return;
    const overflowing = reportTableWrap.clientWidth > 0 &&
      reportTableWrap.scrollWidth > reportTableWrap.clientWidth + 1;
    reportScrollHint?.classList.toggle("hidden", !overflowing);
  }

  if (window.ResizeObserver && reportTableWrap && reportTable) {
    const tableResizeObserver = new ResizeObserver(syncTableOverflow);
    tableResizeObserver.observe(reportTableWrap);
    tableResizeObserver.observe(reportTable);
  } else {
    window.addEventListener("resize", syncTableOverflow);
  }

  function renderReport() {
    if (!currentReport || !reportSummary) return;
    const summary = currentReport.summary || {};
    const objects = summary.objects || {};
    const severity = summary.validation?.severity_counts || {};
    const objectTotal = ["addresses", "address_groups", "services", "service_groups"].reduce((total, key) => total + count(objects[key]), 0);
    const sections = currentReport.sections || {};
    const stats = [];
    if (objects.interfaces != null) stats.push(["Interfaces", objects.interfaces]);
    if (objects.policies != null) stats.push(["Policies", objects.policies]);
    if (["addresses", "address_groups", "services", "service_groups"].some((key) => objects[key] != null)) stats.push(["Objects", objectTotal]);
    if (severity.error != null) stats.push(["Errors", severity.error]);
    if (severity.warning != null) stats.push(["Warnings", severity.warning]);
    if (sections.routes) stats.push(["Routes", sections.routes.length]);
    if (sections.vpn_tunnels || sections.vpn_phase2) stats.push(["VPNs", (sections.vpn_tunnels || []).length + (sections.vpn_phase2 || []).length]);
    if (sections.unresolved_references) stats.push(["Unresolved references", sections.unresolved_references.length]);
    const unsupported = summary.unsupported_count ?? summary.source_only_count;
    if (unsupported != null) stats.push(["Unsupported / source-only", unsupported]);
    const fragment = document.createDocumentFragment();
    const destinations = { Interfaces: ["interfaces"], Objects: ["objects", "addresses"], Policies: ["policies"], Routes: ["routes"], VPNs: ["vpn"] };
    stats.forEach(([label, value]) => {
      const stat = destinations[label] || ["Errors", "Warnings"].includes(label)
        ? document.createElement("button") : document.createElement("div");
      stat.className = `report-stat${stat.tagName === "BUTTON" ? " report-stat-button" : ""}`;
      if (stat.tagName === "BUTTON") {
        stat.type = "button";
        stat.setAttribute("aria-label", `Show ${label.toLowerCase()}`);
        stat.addEventListener("click", () => {
          const destination = destinations[label] || ["validation"];
          activeReportSection = destination[0];
          if (destination[1]) activeObjectSection = destination[1];
          activeValidationGroup = "";
          if (reportSearch) reportSearch.value = "";
          if (reportScopeFilter) reportScopeFilter.value = "";
          if (reportSeverityFilter) reportSeverityFilter.value = label === "Errors" ? "error" : label === "Warnings" ? "warning" : "";
          reportPage = 1;
          renderReport();
        });
      }
      const number = document.createElement("strong"); number.textContent = String(count(value));
      const caption = document.createElement("span"); caption.textContent = label;
      stat.append(number, caption); fragment.appendChild(stat);
    });
    reportSummary.replaceChildren(fragment);
    if (reportScopeSummary) {
      const scopes = summary.scopes || summary.vdoms || [];
      reportScopeSummary.textContent = scopes.length ? `Scopes: ${scopes.map((scope) => typeof scope === "string" ? scope : scope.name || scope.vsys || JSON.stringify(scope)).join(", ")}` : "No scope data found.";
    }
    if (reportScopeFilter) {
      const scopes = summary.scopes || summary.vdoms || [];
      const selected = reportScopeFilter.value;
      const options = [...new Set(scopes.map((scope) => typeof scope === "string" ? scope : scope.name || scope.vsys).filter(Boolean))];
      reportScopeFilter.replaceChildren(new Option("All scopes", ""), ...options.map((scope) => new Option(scope, scope)));
      reportScopeFilter.value = options.includes(selected) ? selected : "";
    }
    const overview = activeReportSection === "overview";
    reportOverview?.classList.toggle("hidden", !overview);
    reportData?.classList.toggle("hidden", overview);
    reportObjectTabs?.classList.toggle("hidden", activeReportSection !== "objects");
    reportSeverityFilter?.classList.toggle("hidden", activeReportSection !== "validation");
    document.querySelectorAll("[data-object-section]").forEach((button) => button.classList.toggle("active", button.dataset.objectSection === activeObjectSection));
    document.querySelectorAll("[data-report-section]").forEach((button) => button.classList.toggle("active", button.dataset.reportSection === activeReportSection));
    renderValidationSummary();
    if (!overview) renderReportTable();
  }

  function syncWorkspace() {
    const hasInput = Boolean(currentFile || currentPreviewId);
    const migrationPairSupported = selectedSourceVendor === "fortigate" && selectedTargetVendor === "palo_alto";
    tabReport?.classList.toggle("hidden", !vendorCapabilities[selectedSourceVendor]?.web_report);
    if (btnGenerateBundle)
      btnGenerateBundle.disabled =
        !currentPreviewId || !sourceReady || !migrationPairSupported || busyButtons.has(btnGenerateBundle);
    if (btnExtractExcel)
      btnExtractExcel.disabled =
        !hasInput || !sourceReady || busyButtons.has(btnExtractExcel);
    optimizerPanel?.classList.toggle("hidden", activeMode === "report" || !sourceReady);
    document.getElementById("migration-build")?.classList.toggle("hidden", !hasInput);
    document.getElementById("migration-mapping")?.classList.toggle(
      "hidden", !sourceReady || !migrationPairSupported || !currentDecisionSet.decisions.length,
    );
    const reviewedArtifact = Boolean(currentRenderedArtifactId && currentArtifactCommandCount);
    if (btnPushCandidate && !busyButtons.has(btnPushCandidate))
      btnPushCandidate.disabled = !sourceReady || !reviewedArtifact;
    const liveArtifactSummary = document.getElementById("live-artifact-summary");
    if (liveArtifactSummary) liveArtifactSummary.textContent = reviewedArtifact
      ? `Current reviewed artifact · ${currentArtifactCommandCount} commands · SHA-256 ${currentArtifactSha256 || "unavailable"}`
      : "No current reviewed artifact. Build and review a migration plan first.";
    const exportHint = document.querySelector(
      "#mode-download-form .export-hint",
    );
    if (exportHint) {
      const pendingRequired = currentDecisionSet.decisions.filter(
        (item) => item.mode === "REQUIRED" && item.review_state !== "CONFIRMED",
      ).length;
      const buildLabel = btnGenerateBundle?.querySelector("span:last-child");
      if (buildLabel) buildLabel.textContent = pendingRequired ? "Build partial plan" : "Build migration plan";
      const hintCopy = sourceReady && migrationPairSupported
        ? migrationPlanNeedsRebuild
          ? "Mappings changed. Rebuild the migration plan to update its commands."
          : pendingRequired
          ? `${pendingRequired} required decisions pending. Build a partial plan or finish the mappings.`
          : "Ready to build the migration plan."
        : sourceReady
          ? "This source and target pair is not supported for migration planning."
        : sourceFailed
          ? "Review the source error before generating a bundle."
          : hasInput
            ? "Reading your source configuration…"
            : "Add a source to get started.";
      const textNode = [...exportHint.childNodes].find(
        (node) => node.nodeType === Node.TEXT_NODE && node.textContent.trim(),
      );
      if (textNode) textNode.textContent = hintCopy;
      else exportHint.appendChild(document.createTextNode(hintCopy));
    }
    document
      .getElementById("workflow-step-source")
      ?.classList.toggle("complete", sourceReady);
    document
      .getElementById("workflow-step-source")
      ?.classList.toggle("current", !sourceReady);
    document
      .getElementById("workflow-step-review")
      ?.classList.toggle("current", sourceReady);
    if (targetVendorSelect)
      targetVendorSelect.disabled =
      activeMode === "live";
    reportContainer?.classList.toggle("hidden", activeMode !== "report" || (!currentReport && !currentPreviewId));
  }

  function setBusy(button, busy) {
    if (!button) return;
    if (busy) busyButtons.add(button);
    else busyButtons.delete(button);
    button.setAttribute("aria-busy", String(busy));
    button.disabled = busy;
    syncWorkspace();
  }

  function setPreviewStatus(message, state = "idle") {
    const status = document.getElementById("preview-status");
    if (status) {
      status.textContent = message;
      status.dataset.state = state;
      status.classList.toggle("hidden", !message);
    }
  }

  function resetPreview() {
    sourceRevision += 1;
    previewController?.abort();
    previewController = null;
    sourceReady = false;
    sourceFailed = false;
    currentPreviewId = null;
    currentDecisionSet = { decisions: [] };
    currentDecisionDocument = null;
    decisionEvidence = {};
    evidenceSummary = {};
    invalidateMigrationPlan();
    currentPlanItems = [];
    document.getElementById("migration-mapping")?.classList.add("hidden");
    document.getElementById("migration-plan")?.classList.add("hidden");
    btnDownloadBundle?.classList.add("hidden");
    btnDownloadSet?.classList.add("hidden");
    if (btnDownloadBundle) btnDownloadBundle.disabled = true;
    candidatePushed = false;
    candidateValidated = false;
    if (btnPushCandidate) btnPushCandidate.disabled = true;
    if (btnValidateCandidate) btnValidateCandidate.disabled = true;
    if (btnCommitCandidate) btnCommitCandidate.disabled = true;
    currentPolicies = [];
    currentReport = null;
    reportPage = 1;
    activeValidationGroup = "";
    activeReportSection = "overview";
    activeObjectSection = "addresses";
    if (reportSearch) reportSearch.value = "";
    if (reportScopeFilter) reportScopeFilter.value = "";
    if (reportSeverityFilter) reportSeverityFilter.value = "";
    reportContainer?.classList.add("hidden");
    optimizerPanel?.classList.add("hidden");
    [statTotalRules, statTotalObjects, statErrors, statWarnings].forEach((element) => {
      if (element) element.textContent = "0";
    });
    setPreviewStatus("");
    syncWorkspace();
  }

  async function readJson(response, fallback) {
    const data = await response.json().catch(() => null);
    if (!response.ok || !data || data.success === false) {
      throw new Error(data?.error || `${fallback} (HTTP ${response.status}).`);
    }
    return data;
  }

  // =========================================================================
  // 1. Mode Tab Switching (Package Export vs Direct Live Migration)
  // =========================================================================
  if (tabDownload) {
    tabDownload.addEventListener("click", () => switchMode("download"));
  }
  if (tabReport) tabReport.addEventListener("click", () => switchMode("report"));
  if (tabLive) {
    tabLive.addEventListener("click", () => switchMode("live"));
  }
  tabCollect?.addEventListener("click", () => switchMode("collect"));

  function switchMode(mode) {
    if (!MODE_COPY[mode]) return;
    if (mode === "live" && activeMode !== "live") {
      offlineTargetVendor = selectedTargetVendor;
      selectedTargetVendor = "palo_alto";
    } else if (mode !== "live" && activeMode === "live") {
      selectedTargetVendor = offlineTargetVendor;
    }
    if (targetVendorSelect) targetVendorSelect.value = selectedTargetVendor;
    if (mode === "collect" && activeMode !== "collect") clearSource();
    activeMode = mode;
    [
      [tabDownload, "download"],
      [tabReport, "report"],
      [tabLive, "live"],
      [tabCollect, "collect"],
    ].forEach(([tab, tabMode]) => {
      if (!tab) return;
      const selected = mode === tabMode;
      tab.classList.toggle("active", selected);
      tab.setAttribute("aria-selected", selected ? "true" : "false");
      tab.tabIndex = selected ? 0 : -1;
    });

    if (modeDownloadForm)
      modeDownloadForm.classList.toggle("hidden", mode !== "download");
    if (modeLiveForm) modeLiveForm.classList.toggle("hidden", mode !== "live");
    document.querySelector(".ingest-tabs")?.classList.toggle("hidden", mode === "collect");
    document.getElementById("ingest-file-container")?.classList.toggle("hidden", mode === "collect");
    liveContainer?.classList.toggle("hidden", mode !== "collect");
    if (mode === "collect") renderCollectionFields();
    const underDevelopment = mode === "live";
    developmentBanner?.classList.toggle("hidden", !underDevelopment);
    if (underDevelopment) developmentBanner.textContent = "Live migration is under development.";
    document.getElementById("workspace-grid")?.classList.toggle("hidden", underDevelopment);
    reportContainer?.classList.toggle("hidden", mode !== "report" || (!currentReport && !currentPreviewId));
    if (targetVendorGroup)
      targetVendorGroup.classList.toggle("hidden", ["report", "collect"].includes(mode));
    if (vendorSelectorGrid)
      vendorSelectorGrid.classList.toggle(
        "report-mode",
        ["report", "collect"].includes(mode),
      );
    setText("page-title", MODE_COPY[mode][0]);
    setText("page-description", MODE_COPY[mode][1]);
    document.getElementById("page-description")?.classList.toggle("hidden", !MODE_COPY[mode][1]);
    syncWorkspace();

    if (mode === "report") {
      renderReport();
      logToTerminal(`[MODE] Switched to ${VENDOR_CONFIGS[selectedSourceVendor]?.name || selectedSourceVendor} source report view.`, "term-system");
    } else if (mode === "download") {
      logToTerminal(
        "[MODE] Switched to migration planning.",
        "term-system",
      );
    } else if (mode === "collect") {
      logToTerminal("[MODE] Switched to Live Collection.", "term-system");
    } else if (mode === "live") {
      logToTerminal(
        "[MODE] Switched to Direct Live Migration Engine (Target Pre-Flight & Live Push).",
        "term-system",
      );
    }
  }

  function enableTabKeys(tabs) {
    const available = tabs.filter(Boolean);
    available.forEach((tab) =>
      tab.addEventListener("keydown", (event) => {
        if (
          ![
            "ArrowLeft",
            "ArrowRight",
            "ArrowUp",
            "ArrowDown",
            "Home",
            "End",
          ].includes(event.key)
        )
          return;
        event.preventDefault();
        const index = available.indexOf(tab);
        const next =
          event.key === "Home"
            ? 0
            : event.key === "End"
              ? available.length - 1
              : (index +
                  (["ArrowRight", "ArrowDown"].includes(event.key) ? 1 : -1) +
                  available.length) %
                available.length;
        if (available[next].disabled) return;
        available[next].focus();
        available[next].click();
      }),
    );
  }
  enableTabKeys([tabReport, tabCollect, tabDownload, tabLive]);
  enableTabKeys([btnIngestFile, btnIngestSnapshot]);

  // =========================================================================
  // 3. Vendor Selector Dropdowns
  // =========================================================================
  if (sourceVendorSelect) {
    selectedSourceVendor = sourceVendorSelect.value || "fortigate";
    sourceVendorSelect.addEventListener("change", (e) => {
      selectedSourceVendor = e.target.value;
      renderCollectionFields();
      currentRenderedArtifactId = null;
      clearSource();
      const vendorName =
        sourceVendorSelect.options[sourceVendorSelect.selectedIndex]?.text ||
        selectedSourceVendor;
      logToTerminal(
        `[VENDOR] Source vendor selected: ${vendorName}`,
        "term-system",
      );

      const cfg = VENDOR_CONFIGS[selectedSourceVendor];
      if (cfg) {
        if (dropzoneSubtext) dropzoneSubtext.innerHTML = cfg.dropText;
        if (fileInput) fileInput.accept = ingestMode === "snapshot" ? ".json" : cfg.fileAccept;
      }

      syncWorkspace();
    });
  }

  if (targetVendorSelect) {
    selectedTargetVendor = targetVendorSelect.value || "palo_alto";
    targetVendorSelect.addEventListener("change", (e) => {
      selectedTargetVendor = e.target.value;
      if (selectedTargetVendor !== "palo_alto") clearTargetEvidence();
      invalidateMigrationPlan();
      const targetName =
        targetVendorSelect.options[targetVendorSelect.selectedIndex]?.text ||
        selectedTargetVendor;
      logToTerminal(
        `[VENDOR] Target platform selected: ${targetName}`,
        "term-system",
      );
      syncWorkspace();
    });
  }

  // =========================================================================
  // 6. File Dropzone & Handling
  // =========================================================================
  if (dropzone && fileInput) {
    ["dragenter", "dragover", "dragleave", "drop"].forEach((evt) => {
      dropzone.addEventListener(evt, preventDefaults, false);
    });

    function preventDefaults(e) {
      e.preventDefault();
      e.stopPropagation();
    }

    ["dragenter", "dragover"].forEach((evt) => {
      dropzone.addEventListener(
        evt,
        () => dropzone.classList.add("dragover"),
        false,
      );
    });

    ["dragleave", "drop"].forEach((evt) => {
      dropzone.addEventListener(
        evt,
        () => dropzone.classList.remove("dragover"),
        false,
      );
    });

    dropzone.addEventListener("drop", (e) => {
      const dt = e.dataTransfer;
      if (dt?.files?.length > 1) {
        showToast(
          "info",
          "One configuration at a time",
          "Select a single configuration file to continue.",
        );
        return;
      }
      if (dt && dt.files && dt.files.length) handleFileSelect(dt.files[0]);
    });

    dropzone.addEventListener("click", (e) => {
      if (e.target !== fileInput && !e.target.closest("button")) {
        fileInput.click();
      }
    });
    dropzone.addEventListener("keydown", (event) => {
      if (
        (event.key === "Enter" || event.key === " ") &&
        event.target === dropzone
      ) {
        event.preventDefault();
        fileInput.click();
      }
    });

    fileInput.addEventListener("change", function () {
      if (this.files.length) handleFileSelect(this.files[0]);
    });
  }

  function handleFileSelect(file) {
    if (!file) return;
    if (!file.size) {
      showToast(
        "error",
        "Empty configuration",
        "This file is empty. Choose a configuration export that contains data.",
      );
      if (fileInput) fileInput.value = "";
      return;
    }
    clearSource();
    currentFile = file;
    currentRenderedArtifactId = null;

    if (selectedFilename) selectedFilename.textContent = file.name;
    if (selectedFilesize) selectedFilesize.textContent = formatBytes(file.size);

    if (dropzone) dropzone.classList.add("hidden");
    if (selectedFileCard) selectedFileCard.classList.remove("hidden");
    hideError();

    syncWorkspace();
    logToTerminal(
      `[FILE] Loaded '${file.name}' (${formatBytes(file.size)}). Ready for processing.`,
      "term-system",
    );

    if (ingestMode === "snapshot") importSnapshot(file);
    else fetchMigrationPreview();
  }

  if (btnRemoveFile) {
    btnRemoveFile.addEventListener("click", () => {
      clearSource();
      logToTerminal("[FILE] Configuration file unloaded.", "term-system");
    });
  }

  document.querySelectorAll("[data-report-section]").forEach((button) => button.addEventListener("click", () => {
    activeReportSection = button.dataset.reportSection;
    if (activeReportSection !== "validation" && reportSeverityFilter) reportSeverityFilter.value = "";
    reportPage = 1;
    activeValidationGroup = "";
    renderReport();
  }));
  document.querySelectorAll("[data-object-section]").forEach((button) => button.addEventListener("click", () => {
    activeObjectSection = button.dataset.objectSection;
    reportPage = 1;
    document.querySelectorAll("[data-object-section]").forEach((item) => item.classList.toggle("active", item === button));
    renderReportTable();
  }));
  function updateReportFilters() {
    reportPage = 1;
    renderReportTable();
    renderValidationSummary();
  }
  reportSearch?.addEventListener("input", updateReportFilters);
  reportScopeFilter?.addEventListener("change", updateReportFilters);
  reportSeverityFilter?.addEventListener("change", updateReportFilters);
  reportPagePrevious?.addEventListener("click", () => { reportPage = Math.max(1, reportPage - 1); renderReportTable(); });
  reportPageNext?.addEventListener("click", () => { reportPage += 1; renderReportTable(); });
  validationSummary?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-validation-group]");
    if (!button) return;
    activeValidationGroup = activeValidationGroup === button.dataset.validationGroup ? "" : button.dataset.validationGroup;
    reportPage = 1;
    renderValidationSummary();
    renderReportTable();
  });
  validationFilterClear?.addEventListener("click", () => {
    activeValidationGroup = "";
    reportPage = 1;
    renderValidationSummary();
    renderReportTable();
  });
  reportDetailClose?.addEventListener("click", () => closeReportDetailModal());
  reportDetailModal?.addEventListener("click", (event) => {
    if (event.target === reportDetailModal) closeReportDetailModal();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !reportDetailModal?.classList.contains("hidden")) closeReportDetailModal();
  });

  function clearSource() {
    currentFile = null;
    if (fileInput) fileInput.value = "";
    selectedFileCard?.classList.add("hidden");
    dropzone?.classList.remove("hidden");
    hideError();
    resetPreview();
  }

  // =========================================================================
  // 7. Migration Intelligence Preview
  // =========================================================================
  async function fetchMigrationPreview() {
    if (!currentFile) return;
    previewController?.abort();
    const controller = new AbortController();
    previewController = controller;
    const requestRevision = sourceRevision;
    sourceReady = false;
    sourceFailed = false;
    currentPreviewId = null;
    setPreviewStatus(
      "Reading your configuration and preparing the inventory…",
      "loading",
    );
    syncWorkspace();

    const formData = new FormData();
    if (currentFile) {
      formData.append("file", currentFile);
    }
    formData.append("source_vendor", selectedSourceVendor);

    try {
      const resp = await fetch("/api/preview", {
        method: "POST",
        body: formData,
        signal: controller.signal,
      });
      const data = await readJson(resp, "Could not read this configuration");
      if (requestRevision !== sourceRevision) return;
      currentPreviewId = data.preview_id || null;
      await loadMigrationReview(currentPreviewId);
      if (requestRevision !== sourceRevision) return;
      const stats = data.stats || data.summary || {};
      const objects = stats.objects || stats;
      const severityCounts = stats.validation?.severity_counts || {};
      const errorCount = count(severityCounts.error);
      const warningCount = count(severityCounts.warning);
      if (statTotalRules) statTotalRules.textContent = count(objects.policies);
      if (statTotalObjects)
        statTotalObjects.textContent =
          ["addresses", "address_groups", "services", "service_groups"]
            .reduce((total, key) => total + count(objects[key]), 0);
      if (statErrors) statErrors.textContent = errorCount;
      if (statWarnings) statWarnings.textContent = warningCount;
      currentPolicies = Array.isArray(data.policies) ? data.policies : [];
      currentReport = data;
      reportPage = 1;
      activeValidationGroup = "";
      renderReport();
      sourceReady = true;
      const itemCount = Object.values(objects).reduce(
        (total, value) => total + count(value),
        0,
      );
      setPreviewStatus(
        itemCount
          ? (errorCount || warningCount
              ? `Parsed · ${errorCount} errors · ${warningCount} warnings`
              : "Parsed successfully.")
          : "No supported objects were found. Review the source file and extraction warnings in the Excel workbook.",
        itemCount ? "ready" : "empty",
      );
    } catch (err) {
      if (err.name === "AbortError" || requestRevision !== sourceRevision)
        return;
      sourceReady = false;
      sourceFailed = true;
      setPreviewStatus(err.message, "error");
    } finally {
      if (requestRevision === sourceRevision) {
        previewController = null;
        syncWorkspace();
      }
    }
  }

  // =========================================================================
  // 8. Mode A: Export Target Migration Bundle (.zip)
  // =========================================================================
  function invalidateMigrationPlan(rebuilding = false) {
    markAIAssistStale();
    if (rebuilding) migrationPlanNeedsRebuild = false;
    else if (currentRenderedArtifactId) migrationPlanNeedsRebuild = true;
    migrationPlanRevision += 1;
    currentRenderedArtifactId = null;
    currentArtifactCommandCount = 0;
    currentArtifactSha256 = null;
    candidatePushed = false;
    candidateValidated = false;
    btnDownloadBundle?.classList.add("hidden");
    btnDownloadSet?.classList.add("hidden");
    if (btnDownloadBundle) btnDownloadBundle.disabled = true;
    if (btnDownloadSet) btnDownloadSet.disabled = true;
    document.getElementById("migration-plan")?.classList.add("hidden");
    if (btnValidateCandidate) btnValidateCandidate.disabled = true;
    if (btnCommitCandidate) btnCommitCandidate.disabled = true;
    const commandPreview = document.getElementById("migration-command-preview");
    const commandSummary = document.getElementById("migration-command-summary");
    const copyCommands = document.getElementById("migration-copy-commands");
    if (commandPreview) commandPreview.textContent = "";
    if (commandSummary) commandSummary.textContent = "";
    if (copyCommands) copyCommands.disabled = true;
    syncWorkspace();
  }

  function markAIAssistStale() {
    const hadResults = aiProposals.length || aiExplanation;
    aiAnalysisRevision += 1;
    aiReviewReady = false;
    aiProposals = [];
    aiExplanation = null;
    const status = document.getElementById("migration-ai-status");
    if (status && hadResults) status.textContent = "Review state changed. AI analysis will refresh after deterministic review.";
    const results = document.getElementById("migration-ai-results");
    results?.replaceChildren();
  }

  async function refreshAIAssistStatus() {
    const panel = document.getElementById("migration-ai-review");
    if (!panel) return;
    const status = document.getElementById("migration-ai-status");
    try {
      const response = await fetch("/api/migration/ai/status");
      const result = await readJson(response, "AI status unavailable");
      aiAssistAvailable = Boolean(result.available);
      const local = result.local;
      const install = document.getElementById("migration-ai-install");
      const remove = document.getElementById("migration-ai-remove");
      document.getElementById("migration-ai-local-details")?.classList.toggle("hidden", result.provider !== "local");
      if (result.provider === "local" && !local?.runtime_available) {
        status.textContent = "The pinned local AI runtime is not installed for this platform.";
        install?.classList.add("hidden");
        remove?.classList.add("hidden");
      } else if (local?.state === "DOWNLOADING" || local?.state === "VERIFYING") {
        const amount = `${(local.downloaded_bytes / 1e9).toFixed(2)} GB / ${(local.download_bytes / 1e9).toFixed(2)} GB`;
        status.textContent = `${local.state === "VERIFYING" ? "Verifying" : "Downloading"} Local AI model · ${amount}`;
        install?.classList.add("hidden");
        remove?.classList.add("hidden");
        setTimeout(refreshAIAssistStatus, 1000);
      } else if (result.provider === "local" && local?.state === "FAILED" && local?.installed) {
        status.textContent = "Local AI runtime failed. AI analysis will retry when review is ready.";
        install?.classList.add("hidden");
        remove?.classList.remove("hidden");
      } else if (result.provider === "local" && local?.installed) {
        status.textContent = "Local AI is ready. Review evidence stays on this computer.";
        install?.classList.add("hidden");
        remove?.classList.remove("hidden");
      } else if (result.provider === "local") {
        status.textContent = local?.state === "RUNTIME_REQUIRED"
          ? "The pinned local AI runtime is not installed for this platform."
          : "Enable local AI by downloading the model once. Deterministic review remains available.";
        install?.classList.toggle("hidden", !local?.runtime_available);
        remove?.classList.add("hidden");
      } else if (!result.available) {
        status.textContent = "AI-assisted review is not configured.";
      } else {
        status.textContent = "AI can organize unresolved mappings using sanitized review evidence.";
      }
      document.getElementById("migration-ai-refresh").disabled = !aiAssistAvailable;
      document.querySelectorAll("[data-ai-explain]").forEach(button => { button.disabled = !aiAssistAvailable; });
      maybeRunAIAssistedAnalysis();
    } catch (_) {
      aiAssistAvailable = false;
      status.textContent = "AI-assisted review is not configured.";
      document.getElementById("migration-ai-refresh").disabled = true;
      document.querySelectorAll("[data-ai-explain]").forEach(button => { button.disabled = true; });
    }
  }

  function focusProposalMapping(proposal) {
    const editor = document.getElementById("advanced-decision-view");
    if (editor) editor.open = true;
    const key = proposal.decision_keys?.[0];
    const input = key ? document.querySelector(`.decision-value[data-decision-key="${CSS.escape(key)}"], .review-work-value[data-decision-key="${CSS.escape(key)}"]`) : null;
    (input || editor)?.scrollIntoView({ behavior: "smooth", block: "center" });
    input?.focus();
  }

  document.getElementById("migration-ai-install")?.addEventListener("click", async event => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const response = await fetch("/api/ai/local/install", { method: "POST" });
      await readJson(response, "Could not install the local AI model");
      await refreshAIAssistStatus();
    } catch (error) {
      document.getElementById("migration-ai-status").textContent = error.message;
    } finally {
      button.disabled = false;
    }
  });

  document.getElementById("migration-ai-remove")?.addEventListener("click", async event => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const response = await fetch("/api/ai/local/remove", { method: "POST" });
      await readJson(response, "Could not remove the local AI model");
      await refreshAIAssistStatus();
    } catch (error) {
      document.getElementById("migration-ai-status").textContent = error.message;
    } finally {
      button.disabled = false;
    }
  });

  function renderAIAssistProposals() {
    const container = document.getElementById("migration-ai-results");
    if (!container) return;
    container.replaceChildren();
    for (const proposal of aiProposals) {
      const card = document.createElement("article"); card.className = "review-work-card";
      const title = document.createElement("h4"); title.textContent = proposal.title;
      const question = document.createElement("p"); question.textContent = proposal.summary;
      card.append(title, question);
      if (proposal.question) { const prompt = document.createElement("p"); prompt.textContent = proposal.question; card.append(prompt); }
      for (const fact of proposal.evidence || []) { const evidence = document.createElement("p"); evidence.textContent = `Evidence: ${fact}`; card.append(evidence); }
      if (proposal.kind === "CANDIDATE_COMPARISON") {
        for (const item of proposal.comparisons || []) {
          const row = document.createElement("section");
          const name = document.createElement("strong"); name.textContent = item.candidate_value; row.append(name);
          const list = document.createElement("ul");
          for (const fact of [...item.evidence, ...item.limitations]) { const li = document.createElement("li"); li.textContent = fact; list.append(li); }
          row.append(list); card.append(row);
        }
        const choose = document.createElement("button"); choose.type = "button"; choose.className = "btn btn-secondary btn-sm";
        choose.textContent = "Choose a mapping"; choose.addEventListener("click", () => focusProposalMapping(proposal)); card.append(choose);
      }
      for (const choice of proposal.choices || []) {
        const button = document.createElement("button"); button.type = "button"; button.className = "btn btn-secondary btn-sm";
        button.textContent = proposal.kind === "MAPPING_RECOMMENDATION" ? "Accept recommendation" : `Use ${choice.label}`;
        button.addEventListener("click", async () => {
          button.disabled = true;
          try {
            const response = await fetch("/api/migration/ai/confirm", { method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ preview_id: currentPreviewId, decision_document: currentDecisionPayload(),
                proposal_id: proposal.proposal_id, choice_index: proposal.choices.indexOf(choice),
                ...(currentTargetPreviewId ? { target_preview_id: currentTargetPreviewId, target_device: selectedTargetDevice } : {}) }) });
            const result = await readJson(response, "Could not confirm AI-assisted choice");
            aiProposals = []; aiExplanation = null;
            await loadMigrationReview(currentPreviewId, result.decision_document);
            invalidateMigrationPlan();
          } catch (error) {
            if (error.message.includes("stale")) markAIAssistStale();
            else document.getElementById("migration-ai-status").textContent = "AI assistance is temporarily unavailable. Deterministic migration review is unchanged.";
            button.disabled = false;
          }
        });
        card.append(button);
      }
      if (proposal.kind !== "CANDIDATE_COMPARISON") {
        const manual = document.createElement("button"); manual.type = "button"; manual.className = "btn btn-secondary btn-sm";
        manual.textContent = "Choose another"; manual.addEventListener("click", () => focusProposalMapping(proposal)); card.append(manual);
      }
      const details = document.createElement("details");
      const summary = document.createElement("summary"); summary.textContent = "Why this result?";
      const list = document.createElement("ul");
      for (const fact of [
        ...(proposal.rationale || []).map(item => `AI rationale: ${item}`),
        ...(proposal.missing_information || []).map(item => `Missing: ${item}`),
        ...(proposal.limitations || []).map(item => `AI limitation: ${item}`),
      ]) {
        const row = document.createElement("li"); row.textContent = fact; list.append(row);
      }
      details.append(summary, list); card.append(details);
      if (proposal.affected_count) {
        const impact = document.createElement("p"); impact.textContent = `Affected: ${proposal.affected_count}`; card.append(impact);
      }
      const advisory = document.createElement("p"); advisory.textContent = "AI-assisted suggestion. Nothing changes until you confirm.";
      card.append(advisory); container.append(card);
    }
    if (aiExplanation) {
      const card = document.createElement("article"); card.className = "review-work-card";
      const heading = document.createElement("h4"); heading.textContent = "AI-assisted comparison"; card.append(heading);
      const title = document.createElement("p"); title.textContent = aiExplanation.summary; card.append(title);
      for (const item of aiExplanation.comparisons || []) {
        const row = document.createElement("section");
        const name = document.createElement("strong"); name.textContent = item.candidate_value; row.append(name);
        const list = document.createElement("ul");
        for (const fact of [...item.evidence, ...item.limitations]) { const li = document.createElement("li"); li.textContent = fact; list.append(li); }
        row.append(list); card.append(row);
      }
      const note = document.createElement("p"); note.textContent = "This explanation does not change the mapping."; card.append(note);
      container.append(card);
    }
  }

  async function maybeRunAIAssistedAnalysis() {
    if (!aiReviewReady || !currentPreviewId || !aiAssistAvailable || aiAnalysisInFlight
        || aiAnalysisCompleteRevision === aiAnalysisRevision) return;
    const revision = aiAnalysisRevision;
    const previewId = currentPreviewId;
    const requestBody = { preview_id: previewId, decision_document: currentDecisionPayload(),
      ...(currentTargetPreviewId ? { target_preview_id: currentTargetPreviewId, target_device: selectedTargetDevice } : {}) };
    const status = document.getElementById("migration-ai-status");
    aiAnalysisInFlight = true;
    aiProposals = []; aiExplanation = null; renderAIAssistProposals();
    status.textContent = "Analyzing candidate-backed review groups…";
    let cursor = 0;
    let insufficient = 0;
    try {
      do {
        const response = await fetch("/api/migration/ai/analyze", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ...requestBody, cursor }) });
        const result = await readJson(response, "AI assistance is temporarily unavailable");
        if (revision !== aiAnalysisRevision || previewId !== currentPreviewId) return;
        aiProposals.push(...(result.proposals || [])); aiExplanation = null; renderAIAssistProposals();
        insufficient = result.insufficient_evidence || 0;
        const next = result.next_cursor;
        if (next === null || next === undefined) break;
        cursor = next;
        status.textContent = `Analyzed ${cursor} of ${result.candidate_backed_groups} candidate-backed groups…`;
      } while (true);
      if (revision !== aiAnalysisRevision) return;
      const countKind = kind => aiProposals.filter(item => item.kind === kind).length;
      status.textContent = `${countKind("MAPPING_RECOMMENDATION")} recommended mappings · ${countKind("CANDIDATE_COMPARISON")} candidate comparisons · ${countKind("ARCHITECTURE_QUESTION")} engineer decisions · ${insufficient} insufficient target evidence.`;
      aiAnalysisCompleteRevision = revision;
    } catch (_) {
      if (revision === aiAnalysisRevision) {
        status.textContent = "AI assistance is temporarily unavailable. Deterministic migration review is unchanged.";
        aiAnalysisCompleteRevision = revision;
      }
    } finally {
      aiAnalysisInFlight = false;
      if (aiReviewReady && aiAnalysisCompleteRevision !== aiAnalysisRevision) maybeRunAIAssistedAnalysis();
    }
  }
  document.getElementById("migration-ai-refresh")?.addEventListener("click", () => {
    aiAnalysisCompleteRevision = -1;
    maybeRunAIAssistedAnalysis();
  });
  document.addEventListener("input", event => {
    if (event.target.matches?.(".decision-value, .review-work-value")) markAIAssistStale();
  });
  refreshAIAssistStatus();

  async function loadMigrationReview(previewId = currentPreviewId, previousDocument = null) {
    markAIAssistStale();
    const panel = document.getElementById("migration-mapping");
    if (selectedSourceVendor !== "fortigate" || !previewId) {
      currentDecisionSet = { decisions: [] };
      currentDecisionDocument = null;
      decisionContext = {};
      decisionCandidates = {};
      reviewSummary = {};
      reviewGroups = [];
      autoDecisionResults = {};
      architectureQuestions = [];
      panel?.classList.add("hidden");
      aiReviewReady = true;
      return;
    }
    const payload = { preview_id: previewId };
    if (previousDocument) payload.decision_document = previousDocument;
    if (currentTargetPreviewId) {
      payload.target_preview_id = currentTargetPreviewId;
      if (selectedTargetDevice) payload.target_device = selectedTargetDevice;
    }
    const response = await fetch("/api/migration/requirements", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    });
    const result = await readJson(response, "Could not load target mapping requirements");
    if (previewId !== currentPreviewId) return;
    currentDecisionSet = result.decisions;
    currentDecisionDocument = result.decision_document;
    decisionContext = result.decision_context || {};
    decisionCandidates = result.decision_candidates || {};
    reviewSummary = result.review_summary || {};
    reviewGroups = result.review_groups || [];
    autoDecisionResults = result.auto_decisions || {};
    architectureQuestions = result.architecture_questions || [];
    ruleSuggestions = result.rule_suggestions || [];
    targetWarnings = result.target_warnings || {};
    targetFindings = result.target_findings || [];
    decisionEvidence = result.decision_evidence || {};
    evidenceSummary = result.evidence_summary || {};
    targetEvidence = result.target_evidence || null;
    currentRecommendations = result.recommendations || [];
    if (targetDeviceSelect) {
      const devices = result.target_devices || [];
      const metadata = Object.fromEntries((result.target_device_metadata || []).map(item => [item.id, item]));
      targetDeviceSelect.replaceChildren(new Option("Select a device", ""), ...devices.map(name => {
        const item = metadata[name];
        const label = item ? `${item.name} · ${item.interfaces} interfaces · ${item.vsys} VSYS` : name;
        return new Option(label, name);
      }));
      selectedTargetDevice = result.target_device || "";
      targetDeviceSelect.value = selectedTargetDevice;
      targetDeviceGroup?.classList.toggle("hidden", devices.length < 2);
      if (currentTargetPreviewId && targetConfigStatus) {
        targetConfigStatus.textContent = devices.length > 1 && !selectedTargetDevice
          ? "Select the target device to enable target-backed suggestions."
          : devices.length === 0
            ? "No device-scoped PAN-OS interfaces found. Source-only suggestions remain available."
            : `Target evidence loaded for ${selectedTargetDevice}. Review suggestions before confirming.`;
      }
    }
    const optionalPanel = document.getElementById("optional-mappings");
    const optionalList = document.getElementById("optional-mapping-list");
    if (optionalPanel && optionalList) {
      optionalList.replaceChildren(...(result.requirements.optional || []).map(item => {
        const li = document.createElement("li");
        li.textContent = `${item.source_vdom} · ${item.kind} · ${item.source_name}`;
        return li;
      }));
      optionalPanel.classList.toggle("hidden", !(result.requirements.optional || []).length);
    }
    renderDecisionTable();
    renderMigrationReviewWorkflow();
    renderRecommendations();
    panel?.classList.toggle("hidden", !sourceReady || selectedTargetVendor !== "palo_alto");
    updateMappingCompletion();
    aiReviewReady = true;
    maybeRunAIAssistedAnalysis();
  }

  function currentDecisionPayload() {
    return { ...(currentDecisionDocument || {}), decisions: currentDecisionSet.decisions };
  }

  async function refreshMigrationReviewFromCurrentDecisions() {
    if (!currentPreviewId) return;
    const previous = currentDecisionPayload();
    automationRunSummary = null;
    invalidateMigrationPlan();
    await loadMigrationReview(currentPreviewId, previous);
  }

  function clearTargetEvidence() {
    automationRunSummary = null;
    targetRevision += 1;
    currentTargetPreviewId = null;
    selectedTargetDevice = "";
    targetWarnings = {};
    targetFindings = [];
    targetPlanFindings = [];
    decisionEvidence = {};
    decisionContext = {};
    decisionCandidates = {};
    evidenceSummary = {};
    targetEvidence = null;
    currentRecommendations = [];
    if (targetConfigFile) targetConfigFile.value = "";
    targetConfigRemove?.classList.add("hidden");
    targetDeviceGroup?.classList.add("hidden");
    if (targetConfigStatus) targetConfigStatus.textContent = "Upload target XML for evidence-based suggestions. Source-only suggestions remain available.";
    invalidateMigrationPlan();
  }

  targetConfigFile?.addEventListener("change", async () => {
    const file = targetConfigFile.files?.[0];
    if (!file) return;
    const previous = currentDecisionPayload();
    clearTargetEvidence();
    const revision = targetRevision;
    if (targetConfigStatus) targetConfigStatus.textContent = "Reading target PAN-OS XML…";
    try {
      const body = new FormData();
      body.append("source_vendor", "palo_alto");
      body.append("file", file);
      const response = await fetch("/api/preview", { method: "POST", body });
      const result = await readJson(response, "Could not read target PAN-OS XML");
      if (revision !== targetRevision) return;
      currentTargetPreviewId = result.preview_id;
      targetConfigRemove?.classList.remove("hidden");
      await loadMigrationReview(currentPreviewId, previous);
      invalidateMigrationPlan();
    } catch (error) {
      if (revision === targetRevision && targetConfigStatus) targetConfigStatus.textContent = error.message;
    }
  });
  targetConfigRemove?.addEventListener("click", async () => {
    const previous = currentDecisionPayload();
    clearTargetEvidence();
    if (currentPreviewId) await loadMigrationReview(currentPreviewId, previous);
  });
  targetDeviceSelect?.addEventListener("change", async () => {
    const previous = currentDecisionPayload();
    selectedTargetDevice = targetDeviceSelect.value;
    invalidateMigrationPlan();
    await loadMigrationReview(currentPreviewId, previous);
  });

  function decisionIsResolved(decision) {
    return decision.mode === "AUTO" || decision.review_state === "CONFIRMED";
  }

  function decisionDisplayValue(decision) {
    return decision.value ?? (decision.mode === "SUGGESTED" && decision.review_state === "PENDING" ? decision.suggested_value : "") ?? "";
  }

  function renderMigrationReviewWorkflow() {
    const summaryNode = document.getElementById("review-summary");
    const container = document.getElementById("migration-review-groups");
    if (!summaryNode || !container) return;
    const summaryItems = [
      ["verified", "Verified"], ["derived", "Derived"],
      ["choose_candidate", "Choices"], ["needs_input", "Manual"], ["conflicts", "Conflicts"],
    ];
    const safeCount = status => Object.values(autoDecisionResults).filter(item => item.status === status).length;
    const safeKeys = Object.entries(autoDecisionResults).filter(([, item]) => ["VERIFIED", "DERIVED"].includes(item.status)).map(([key]) => key);
    reviewSummary.verified = safeCount("VERIFIED");
    reviewSummary.derived = safeCount("DERIVED");
    const approveSafe = document.getElementById("decision-approve-safe");
    if (approveSafe) {
      approveSafe.textContent = `Approve ${safeKeys.length} verified / derived mappings`;
      approveSafe.disabled = safeKeys.length === 0;
    }
    summaryNode.replaceChildren(...summaryItems.map(([key, label]) => {
      const card = document.createElement("div"); card.className = "review-summary-card";
      const count = document.createElement("strong"); count.textContent = String(reviewSummary[key] || 0);
      const text = document.createElement("span"); text.textContent = label;
      card.append(count, text); return card;
    }));
    const automationResult = document.getElementById("automation-result");
    if (automationResult && automationRunSummary) {
      automationResult.textContent = `Automation result · ${automationRunSummary.resolved} resolved by enabled rules · ${reviewSummary.verified} verified against target · ${reviewSummary.choose_candidate || 0} choices required · ${reviewSummary.needs_input || 0} manual design items · ${reviewSummary.conflicts || 0} conflicts`;
    }
    const tabCounts = {
      READY_TO_CONFIRM: reviewGroups.filter(group => group.queue === "READY_TO_CONFIRM").length,
      CHOOSE_CANDIDATE: reviewGroups.filter(group => group.queue === "CHOOSE_CANDIDATE").length,
      NEEDS_INPUT: reviewGroups.filter(group => group.queue === "NEEDS_INPUT").length,
      CONFLICT: reviewGroups.filter(group => group.queue === "CONFLICT").length,
      COMPLETE: reviewGroups.filter(group => group.queue === "COMPLETE").length,
    };
    document.querySelectorAll("[data-review-queue]").forEach(tab => {
      const queue = tab.dataset.reviewQueue;
      tab.setAttribute("aria-selected", String(queue === activeReviewQueue));
      const count = tab.querySelector("span"); if (count) count.textContent = String(tabCounts[queue] || 0);
    });
    let visible = reviewGroups.filter(group => group.queue === activeReviewQueue);
    if (!visible.length) {
      const empty = document.createElement("p"); empty.textContent = reviewGroups.length ? "Nothing in this queue." : "No migration decisions are required.";
      container.replaceChildren(empty); return;
    }
    const fragment = document.createDocumentFragment();
    for (const question of architectureQuestions) {
      const card = document.createElement("article"); card.className = "review-work-card architecture-question";
      const title = document.createElement("h3");
      title.textContent = question.type === "AGGREGATE_MAPPING" ? `Which PAN aggregate replaces ${question.source_name}?`
        : question.type === "VDOM_CONTEXT" ? `Where should ${question.source_name} VDOM live?`
          : `Which PAN zone replaces ${question.source_name}?`;
      card.append(title);
      if (question.type === "AGGREGATE_MAPPING") {
        const affected = document.createElement("p"); affected.textContent = `Will re-evaluate ${question.affected_count} VLAN mappings when you confirm this parent.`;
        card.append(affected);
      }
      const pendingNotice = document.createElement("p");
      pendingNotice.className = "review-work-suggestion";
      pendingNotice.textContent = "Edited mapping · Confirm to save and refresh the review queues.";
      pendingNotice.hidden = true;
      card.append(pendingNotice);
      const choices = question.type === "VDOM_CONTEXT"
        ? question.fields.flatMap(field => field.suggested_value ? [{ key: field.key, value: `${field.target_field === "vsys" ? "VSYS" : "VR"}: ${field.suggested_value}`, target: field.suggested_value }] : [])
        : (question.candidates || []).map(value => ({ key: question.decision_key, value: question.type === "ZONE_MAPPING" ? value : `Use ${value}`, target: value }));
      for (const option of choices) {
        const button = document.createElement("button"); button.type = "button"; button.className = "btn btn-secondary btn-sm";
        button.textContent = option.value.startsWith("VSYS:") || option.value.startsWith("VR:") || question.type === "ZONE_MAPPING" ? option.value : `Use ${option.value}`;
        button.addEventListener("click", () => {
          const input = document.querySelector(`.review-work-value[data-decision-key="${CSS.escape(option.key)}"]`);
          const decision = currentDecisionSet.decisions.find(item => item.key === option.key);
          if (input && decision) {
            input.value = option.target; decision.value = option.target;
            if (decision.mode === "AUTO") decision.mode = "REQUIRED";
            decision.review_state = "PENDING"; pendingNotice.hidden = false;
            updateMappingCompletion(); invalidateMigrationPlan();
          }
        });
        card.append(button);
      }
      fragment.append(card);
    }
    for (const suggestion of ruleSuggestions) {
      const card = document.createElement("article"); card.className = "review-work-card architecture-question";
      const title = document.createElement("h3");
      title.textContent = `Apply ${suggestion.target_zone} to ${suggestion.affected.length} other interfaces in ${suggestion.source_zone}?`;
      const facts = document.createElement("p");
      facts.textContent = `Based on ${suggestion.confirmed_count} engineer-confirmed mappings for explicit zone members.`;
      const review = document.createElement("details");
      const summary = document.createElement("summary"); summary.textContent = "Review affected mappings";
      const list = document.createElement("ul");
      suggestion.affected.forEach(name => { const item = document.createElement("li"); item.textContent = name; list.append(item); });
      review.append(summary, list);
      const apply = document.createElement("button"); apply.type = "button"; apply.className = "btn btn-secondary";
      apply.textContent = `Apply to ${suggestion.affected.length} mappings`;
      apply.addEventListener("click", async () => {
        apply.disabled = true;
        try {
          const response = await fetch("/api/migration/rules/apply", { method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ preview_id: currentPreviewId, decision_document: currentDecisionPayload(),
              rule_type: suggestion.rule_type, source_vdom: suggestion.source_vdom,
              source_zone: suggestion.source_zone, value: suggestion.target_zone, apply_to: suggestion.apply_to }) });
          const result = await readJson(response, "Could not apply repeated engineer pattern");
          await loadMigrationReview(currentPreviewId, result.decision_document);
          invalidateMigrationPlan();
        } catch (error) { showError(error.message); apply.disabled = false; }
      });
      card.append(title, facts, review, apply); fragment.append(card);
    }
    const decisionByKey = new Map(currentDecisionSet.decisions.map(item => [item.key, item]));
    const labels = { target_interface: "Target interface", target_zone: "Target zone", vsys: "Target VSYS", virtual_router: "Target virtual router" };
    const statusLabels = { READY_TO_CONFIRM: "Suggestion ready", CHOOSE_CANDIDATE: "Choose a match", NEEDS_INPUT: "Manual decision", CONFLICT: "Conflict", COMPLETE: "Complete" };
    for (const group of visible) {
      const card = document.createElement("article"); card.className = `review-work-card queue-${group.queue.toLowerCase()}`;
      const heading = document.createElement("div"); heading.className = "review-work-heading";
      const title = document.createElement("h3"); title.textContent = group.source_kind === "vdom" ? `${group.source_name} VDOM` : group.source_name;
      const subtitle = document.createElement("p");
      const sourceType = group.source_evidence?.source_type;
      subtitle.textContent = [group.source_vdom, group.source_kind === "interface" ? (sourceType || "Interface") : group.source_kind]
        .filter(Boolean).join(" · ");
      const badge = document.createElement("span"); badge.className = "review-work-badge"; badge.textContent = statusLabels[group.queue] || "Review";
      heading.append(title, subtitle, badge); card.append(heading);
      for (const view of group.decisions) {
        const decision = decisionByKey.get(view.key) || view;
        if (decision.mode === "UNSUPPORTED") continue;
        const field = document.createElement("div"); field.className = "review-work-field";
        const label = document.createElement("label"); label.textContent = labels[decision.target_field] || decision.target_field;
        const input = document.createElement("input"); input.type = "text"; input.className = "review-work-value";
        input.dataset.decisionKey = decision.key; input.value = decisionDisplayValue(decision);
        const pendingNotice = document.createElement("p");
        pendingNotice.className = "review-work-suggestion";
        pendingNotice.dataset.pendingReviewNotice = "true";
        pendingNotice.textContent = "Edited mapping · Confirm to save and refresh the review queues.";
        pendingNotice.hidden = true;
        input.placeholder = decision.suggested_value ? `Suggested: ${decision.suggested_value}` : "Enter mapping";
        input.setAttribute("aria-label", `${labels[decision.target_field] || decision.target_field} for ${group.source_name}`);
        input.addEventListener("input", () => {
          decision.value = input.value.trim() || null;
          if (decision.mode === "AUTO") decision.mode = "REQUIRED";
          decision.review_state = "PENDING";
          pendingNotice.hidden = false;
          updateMappingCompletion();
          invalidateMigrationPlan();
        });
        field.append(label, input, pendingNotice);
        if (decision.suggested_value && decision.review_state !== "CONFIRMED") {
          const suggestion = document.createElement("p"); suggestion.className = "review-work-suggestion";
          suggestion.textContent = `Suggested: ${decision.suggested_value}`; field.append(suggestion);
        } else if (!decision.value && decision.target_field === "target_interface") {
          const noSuggestion = document.createElement("p"); noSuggestion.className = "review-work-suggestion";
          noSuggestion.textContent = "No safe suggestion"; field.append(noSuggestion);
        }
        const candidates = group.candidates?.[decision.key] || [];
        if (candidates.length) {
          const matches = document.createElement("div"); matches.className = "review-work-candidates";
          candidates.forEach(candidate => {
            const row = document.createElement("div"); row.className = "review-work-candidate";
            const recommended = candidate.class === "STRONG";
            const description = document.createElement("span");
            description.textContent = `${recommended ? "Recommended" : "Other possible match"}: ${candidate.value}`;
            const use = document.createElement("button"); use.type = "button"; use.className = "btn btn-secondary btn-sm"; use.textContent = "Use";
            use.addEventListener("click", () => {
              input.value = candidate.value; decision.value = candidate.value;
              if (decision.mode === "AUTO") decision.mode = "REQUIRED";
              decision.review_state = "PENDING"; pendingNotice.hidden = false;
              updateMappingCompletion(); invalidateMigrationPlan();
            });
            const why = document.createElement("details");
            const whySummary = document.createElement("summary"); whySummary.textContent = "Why?"; why.append(whySummary);
            const evidence = document.createElement("ul");
            for (const fact of [...(candidate.strong_evidence || []), ...(candidate.supporting_evidence || []), ...(candidate.contradicting_evidence || [])]) {
              const entry = document.createElement("li"); entry.textContent = fact; evidence.append(entry);
            }
            if (candidate.target_scope) { const scope = document.createElement("li"); scope.textContent = `Target scope: ${candidate.target_scope}`; evidence.append(scope); }
            why.append(evidence); row.append(description, use, why); matches.append(row);
          });
          field.append(matches);
        }
        const findings = targetFindings.filter(item => item.decision_key === decision.key);
        const warningText = [targetWarnings[decision.key], ...findings.map(item => item.message)].filter(Boolean);
        if (warningText.length) {
          const notes = document.createElement("ul"); notes.className = "review-work-notes";
          warningText.forEach(message => { const note = document.createElement("li"); note.textContent = message; notes.append(note); });
          field.append(notes);
        }
        card.append(field);
      }
      const summary = document.createElement("div"); summary.className = "review-work-impact";
      if (group.affected_count) summary.append(document.createTextNode(`${group.affected_count} affected objects`));
      if (group.dependent_decision_count) {
        const dependents = document.createElement("p");
        dependents.textContent = `${group.dependent_decision_count} dependent mappings will be re-evaluated`;
        summary.append(dependents);
      }
      if (group.next_action) { const next = document.createElement("p"); next.textContent = `Next action: ${group.next_action}`; summary.append(next); }
      if (group.source_evidence && Object.keys(group.source_evidence).length) {
        const facts = document.createElement("details"); const detailsLabel = document.createElement("summary"); detailsLabel.textContent = "Source facts"; facts.append(detailsLabel);
        const list = document.createElement("ul");
        Object.entries(group.source_evidence).forEach(([name, value]) => {
          const display = Array.isArray(value) ? value.length ? value.join(", ") : "(explicitly empty)" : value;
          const item = document.createElement("li"); item.textContent = `${name.replace(/^source_/, "").replaceAll("_", " ")}: ${display}`; list.append(item);
        });
        facts.append(list); summary.append(facts);
      }
      card.append(summary);
      if (group.queue === "CHOOSE_CANDIDATE" && Object.keys(group.candidates || {}).length) {
        const explain = document.createElement("button"); explain.type = "button"; explain.className = "btn btn-secondary btn-sm";
        explain.dataset.aiExplain = "true"; explain.disabled = !aiAssistAvailable;
        explain.textContent = "Explain candidates with AI";
        explain.addEventListener("click", async () => {
          explain.disabled = true;
          try {
            const response = await fetch("/api/migration/ai/explain", { method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ preview_id: currentPreviewId, decision_document: currentDecisionPayload(),
                source_vdom: group.source_vdom, source_kind: group.source_kind, source_name: group.source_name,
                ...(currentTargetPreviewId ? { target_preview_id: currentTargetPreviewId, target_device: selectedTargetDevice } : {}) }) });
            const result = await readJson(response, "AI assistance is temporarily unavailable");
            aiExplanation = result.proposal; aiProposals = [];
            renderAIAssistProposals();
          } catch (_) {
            document.getElementById("migration-ai-status").textContent = "AI assistance is temporarily unavailable. Deterministic migration review is unchanged.";
          } finally { explain.disabled = false; }
        });
        card.append(explain);
      }
      if (group.actions?.length) for (const action of group.actions) {
        const apply = document.createElement("button"); apply.type = "button"; apply.className = "btn btn-secondary";
        apply.textContent = `Apply to ${action.apply_to.length} member decisions`;
        apply.addEventListener("click", async () => {
          apply.disabled = true;
          try {
            const response = await fetch("/api/migration/rules/apply", { method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ preview_id: currentPreviewId, decision_document: currentDecisionPayload(),
                rule_type: action.type, source_key: action.source_key, value: action.value, apply_to: action.apply_to }) });
            const result = await readJson(response, "Could not apply zone mapping");
            await loadMigrationReview(currentPreviewId, result.decision_document);
          } catch (error) { showError(error.message); apply.disabled = false; }
        });
        card.append(apply);
      }
      const canConfirm = group.decisions.some(item => item.mode !== "UNSUPPORTED");
      if (canConfirm) {
        const confirm = document.createElement("button"); confirm.type = "button"; confirm.className = "btn btn-primary"; confirm.textContent = "Confirm mapping";
        confirm.addEventListener("click", async () => {
          const selected = group.decisions.map(item => decisionByKey.get(item.key)).filter(Boolean)
            .filter(item => item.mode !== "UNSUPPORTED");
          selected.forEach(item => {
            const input = [...container.querySelectorAll("[data-decision-key]")]
              .find(node => node.dataset.decisionKey === item.key);
            if (input) item.value = input.value.trim() || null;
          });
          await saveDecisionValues(selected.filter(item => item.value));
        });
        card.append(confirm);
      }
      fragment.append(card);
    }
    container.replaceChildren(fragment);
  }

  document.querySelectorAll("[data-review-queue]").forEach(tab => tab.addEventListener("click", () => {
    activeReviewQueue = tab.dataset.reviewQueue; renderMigrationReviewWorkflow();
  }));

  document.getElementById("automation-run")?.addEventListener("click", async event => {
    if (!currentPreviewId) return;
    const button = event.currentTarget;
    const enabledPolicies = [
      document.getElementById("automation-verified")?.checked && "AUTO_APPLY_VERIFIED",
      document.getElementById("automation-derived")?.checked && "AUTO_APPLY_DERIVED",
    ].filter(Boolean);
    button.disabled = true;
    try {
      const response = await fetch("/api/migration/automation/run", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ preview_id: currentPreviewId, decision_document: currentDecisionPayload(),
          enabled_policies: enabledPolicies,
          ...(currentTargetPreviewId ? { target_preview_id: currentTargetPreviewId, target_device: selectedTargetDevice } : {}) }) });
      const result = await readJson(response, "Could not run deterministic automation");
      automationRunSummary = { resolved: (result.audit || []).length };
      if (!enabledPolicies.length) automationRunSummary.resolved = 0;
      await loadMigrationReview(currentPreviewId, result.decision_document);
      invalidateMigrationPlan();
    } catch (error) { showError(`Could not run deterministic automation: ${error.message}`); }
    finally { button.disabled = false; }
  });

  document.getElementById("decision-approve-safe")?.addEventListener("click", async () => {
    const decisionKeys = Object.entries(autoDecisionResults).filter(([, item]) => ["VERIFIED", "DERIVED"].includes(item.status)).map(([key]) => key);
    if (!decisionKeys.length) return;
    try {
      const response = await fetch("/api/migration/decisions/approve", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ preview_id: currentPreviewId, decision_document: currentDecisionPayload(), decision_keys: decisionKeys,
          ...(currentTargetPreviewId ? { target_preview_id: currentTargetPreviewId, target_device: selectedTargetDevice } : {}) }) });
      const result = await readJson(response, "Could not approve verified mappings");
      await loadMigrationReview(currentPreviewId, result.decision_document);
      invalidateMigrationPlan();
    } catch (error) { showError(`Could not approve mappings: ${error.message}`); }
  });

  document.getElementById("target-intent-import")?.addEventListener("change", async event => {
    const file = event.target.files?.[0]; if (!file || !currentPreviewId) return;
    try {
      const yaml = await file.text();
      const response = await fetch("/api/migration/target-intent/import", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ preview_id: currentPreviewId, decision_document: currentDecisionPayload(), yaml,
          ...(currentTargetPreviewId ? { target_preview_id: currentTargetPreviewId, target_device: selectedTargetDevice } : {}) }) });
      const result = await readJson(response, "Could not import target intent");
      await loadMigrationReview(currentPreviewId, result.decision_document);
      invalidateMigrationPlan();
    } catch (error) { showError(`Could not import target intent: ${error.message}`); }
    finally { event.target.value = ""; }
  });

  document.getElementById("target-intent-export")?.addEventListener("click", async () => {
    if (!currentPreviewId) return;
    try {
      const response = await fetch("/api/migration/target-intent/export", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ preview_id: currentPreviewId, decision_document: currentDecisionPayload() }) });
      const result = await readJson(response, "Could not export target intent");
      const link = document.createElement("a"); link.href = URL.createObjectURL(new Blob([result.yaml], { type: "text/yaml" }));
      link.download = "target_intent.yaml"; link.click(); URL.revokeObjectURL(link.href);
    } catch (error) { showError(`Could not export target intent: ${error.message}`); }
  });

  function switchIngestMode(mode) {
    if (!["file", "snapshot"].includes(mode)) return;
    ingestMode = mode;
    clearSource();
    [[btnIngestFile, "file"], [btnIngestSnapshot, "snapshot"]].forEach(([tab, value]) => {
      tab?.classList.toggle("active", value === mode);
      tab?.setAttribute("aria-selected", String(value === mode));
    });
    fileInput.accept = mode === "snapshot" ? ".json" : VENDOR_CONFIGS[selectedSourceVendor]?.fileAccept || ".txt";
    fileInput.setAttribute("aria-label", mode === "snapshot" ? "Collection snapshot file" : "Firewall configuration file");
    dropzone?.setAttribute("aria-label", mode === "snapshot" ? "Choose a collection snapshot file" : "Choose a firewall configuration file");
    dropzoneSubtext.textContent = mode === "snapshot" ? "Select a previously downloaded collection snapshot (.json)" : "Select a configuration file";
  }
  btnIngestFile?.addEventListener("click", () => switchIngestMode("file"));
  btnIngestSnapshot?.addEventListener("click", () => switchIngestMode("snapshot"));

  function collectionPayload() {
    const connection = {};
    document.querySelectorAll("[data-collection-field]").forEach((field) => {
      connection[field.dataset.collectionField] = field.type === "checkbox" ? field.checked : field.type === "number" ? Number(field.value) : field.value.trim();
    });
    return { vendor: selectedSourceVendor, connection };
  }

  async function applyCollectionPreview(data) {
    currentPreviewId = data.preview_id;
    sourceReady = false;
    automationRunSummary = null;
    currentReport = data.preview?.sections ? data.preview : null;
    reportPage = 1;
    activeValidationGroup = "";
    if (currentReport) renderReport();
    invalidateMigrationPlan();
    await loadMigrationReview(currentPreviewId);
    sourceReady = true;
    const summary = data.preview?.summary || {};
    for (const [element, value] of [[statTotalRules, summary.rules], [statTotalObjects, summary.objects], [statErrors, summary.errors], [statWarnings, summary.warnings]]) {
      if (element) element.textContent = typeof value === "number" ? value : 0;
    }
    optimizerPanel?.classList.toggle("hidden", ![summary.rules, summary.objects, summary.errors, summary.warnings].some(value => typeof value === "number"));
    syncWorkspace();
  }

  async function importSnapshot(file) {
    const body = new FormData();
    body.append("file", file);
    try {
      const response = await fetch("/api/collection/snapshot/import", { method: "POST", body });
      const data = await readJson(response, "Snapshot import failed");
      selectedSourceVendor = data.vendor_id;
      sourceVendorSelect.value = data.vendor_id;
      currentFile = null;
      await applyCollectionPreview(data);
      setPreviewStatus("Snapshot imported. Preview and Excel are ready.");
    } catch (error) { setPreviewStatus(error.message, "error"); }
  }
  async function collectionRequest(path) {
    const status = document.getElementById("collection-status");
    status.textContent = path.endsWith("/test") ? "Testing connection…" : "Collecting configuration and preparing preview…";
    status.classList.remove("hidden");
    try {
      const response = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(collectionPayload()) });
      const data = await readJson(response, "Collection failed");
      if (path.endsWith("/test")) status.textContent = "✓ Connected";
      else {
        await applyCollectionPreview(data);
        status.textContent = `Configuration collected (${data.collection.status}). ${data.collection.warnings?.length || 0} warnings. Snapshot download ready.`;
        const filename = `firewall_snapshot_${selectedSourceVendor}_${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
        await downloadBlob(new Blob([JSON.stringify(data.snapshot)], { type: "application/json" }), filename);
      }
    } catch (error) { status.textContent = `Collection failed: ${error.message}`; }
  }
  document.getElementById("btn-test-collection")?.addEventListener("click", () => collectionRequest("/api/collection/test"));
  document.getElementById("btn-collect-configuration")?.addEventListener("click", () => collectionRequest("/api/collection/collect"));

  function renderDecisionTable() {
    const container = document.getElementById("migration-mapping-fields");
    if (!container) return;
    const table = document.createElement("table"); table.className = "mapping-table decision-table";
    const labels = ["Select", "Source", "Decision", "Mode", "Evidence", "Suggested", "Final Value", "Review", "Affected", "Reason"];
    const thead = document.createElement("thead"), head = document.createElement("tr");
    labels.forEach(label => { const th = document.createElement("th"); th.textContent = label; head.append(th); });
    thead.append(head); table.append(thead);
    const body = document.createElement("tbody");
    for (const decision of currentDecisionSet.decisions) {
      const row = document.createElement("tr");
      row.dataset.key = decision.key; row.dataset.kind = decision.source_kind;
      row.dataset.vdom = decision.source_vdom; row.dataset.field = decision.target_field; row.dataset.state = decisionIsResolved(decision) ? "CONFIRMED" : decision.review_state;
      row.dataset.mode = decision.mode;
      row.dataset.affectedBy = Object.keys(decision.affected_by || {}).join(",");
      const evidence = decisionEvidence[decision.key] || "SOURCE";
      row.dataset.evidence = evidence;
      const mode = decision.mode, unsupported = mode === "UNSUPPORTED";
      row.classList.add(mode === "SUGGESTED" && decision.review_state === "PENDING" ? "decision-suggested" :
        mode === "REQUIRED" && decision.review_state === "PENDING" ? "decision-required" :
        mode === "UNSUPPORTED" ? "decision-unsupported" : "decision-resolved");
      const selectCell = document.createElement("td"); selectCell.dataset.label = labels[0];
      const checkbox = document.createElement("input"); checkbox.type = "checkbox"; checkbox.className = "decision-select";
      checkbox.disabled = unsupported;
      checkbox.setAttribute("aria-label", `Select ${decision.source_name} ${decision.target_field} in ${decision.source_vdom}`);
      checkbox.addEventListener("change", updateSelectedDecisionCount);
      selectCell.append(checkbox); row.append(selectCell);
      const addText = (value, label) => { const cell = document.createElement("td"); cell.dataset.label = label; cell.textContent = value || "—"; row.append(cell); return cell; };
      const sourceCell = addText(`${decision.source_vdom} · ${decision.source_kind} · ${decision.source_name}`, labels[1]);
      const context = decisionContext[decision.key] || {};
      const sourceFacts = Object.entries(context).filter(([name]) => name.startsWith("source_") && name !== "source_members");
      if (Object.hasOwn(context, "source_members")) {
        sourceFacts.push(["source_members", context.source_members.length ? context.source_members.join(", ") : "(explicitly empty)"]);
      }
      if (sourceFacts.length || context.next_action) {
        const details = document.createElement("details"); details.className = "decision-source-details";
        const summary = document.createElement("summary"); summary.textContent = "Source evidence"; details.append(summary);
        if (sourceFacts.length) {
          const list = document.createElement("dl");
          for (const [name, value] of sourceFacts) {
            const term = document.createElement("dt"); term.textContent = name.replace(/^source_/, "").replaceAll("_", " ");
            const description = document.createElement("dd"); description.textContent = Array.isArray(value) ? value.join(", ") : String(value);
            list.append(term, description);
          }
          details.append(list);
        }
        if (context.next_action) { const next = document.createElement("p"); next.textContent = `Next action: ${context.next_action}`; details.append(next); }
        sourceCell.append(details);
      }
      addText(decision.target_field, labels[2]);
      const modeCell = document.createElement("td"); modeCell.dataset.label = labels[3];
      const modeBadge = document.createElement("span"); modeBadge.className = `decision-mode-badge mode-${decision.mode.toLowerCase()}`; modeBadge.textContent = decision.mode;
      modeCell.append(modeBadge); row.append(modeCell);
      const evidenceCell = document.createElement("td"); evidenceCell.dataset.label = labels[4];
      const evidenceBadge = document.createElement("span"); evidenceBadge.className = `decision-evidence-badge evidence-${evidence.toLowerCase()}`; evidenceBadge.textContent = evidence;
      evidenceCell.append(evidenceBadge); row.append(evidenceCell);
      addText(decision.suggested_value, labels[5]);
      const finalCell = document.createElement("td"); finalCell.dataset.label = labels[6];
      const input = document.createElement("input"); input.type = "text"; input.className = "decision-value";
      input.value = decisionDisplayValue(decision);
      input.disabled = unsupported; input.setAttribute("aria-label", `${decision.target_field} for ${decision.source_name} in ${decision.source_vdom}`);
      const stateCell = document.createElement("td"); stateCell.dataset.label = labels[7];
      const reviewBadge = document.createElement("span");
      reviewBadge.className = `decision-review-badge review-${decisionIsResolved(decision) ? "confirmed" : "pending"}`;
      reviewBadge.textContent = decisionIsResolved(decision) ? "CONFIRMED" : "PENDING";
      stateCell.append(reviewBadge);
      input.addEventListener("input", () => {
        decision.value = input.value.trim() || null;
        if (decision.mode === "AUTO") decision.mode = "REQUIRED";
        decision.review_state = "PENDING";
        row.dataset.mode = decision.mode; row.dataset.state = decision.review_state;
        reviewBadge.className = "decision-review-badge review-pending";
        reviewBadge.textContent = "PENDING";
        row.className = "decision-required";
        invalidateMigrationPlan(); updateMappingCompletion();
      });
      finalCell.append(input);
      const candidates = decisionCandidates[decision.key] || [];
      if (decision.target_field === "target_interface" && candidates.length) {
        const details = document.createElement("details"); details.className = "decision-candidates";
        const summary = document.createElement("summary"); summary.textContent = `Candidates (${candidates.length})`; details.append(summary);
        for (const candidate of candidates) {
          const item = document.createElement("div"); item.className = "decision-candidate";
          const evidenceText = [...(candidate.strong_evidence || []), ...(candidate.supporting_evidence || [])].join(" · ");
          const label = document.createElement("span");
          label.textContent = `${candidate.value} · ${candidate.class}${candidate.target_scope ? ` · ${candidate.target_scope}` : ""}${evidenceText ? ` · ${evidenceText}` : ""}`;
          const use = document.createElement("button"); use.type = "button"; use.className = "btn btn-secondary btn-sm"; use.textContent = "Use candidate"; use.disabled = unsupported;
          use.addEventListener("click", () => {
            input.value = candidate.value; decision.value = candidate.value;
            if (decision.mode === "AUTO") decision.mode = "REQUIRED";
            decision.review_state = "PENDING"; row.dataset.mode = decision.mode; row.dataset.state = "PENDING";
            reviewBadge.className = "decision-review-badge review-pending"; reviewBadge.textContent = "PENDING";
            row.className = decision.mode === "SUGGESTED" ? "decision-suggested" : "decision-required";
            invalidateMigrationPlan(); updateMappingCompletion();
          });
          item.append(label, use); details.append(item);
        }
        finalCell.append(details);
      }
      row.append(finalCell, stateCell);
      const affectedCell = document.createElement("td"); affectedCell.dataset.label = labels[8];
      const affectedCount = document.createElement("strong"); affectedCount.textContent = String(decision.affected_count || 0);
      affectedCell.append(affectedCount);
      const affectedBy = Object.entries(decision.affected_by || {}).filter(([, count]) => count > 0);
      if (affectedBy.length) {
        const details = document.createElement("details"); details.className = "affected-details";
        const summary = document.createElement("summary"); summary.textContent = "Show affected objects";
        const list = document.createElement("ul");
        for (const [name, count] of affectedBy) {
          const item = document.createElement("li");
          item.textContent = `${name.replaceAll("_", " ").replace(/\b\w/g, letter => letter.toUpperCase())}: ${count}`;
          list.append(item);
        }
        details.append(summary, list); affectedCell.append(details);
      }
      row.append(affectedCell);
      addText([decision.reason, targetWarnings[decision.key]].filter(Boolean).join(" · "), labels[9]);
      body.append(row);
    }
    table.append(body); container.replaceChildren(table);
    const vdomFilter = document.getElementById("mapping-vdom-filter");
    const selectedVdom = vdomFilter?.value || "all";
    if (vdomFilter) {
      vdomFilter.replaceChildren(new Option("All VDOMs", "all"), ...[...new Set(currentDecisionSet.decisions.map(item => item.source_vdom))].sort().map(vdom => new Option(vdom, vdom)));
      vdomFilter.value = selectedVdom;
    }
    applyDecisionFilters();
    updateEvidenceSummary();
    updateSelectedDecisionCount();
  }

  function renderRecommendations() {
    const container = document.getElementById("migration-recommendation-fields");
    const section = document.getElementById("migration-recommendations");
    if (!container || !section) return;
    section.classList.toggle("hidden", !currentRecommendations.length);
    const table = document.createElement("table"); table.className = "mapping-table recommendation-table";
    const labels = ["Source", "Family", "Recommendation", "Method", "Confidence", "Evidence", "Blockers", "Action"];
    const thead = document.createElement("thead"), head = document.createElement("tr");
    labels.forEach(label => { const th = document.createElement("th"); th.textContent = label; head.append(th); });
    thead.append(head); table.append(thead);
    const body = document.createElement("tbody");
    currentRecommendations.forEach(item => {
      const row = document.createElement("tr"); row.dataset.family = item.family || "";
      row.dataset.needsDecision = String((item.blockers || []).length > 0 || (item.required_decision_keys || []).length > 0);
      const add = (value, label) => { const cell = document.createElement("td"); cell.dataset.label = label; cell.textContent = value || "—"; row.append(cell); };
      add(`${item.source_vdom} · ${item.source_kind} · ${item.source_name}`, labels[0]);
      add(item.family, labels[1]); add(`${item.title}: ${item.summary}`, labels[2]);
      add(item.method, labels[3]); add(item.confidence, labels[4]);
      add((item.evidence || []).join(" · "), labels[5]);
      add((item.blockers || []).concat(item.warnings || []).join(" · "), labels[6]);
      const action = document.createElement("td"); action.dataset.label = labels[7];
      const key = (item.required_decision_keys || [])[0];
      if (key) {
        const button = document.createElement("button"); button.type = "button"; button.className = "btn btn-secondary btn-sm"; button.textContent = "Review mapping";
        button.addEventListener("click", () => focusDecision(key)); action.append(button);
      } else action.textContent = "Manual design";
      row.append(action); body.append(row);
    });
    table.append(body); container.replaceChildren(table); applyRecommendationFilters();
  }

  function applyRecommendationFilters() {
    const filter = document.getElementById("recommendation-filter")?.value || "all";
    document.querySelectorAll(".recommendation-table tbody tr").forEach(row => {
      row.hidden = filter === "needs-decision" ? row.dataset.needsDecision !== "true" : filter !== "all" && row.dataset.family !== filter;
    });
  }

  function applyDecisionFilters() {
    const filter = document.getElementById("mapping-filter")?.value || "all";
    const vdom = document.getElementById("mapping-vdom-filter")?.value || "all";
    const pendingOnly = document.getElementById("decision-pending-only")?.checked;
    const evidenceFilter = document.getElementById("mapping-evidence-filter")?.value || "all";
    document.querySelectorAll(".decision-table tbody tr").forEach(row => {
      const routeNat = row.dataset.affectedBy.split(",").some(item => ["static_route", "source_nat"].includes(item));
      row.hidden = (vdom !== "all" && row.dataset.vdom !== vdom) || (pendingOnly && row.dataset.state !== "PENDING") ||
        (filter === "zones" && row.dataset.kind !== "zone") || (filter === "interfaces" && row.dataset.kind !== "interface") ||
        (filter === "route-nat" && !routeNat) ||
        (evidenceFilter === "target" && row.dataset.evidence !== "TARGET") ||
        (evidenceFilter === "source" && row.dataset.evidence !== "SOURCE") ||
        (evidenceFilter === "conflict" && row.dataset.evidence !== "CONFLICT") ||
        (evidenceFilter === "required" && row.dataset.mode !== "REQUIRED") ||
        (evidenceFilter === "confirmed" && row.dataset.state !== "CONFIRMED");
    });
    updateSelectedDecisionCount();
  }

  function updateEvidenceSummary() {
    const summary = document.getElementById("mapping-evidence-summary");
    if (!summary) return;
    const summaryValues = evidenceSummary;
    summary.textContent = targetEvidence
      ? `Target: ${targetEvidence.device || "not selected"} · ${summaryValues.target_backed || 0} target-backed · ${summaryValues.source_only || 0} source-only · ${summaryValues.conflicts || 0} conflicts · ${summaryValues.required || 0} required · ${summaryValues.confirmed || 0} confirmed`
      : `Target evidence: not provided · ${summaryValues.source_only || 0} source-only suggestions are active.`;
  }

  function updateSelectedDecisionCount() {
    const selectedCount = document.querySelectorAll(".decision-select:checked").length;
    const status = document.getElementById("decision-selected-count");
    if (status) status.textContent = `Selected: ${selectedCount}`;
  }

  function updateMappingCompletion() {
    const decisions = currentDecisionSet.decisions;
    const count = (predicate) => decisions.filter(predicate).length;
    const status = document.getElementById("mapping-completion");
    if (status) status.textContent = `Confirmed ${count(item => item.review_state === "CONFIRMED" || item.mode === "AUTO")} · Suggested ${count(item => item.mode === "SUGGESTED" && item.review_state !== "CONFIRMED")} · Required ${count(item => item.mode === "REQUIRED" && item.review_state !== "CONFIRMED")} · Unsupported ${count(item => item.mode === "UNSUPPORTED")}`;
  }

  document.getElementById("mapping-filter")?.addEventListener("change", applyDecisionFilters);
  document.getElementById("mapping-vdom-filter")?.addEventListener("change", applyDecisionFilters);
  document.getElementById("decision-pending-only")?.addEventListener("change", applyDecisionFilters);
  document.getElementById("mapping-evidence-filter")?.addEventListener("change", applyDecisionFilters);
  document.getElementById("recommendation-filter")?.addEventListener("change", applyRecommendationFilters);

  function selectedDecisions() {
    const keys = new Set([...document.querySelectorAll(".decision-select:checked")].map(input => input.closest("tr").dataset.key));
    return currentDecisionSet.decisions.filter(item => keys.has(item.key) && item.mode !== "UNSUPPORTED");
  }
  document.getElementById("decision-select-visible")?.addEventListener("click", () => {
    document.querySelectorAll(".decision-table tbody tr:not([hidden]) .decision-select:not(:disabled)").forEach(input => { input.checked = true; });
    updateSelectedDecisionCount();
  });
  document.getElementById("decision-clear-selection")?.addEventListener("click", () => {
    document.querySelectorAll(".decision-select:checked").forEach(input => { input.checked = false; });
    updateSelectedDecisionCount();
  });
  async function saveDecisionValues(decisions) {
    for (const decision of decisions) {
      decision.mode = decision.mode === "AUTO" ? "REQUIRED" : decision.mode;
      decision.review_state = "CONFIRMED";
    }
    try { await refreshMigrationReviewFromCurrentDecisions(); }
    catch (error) { showError(`Could not refresh migration review: ${error.message}`); }
  }
  document.getElementById("decision-confirm-selected")?.addEventListener("click", () => {
    const selected = selectedDecisions();
    for (const decision of selected) {
      const input = [...document.querySelectorAll(".decision-value")].find(node => node.closest("tr").dataset.key === decision.key);
      decision.value = input ? input.value.trim() || null : decision.suggested_value || null;
    }
    saveDecisionValues(selected.filter(item => item.value));
  });
  document.getElementById("decision-confirm-suggestions")?.addEventListener("click", () => {
    const selected = currentDecisionSet.decisions.filter(item => item.mode === "SUGGESTED" && item.suggested_value);
    selected.forEach(item => { item.value = item.suggested_value; }); saveDecisionValues(selected);
  });
  document.getElementById("decision-set-selected")?.addEventListener("click", () => {
    const value = document.getElementById("decision-bulk-value")?.value.trim(); if (!value) return;
    const selected = selectedDecisions();
    if (new Set(selected.map(item => item.target_field)).size > 1) {
      showToast("error", "Mixed target fields", "Select rows with one target field before setting a shared value.");
      return;
    }
    selected.forEach(item => { item.value = value; }); saveDecisionValues(selected);
  });
  document.getElementById("decision-use-suggestion")?.addEventListener("click", () => {
    const selected = selectedDecisions().filter(item => item.suggested_value);
    selected.forEach(item => { item.value = item.suggested_value; }); saveDecisionValues(selected);
  });
  document.getElementById("decision-clear-selected")?.addEventListener("click", () => {
    for (const decision of selectedDecisions()) {
      decision.value = null;
      if (decision.mode === "AUTO") decision.mode = "REQUIRED";
      decision.review_state = "PENDING";
    }
    invalidateMigrationPlan(); renderDecisionTable(); updateMappingCompletion();
  });

  document.getElementById("mapping-template")?.addEventListener("click", () => {
    const decisions = currentDecisionSet.decisions;
    const vdoms = [...new Set(decisions.filter(item => item.source_kind === "vdom").map(item => item.source_vdom))];
    const interfaces = new Map();
    for (const item of decisions.filter(item => item.source_kind !== "vdom")) {
      interfaces.set(item.source_vdom, [...new Set([...(interfaces.get(item.source_vdom) || []), item.source_name])]);
    }
    const yaml = ["vdoms:", ...vdoms.flatMap(vdom => [`  ${JSON.stringify(vdom)}:`, "    vsys:", "    virtual_router:"]), "interfaces:", ...[...interfaces].flatMap(([vdom, names]) => [
      `  ${JSON.stringify(vdom)}:`, ...names.flatMap(name => [`    ${JSON.stringify(name)}:`, "      target_interface:", "      target_zone:"]),
    ])].join("\n") + "\n";
    const link = document.createElement("a"); link.href = URL.createObjectURL(new Blob([yaml], { type: "text/yaml" })); link.download = "target-mapping.yaml"; link.click(); URL.revokeObjectURL(link.href);
  });

  document.getElementById("mapping-import")?.addEventListener("change", async event => {
    const file = event.target.files?.[0]; if (!file) return;
    try {
      const response = await fetch("/api/migration/mapping/import", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ yaml: await file.text() }) });
      const imported = await readJson(response, "Could not import mapping YAML");
      let matched = 0, ignored = 0;
      for (const [vdom, values] of Object.entries(imported.mapping.vdoms || {})) for (const [field, value] of Object.entries(values)) {
        if (value != null && upsertConfirmedDecision(vdom, "vdom", vdom, field, value)) matched++; else ignored++;
      }
      for (const [vdom, entries] of Object.entries(imported.mapping.interfaces || {})) for (const [name, values] of Object.entries(entries)) for (const [field, value] of Object.entries(values)) {
        const kinds = field === "target_interface" ? ["interface"] : ["interface", "zone"].filter(kind => currentDecisionSet.decisions.some(item => item.source_vdom === vdom && item.source_kind === kind && item.source_name === name && item.target_field === field));
        if (value == null) { ignored++; continue; }
        const updated = kinds.filter(kind => upsertConfirmedDecision(vdom, kind, name, field, value));
        if (updated.length) matched++; else ignored++;
      }
      currentDecisionDocument = currentDecisionPayload();
      await refreshMigrationReviewFromCurrentDecisions();
      showToast("info", "YAML mapping imported", `${matched} known decisions updated; ${ignored} unmatched or empty entries ignored.`);
    } catch (error) { showError(error.message); }
    event.target.value = "";
  });

  function upsertConfirmedDecision(vdom, kind, name, field, value) {
    const decision = currentDecisionSet.decisions.find(item => item.source_vdom === vdom && item.source_kind === kind && item.source_name === name && item.target_field === field);
    if (!decision || decision.mode === "UNSUPPORTED") return false;
    decision.value = value; decision.review_state = "CONFIRMED";
    return true;
  }

  document.getElementById("decision-import")?.addEventListener("change", async event => {
    const file = event.target.files?.[0]; if (!file || !currentPreviewId) return;
    try {
      const document = JSON.parse(await file.text());
      invalidateMigrationPlan();
      await loadMigrationReview(currentPreviewId, document);
    } catch (error) { showError(error.message); }
    event.target.value = "";
  });
  document.getElementById("decision-export")?.addEventListener("click", async () => {
    try {
      const response = await fetch("/api/migration/decisions/export", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ preview_id: currentPreviewId, decision_document: currentDecisionPayload() }) });
      const result = await readJson(response, "Could not export migration decisions");
      currentDecisionDocument = result.document;
      await downloadBlob(new Blob([JSON.stringify(result.document, null, 2)], { type: "application/json" }), "migration_decisions.json");
    } catch (error) { showError(error.message); }
  });

  function renderMigrationPlanItems(items) {
    const container = document.getElementById("migration-plan-items");
    if (!container) return;
    const filter = document.getElementById("migration-plan-filter")?.value || "attention";
    const attention = item => item.status !== "SUPPORTED" || !item.satisfied || item.warnings?.length || item.render_blockers?.length || targetPlanFindings.some(finding => finding.affected_item_keys?.includes(item.item_key));
    const visible = items.filter(item => {
      if (filter === "all") return true;
      if (filter === "attention") return attention(item);
      if (filter === "not_renderable") return !item.satisfied;
      return String(item.status || "").toLowerCase() === filter;
    });
    const table = document.createElement("table"); table.className = "mapping-table migration-plan-table";
    const labels = ["Source", "Type", "Target", "Status", "Satisfied", "Action", "Commands", "Resolution", "Next action", "Warnings / blockers"];
    const head = document.createElement("tr");
    labels.forEach(label => { const cell = document.createElement("th"); cell.textContent = label; head.append(cell); });
    const thead = document.createElement("thead"); thead.append(head); table.append(thead);
    const body = document.createElement("tbody");
    for (const planItem of visible) {
      const row = document.createElement("tr");
      const targetReasons = targetPlanFindings.filter(finding => finding.affected_item_keys?.includes(planItem.item_key)).map(finding => finding.message);
      const warnings = [...new Set([...(planItem.warnings || []), ...(planItem.render_blockers || []), ...targetReasons])];
      const guidance = supportGuidance.find(item => item.source_vdom === planItem.source_vdom && item.source_name === planItem.source_name);
      const values = [
        [planItem.source_vdom, planItem.source_name].filter(Boolean).join(" · "),
        planItem.source_kind,
        [planItem.target_vsys, planItem.target_name].filter(Boolean).join(" · "),
      ];
      values.forEach((value, index) => { const cell = document.createElement("td"); cell.dataset.label = labels[index]; cell.textContent = value || "—"; row.append(cell); });
      const status = document.createElement("td"); status.dataset.label = labels[3];
      const badge = document.createElement("span"); badge.className = `plan-status-badge status-${String(planItem.status || "unknown").toLowerCase()}`; badge.textContent = String(planItem.status || "UNKNOWN").toLowerCase().replaceAll("_", " ").replace(/\b\w/g, letter => letter.toUpperCase()); status.append(badge); row.append(status);
      const satisfied = document.createElement("td"); satisfied.dataset.label = labels[4]; satisfied.textContent = planItem.satisfied ? "Yes" : "No"; satisfied.className = planItem.satisfied ? "plan-renderable" : "plan-not-renderable"; row.append(satisfied);
      const disposition = document.createElement("td"); disposition.dataset.label = labels[5];
      disposition.textContent = ({ CREATE: "Will create", REUSE: "Reuse existing target object", BLOCK: "Blocked" })[planItem.render_disposition] || "Needs manual review";
      row.append(disposition);
      const commands = document.createElement("td"); commands.dataset.label = labels[6];
      commands.textContent = planItem.render_disposition === "REUSE" ? "None required" : planItem.rendered ? `${(planItem.commands || []).length} commands` : "—"; row.append(commands);
      const resolution = document.createElement("td"); resolution.dataset.label = labels[7];
      if (guidance) {
        resolution.textContent = `${guidance.resolution_type.replaceAll("_", " ")}: ${guidance.title}`;
        if (guidance.decision_key) {
          const review = document.createElement("button"); review.type = "button"; review.className = "btn btn-secondary btn-sm guidance-review"; review.textContent = "Review decision";
          review.dataset.reviewDecision = guidance.decision_key; resolution.append(document.createElement("br"), review);
        }
      } else resolution.textContent = "—";
      row.append(resolution);
      const nextAction = document.createElement("td"); nextAction.dataset.label = labels[8]; nextAction.textContent = guidance?.next_action || "—"; row.append(nextAction);
      const issues = document.createElement("td"); issues.dataset.label = labels[9];
      if (warnings.length) {
        const details = document.createElement("details"); details.className = "plan-issues";
        const summary = document.createElement("summary"); summary.textContent = `${warnings.length} issue${warnings.length === 1 ? "" : "s"}`;
        const list = document.createElement("ul");
        warnings.forEach(warning => { const item = document.createElement("li"); item.textContent = warning; list.append(item); });
        details.append(summary, list); issues.append(details);
      } else issues.textContent = "—";
      row.append(issues);
      body.append(row);
    }
    table.append(body);
    const empty = document.createElement("p"); empty.textContent = visible.length ? "" : "No plan items match this filter.";
    container.replaceChildren(table, empty);
    container.querySelectorAll("[data-review-decision]").forEach(button => button.addEventListener("click", () => focusDecision(button.dataset.reviewDecision)));
  }

  function focusDecision(key) {
    document.getElementById("migration-mapping")?.classList.remove("hidden");
    const editor = document.getElementById("advanced-decision-view");
    if (editor) editor.open = true;
    const decisionFilter = document.getElementById("mapping-filter");
    const vdomFilter = document.getElementById("mapping-vdom-filter");
    const pendingOnly = document.getElementById("decision-pending-only");
    if (decisionFilter) decisionFilter.value = "all";
    if (vdomFilter) vdomFilter.value = "all";
    if (pendingOnly) pendingOnly.checked = false;
    const evidenceFilter = document.getElementById("mapping-evidence-filter");
    if (evidenceFilter) evidenceFilter.value = "all";
    applyDecisionFilters();
    if (!key) {
      editor?.scrollIntoView({ block: "center" });
      return;
    }
    const row = document.querySelector(`.decision-table tr[data-key='${CSS.escape(key)}']`);
    if (!row) {
      editor?.scrollIntoView({ block: "center" });
      return;
    }
    row.hidden = false;
    row.scrollIntoView({ block: "center" });
    row.classList.add("decision-focus");
    row.querySelector(".decision-value")?.focus();
    setTimeout(() => row.classList.remove("decision-focus"), 1400);
  }

  document.getElementById("migration-plan-filter")?.addEventListener("change", () => {
    renderMigrationPlanItems(currentPlanItems);
  });
  document.getElementById("migration-copy-commands")?.addEventListener("click", async () => {
    const text = document.getElementById("migration-command-preview")?.textContent || "";
    if (!text || !navigator.clipboard?.writeText) return;
    try { await navigator.clipboard.writeText(text); showToast("success", "Copied", "Migration commands copied."); }
    catch { showToast("error", "Could not copy", "Select the command text and copy it using your keyboard."); }
  });

  if (btnGenerateBundle) {
    btnGenerateBundle.addEventListener("click", async () => {
      if (!currentPreviewId || !sourceReady) return;
      invalidateMigrationPlan(true);
      const requestRevision = migrationPlanRevision;
      setBusy(btnGenerateBundle, true);
      hideError();
      try {
      const resp = await fetch("/api/migrate", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ preview_id: currentPreviewId, source_vendor: selectedSourceVendor, target_vendor: selectedTargetVendor, decision_document: currentDecisionPayload(), target_preview_id: currentTargetPreviewId, target_device: selectedTargetDevice }),
        });
        const artifact = await readJson(resp, "Migration planning failed");
        if (requestRevision !== migrationPlanRevision) return;
        currentRenderedArtifactId = artifact.artifact_id;
        migrationPlanNeedsRebuild = false;
        currentPlanItems = artifact.report?.items || [];
        currentRecommendations = artifact.recommendations || artifact.report?.review?.recommendations || currentRecommendations;
        targetFindings = artifact.target_findings || [];
        targetPlanFindings = artifact.target_plan_findings || [];
        decisionEvidence = artifact.decision_evidence || {};
        evidenceSummary = artifact.evidence_summary || {};
        supportGuidance = artifact.support_guidance || artifact.report?.review?.support_guidance || [];
        targetEvidence = artifact.target_evidence || artifact.report?.target_evidence || targetEvidence;
        const planFilter = document.getElementById("migration-plan-filter");
        planFilter.value = currentPlanItems.some(item => item.status !== "SUPPORTED" || !item.satisfied || item.warnings?.length || item.render_blockers?.length) ? "attention" : "all";
        renderMigrationPlanItems(currentPlanItems);
        renderRecommendations();
        document.getElementById("migration-plan")?.classList.remove("hidden");
        const counts = artifact.counts || {};
        const summary = document.getElementById("migration-plan-summary");
        if (summary) {
          const status = artifact.plan_status === "READY_NO_CHANGES"
            ? "No PAN-OS configuration changes are required. All supported planned objects are already satisfied by the selected target."
            : artifact.plan_status === "READY" ? "Migration artifact ready."
              : artifact.plan_status === "PARTIAL" ? (artifact.commands ? "Partial commands are ready." : "The migration plan has blockers.") : "Target mappings required.";
          const blockers = new Set(artifact.blocking_reasons || []);
          const targetIssueCount = (artifact.target_findings || []).length;
          const guidanceCount = (artifact.support_guidance || []).length;
          const render = artifact.render_summary || {};
          summary.textContent = `${render.create || 0} will be created · ${render.reuse || 0} existing target objects reused · ${render.blocked || 0} blocked · ${artifact.commands} commands\n${status}${blockers.size ? `\n${blockers.size} blocking issue${blockers.size === 1 ? "" : "s"}. Review the results below.` : ""}${targetIssueCount ? `\n${targetIssueCount} target conflict${targetIssueCount === 1 ? "" : "s"}.` : ""}${guidanceCount ? `\n${guidanceCount} support guidance item${guidanceCount === 1 ? "" : "s"}.` : ""}`;
          summary.textContent += `\nSource status: ${counts.SUPPORTED || 0} supported · ${counts.PARTIAL || 0} partial · ${counts.MANUAL_REVIEW || 0} manual review · ${counts.UNSUPPORTED || 0} unsupported`;
        }
        const previewElement = document.getElementById("migration-command-preview");
        const reviewSummary = document.getElementById("migration-command-summary");
        if (artifact.commands || artifact.plan_status === "READY_NO_CHANGES") {
          const preview = await readJson(await fetch("/api/migration/command-preview", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ artifact_id: currentRenderedArtifactId }) }), "Could not load command preview");
          if (requestRevision !== migrationPlanRevision) return;
          currentArtifactCommandCount = preview.command_count;
          currentArtifactSha256 = preview.command_sha256;
          if (previewElement) previewElement.textContent = preview.command_text;
          if (reviewSummary) reviewSummary.textContent = `Reviewed artifact · ${preview.command_count} commands · SHA-256 ${preview.command_sha256}. Pending decisions ${preview.review_summary.pending} · Manual review ${preview.review_summary.manual} · Unsupported ${preview.review_summary.unsupported}.`;
          const copyCommands = document.getElementById("migration-copy-commands");
          if (copyCommands) copyCommands.disabled = preview.command_count === 0;
        } else {
          if (previewElement) previewElement.textContent = "No renderable commands. Complete required decisions to build a command preview.";
          if (reviewSummary) reviewSummary.textContent = `Pending decisions ${currentDecisionSet.decisions.filter(item => item.review_state === "PENDING").length} · Manual review ${counts.MANUAL_REVIEW || 0} · Unsupported ${counts.UNSUPPORTED || 0}`;
        }
        syncWorkspace();
        const noChanges = artifact.plan_status === "READY_NO_CHANGES";
        btnDownloadBundle?.classList.toggle("hidden", !artifact.commands && !noChanges);
        btnDownloadSet?.classList.toggle("hidden", noChanges || artifact.commands === 0);
        document.getElementById("migration-export")?.classList.toggle("hidden", !artifact.commands && !noChanges);
        if (btnDownloadBundle) {
          btnDownloadBundle.disabled = !artifact.commands && !noChanges;
          const label = btnDownloadBundle.querySelector("span:last-child");
          if (label) label.textContent = "Download bundle";
        }
        if (btnDownloadSet) btnDownloadSet.disabled = artifact.commands === 0;
        if (activeMode === "download") document.getElementById("migration-plan")?.scrollIntoView({ block: "start" });
        logToTerminal(`[PLAN] ${artifact.plan_status}: ${artifact.commands} commands ready.`, artifact.commands || noChanges ? "term-success" : "term-error");
      } catch (err) {
        showError(err.message);
        logToTerminal(`[ERROR] Migration planning failed: ${err.message}`, "term-error");
      } finally {
        setBusy(btnGenerateBundle, false);
      }
    });
  }

  btnDownloadBundle?.addEventListener("click", async () => {
    if (!currentRenderedArtifactId) return;
    setBusy(btnDownloadBundle, true);
    try {
      const response = await fetch("/api/migration/bundle", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ artifact_id: currentRenderedArtifactId }) });
      if (!response.ok) throw new Error((await response.json()).error || "Bundle generation failed");
      const saved = await downloadBlob(await response.blob(), "migration_fortigate_to_palo_alto.zip");
      if (saved) showToast("success", "Migration artifact ready", "Download the migration bundle.");
    } catch (err) { showError(err.message); }
    finally { setBusy(btnDownloadBundle, false); }
  });

  btnDownloadSet?.addEventListener("click", async () => {
    if (!currentRenderedArtifactId) return;
    setBusy(btnDownloadSet, true);
    try {
      const response = await fetch("/api/migration/download", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ artifact_id: currentRenderedArtifactId }) });
      if (!response.ok) throw new Error((await response.json()).error || "Command download failed");
      await downloadBlob(await response.blob(), "palo_alto_config.set");
    } catch (err) { showError(err.message); }
    finally { setBusy(btnDownloadSet, false); }
  });

  // =========================================================================
  // 8b. Vendor-native Excel source report
  // =========================================================================
  if (btnExtractExcel) {
    btnExtractExcel.addEventListener("click", async () => {
      if (!currentFile && !currentPreviewId) {
        showToast(
          "info",
          "No Input",
          "Please upload a configuration file first.",
        );
        return;
      }

      setBusy(btnExtractExcel, true);
      const exportSource = selectedSourceVendor;
      const btnText = btnExtractExcel.querySelector("span:last-child");
      const originalText = btnText
        ? btnText.textContent
        : "Download Source Inventory (.xlsx)";
      if (btnText) btnText.textContent = "Building Source Inventory...";
      hideError();

      const formData = new FormData();
      if (currentFile) {
        formData.append("file", currentFile);
        formData.append("source_vendor", selectedSourceVendor);
      }
      if (currentPreviewId) formData.append("preview_id", currentPreviewId);
      formData.append("excel_profile", excelProfile?.value || "fast");

      try {
        const resp = await fetch("/api/extract/excel", {
          method: "POST",
          body: formData,
        });
        if (!resp.ok) {
          const errData = await resp.json().catch(() => ({}));
          throw new Error(
            errData.error || "Failed to generate Excel inventory",
          );
        }
        const blob = await resp.blob();
        const saved = await downloadBlob(
          blob,
          `firewall_inventory_${exportSource}.xlsx`,
        );
        if (saved)
          showToast(
            "success",
            "Inventory Generated",
            "Your source inventory workbook is ready.",
          );
      } catch (err) {
        showError(err.message);
        showToast("error", "Excel Export Failed", err.message);
      } finally {
        setBusy(btnExtractExcel, false);
        if (btnText) btnText.textContent = originalText;
      }
    });
  }

  // =========================================================================
  // 9. Mode B: Target Authentication Switcher & Diagnostics
  // =========================================================================
  document.addEventListener("click", (event) => {
    const button = event.target.closest(".btn-toggle-password");
    if (!button) return;
    const input = document.getElementById(button.dataset.target);
    if (!input) return;
    const visible = input.type === "password";
    input.type = visible ? "text" : "password";
    button.textContent = visible ? "Hide" : "Show";
    button.setAttribute(
      "aria-label",
      visible ? "Hide password" : "Show password",
    );
    button.setAttribute("aria-pressed", String(visible));
  });
  [panHost, panPort, panUser, panPass].forEach(
    (element) => {
      element?.addEventListener("input", () => {
        element.classList.remove("input-invalid");
        element.removeAttribute("aria-invalid");
        element
          .closest(".form-group")
          ?.querySelector(".field-error-text")
          ?.remove();
      });
    },
  );

  function sshPayload() {
    return {
      host: panHost?.value.trim() || "",
      port: Number(panPort?.value || 22),
      username: panUser?.value.trim() || "",
      password: panPass?.value || "",
    };
  }

  async function postSSH(path, payload) {
    const response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return readJson(response, "SSH operation failed");
  }

  btnPushCandidate?.addEventListener("click", async () => {
    if (!sourceReady || !currentRenderedArtifactId || !currentArtifactCommandCount) return;
    btnPushCandidate.disabled = true;
    try {
      if (!currentRenderedArtifactId) throw new Error("Generate a migration plan first.");
      const response = await fetch("/api/deploy", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...sshPayload(), artifact_id: currentRenderedArtifactId }),
      });
      const data = await readJson(response, "Candidate push failed");
      candidatePushed = true;
      btnValidateCandidate.disabled = false;
      logToTerminal(`[DEPLOY] Pushed ${data.result.commands_succeeded} candidate commands.`, "term-success");
    } catch (err) {
      candidatePushed = false;
      btnValidateCandidate.disabled = true;
      logToTerminal(`[ERROR] Candidate push failed: ${err.message}`, "term-error");
      showError(err.message);
    } finally {
      syncWorkspace();
    }
  });

  btnValidateCandidate?.addEventListener("click", async () => {
    if (!candidatePushed) return;
    btnValidateCandidate.disabled = true;
    try {
      const data = await postSSH("/api/validate-candidate", sshPayload());
      candidateValidated = data.result.status === "SUCCESS";
      btnCommitCandidate.disabled = !candidateValidated;
      logToTerminal(`[VALIDATE] Candidate ${data.result.status.toLowerCase()}: ${data.result.response}`, candidateValidated ? "term-success" : "term-error");
    } catch (err) {
      candidateValidated = false;
      btnCommitCandidate.disabled = true;
      logToTerminal(`[ERROR] Candidate validation failed: ${err.message}`, "term-error");
      showError(err.message);
    } finally {
      btnValidateCandidate.disabled = false;
    }
  });

  btnCommitCandidate?.addEventListener("click", async () => {
    if (!candidateValidated || !confirm("Commit the validated candidate configuration to the firewall?")) return;
    btnCommitCandidate.disabled = true;
    try {
      const data = await postSSH("/api/commit", sshPayload());
      logToTerminal(`[COMMIT] Commit submitted (job ${data.result.job_id || "unknown"}).`, "term-success");
    } catch (err) {
      btnCommitCandidate.disabled = false;
      logToTerminal(`[ERROR] Commit failed: ${err.message}`, "term-error");
      showError(err.message);
    }
  });

  // =========================================================================
  // 10. Terminal Helpers (Clear, Copy, Log)
  // =========================================================================
  if (btnClearTerm) {
    btnClearTerm.addEventListener("click", () => {
      if (terminalStreamBody) {
        terminalStreamBody.innerHTML =
          '<div class="term-line term-system">[SYSTEM] Terminal logs cleared. Ready for operations.</div>';
      }
    });
  }

  if (btnCopyTerm) {
    btnCopyTerm.addEventListener("click", () => {
      if (!terminalStreamBody) return;
      const text = terminalStreamBody.innerText;
      if (!navigator.clipboard?.writeText) {
        showToast(
          "info",
          "Clipboard unavailable",
          "Select the log text and copy it using your keyboard.",
        );
        return;
      }
      navigator.clipboard
        .writeText(text)
        .then(() => {
          showToast("info", "Copied", "Terminal log copied to clipboard");
        })
        .catch((err) => {
          showToast(
            "error",
            "Could not copy",
            "Select the log text and copy it using your keyboard.",
          );
        });
    });
  }

  function logToTerminal(text, className = "term-log") {
    if (!terminalStreamBody) return;
    const line = document.createElement("div");
    line.className = `term-line ${className}`;
    line.textContent = text;
    terminalStreamBody.appendChild(line);

    if (termAutoscroll && termAutoscroll.checked) {
      terminalStreamBody.scrollTop = terminalStreamBody.scrollHeight;
    }
  }

  // 11. Feedback, Errors & Toast System
  // =========================================================================
  function clearInputErrors() {
    document.querySelectorAll(".input-invalid").forEach((el) => {
      el.classList.remove("input-invalid");
      el.removeAttribute("aria-invalid");
    });
    document.querySelectorAll(".field-error-text").forEach((el) => el.remove());
  }

  function showInputError(elementId, message) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.classList.add("input-invalid");
    el.setAttribute("aria-invalid", "true");

    const parent = el.closest(".form-group") || el.parentElement;
    const existing = parent.querySelector(".field-error-text");
    if (existing) existing.remove();

    const err = document.createElement("div");
    err.className = "field-error-text";
    err.textContent = message;
    err.id = `${elementId}-error`;
    el.setAttribute("aria-describedby", err.id);

    if (el.closest(".password-wrapper")) {
      el.closest(".password-wrapper").insertAdjacentElement("afterend", err);
    } else {
      el.insertAdjacentElement("afterend", err);
    }
    el.focus();
  }

  function showToast(type, title, msg, duration = 5000) {
    if (!toastContainer) return;
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;

    const icons = {
      error: "⚠️",
      success: "✓",
      info: "ℹ️",
    };

    toast.innerHTML = `
            <div class="toast-icon">${icons[type] || "ℹ️"}</div>
            <div class="toast-content" style="flex: 1;">
                <div class="toast-title"></div>
                <div class="toast-msg"></div>
            </div>
            <button class="toast-close" type="button" aria-label="Close">✕</button>
        `;
    toast.querySelector(".toast-title").textContent = title;
    toast.querySelector(".toast-msg").textContent = msg;
    toast.setAttribute("role", type === "error" ? "alert" : "status");

    const removeToast = () => {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(100%)";
      toast.style.transition = "all 0.25s ease";
      setTimeout(() => toast.remove(), 250);
    };

    const closeBtn = toast.querySelector(".toast-close");
    if (closeBtn) closeBtn.addEventListener("click", removeToast);

    setTimeout(removeToast, duration);
    toastContainer.appendChild(toast);
  }

  function showError(msg) {
    if (errorBanner) {
      errorBanner.textContent = msg;
      errorBanner.classList.remove("hidden");
    }
  }

  function hideError() {
    if (errorBanner) {
      errorBanner.textContent = "";
      errorBanner.classList.add("hidden");
    }
  }

  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  }

  async function downloadBlob(blob, filename) {
    // 1. Check if running inside desktop app (pywebview)
    if (
      window.pywebview &&
      window.pywebview.api &&
      typeof window.pywebview.api.save_file_dialog === "function"
    ) {
      try {
        const base64Data = await new Promise((resolve, reject) => {
          const reader = new FileReader();
          reader.onloadend = () => {
            const res = reader.result;
            const base64 = res.substring(res.indexOf(",") + 1);
            resolve(base64);
          };
          reader.onerror = reject;
          reader.readAsDataURL(blob);
        });

        const res = await window.pywebview.api.save_file_dialog(
          filename,
          base64Data,
        );
        if (res && res.success) {
          showToast(
            "success",
            "File Saved",
            `Saved successfully to ${res.path}`,
          );
          logToTerminal(
            `[SAVED] File saved successfully to: ${res.path}`,
            "term-success",
          );
          return true;
        } else if (res && res.cancelled) {
          logToTerminal(
            `[CANCELLED] File save cancelled by user.`,
            "term-info",
          );
          return false;
        } else if (res && res.error) {
          showToast("error", "Save Failed", res.error);
          logToTerminal(
            `[ERROR] Failed to save file: ${res.error}`,
            "term-error",
          );
        }
        return false;
      } catch (err) {
        console.error(
          "Desktop save dialog failed, falling back to browser download",
          err,
        );
      }
    }

    // 2. Standard Web Browser download fallback
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.style.display = "none";
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => window.URL.revokeObjectURL(url), 10000);
    a.remove();
    return true;
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  document
    .getElementById("btn-new-workspace")
    ?.addEventListener("click", () => {
      if (
        currentFile &&
        !confirm(
          "Start a new workspace? This clears the current source from this window.",
        )
      )
        return;
      clearSource();
      clearInputErrors();
      [panHost, panUser, panPass].forEach((input) => {
        if (input) input.value = "";
      });
      if (terminalStreamBody) terminalStreamBody.replaceChildren();
      logToTerminal(
        "[SYSTEM] New workspace ready. Choose a source configuration to begin.",
        "term-system",
      );
      sourceVendorSelect?.focus();
    });

  const themeToggle = document.getElementById("btn-toggle-theme");
  const themePreference = window.matchMedia?.("(prefers-color-scheme: dark)");
  let explicitTheme = null;
  try {
    const savedTheme = localStorage.getItem("fwmigrate-theme");
    if (savedTheme === "light" || savedTheme === "dark")
      explicitTheme = savedTheme;
  } catch {
    // Theme switching remains available when browser storage is restricted.
  }

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    const isDark = theme === "dark";
    document
      .querySelector('meta[name="theme-color"]')
      ?.setAttribute("content", isDark ? "#141d19" : "#f5f6f3");
    const label = isDark ? "Light mode" : "Dark mode";
    setText("theme-label", label);
    themeToggle?.setAttribute("aria-label", `Switch to ${label.toLowerCase()}`);
    themeToggle?.setAttribute("aria-pressed", String(isDark));
  }

  themeToggle?.addEventListener("click", () => {
    explicitTheme =
      document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    applyTheme(explicitTheme);
    try {
      localStorage.setItem("fwmigrate-theme", explicitTheme);
    } catch {
      // Preserve the choice for this session even if it cannot be saved.
    }
  });

  const followSystemTheme = (event) => {
    if (!explicitTheme) applyTheme(event.matches ? "dark" : "light");
  };
  if (themePreference?.addEventListener)
    themePreference.addEventListener("change", followSystemTheme);
  else themePreference?.addListener?.(followSystemTheme);
  applyTheme(explicitTheme || (themePreference?.matches ? "dark" : "light"));

  loadCollectionCapabilities();
  switchMode(activeMode);
  syncWorkspace();
});
