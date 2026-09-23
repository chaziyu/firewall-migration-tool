document.addEventListener("DOMContentLoaded", () => {
  // =========================================================================
  // Application State
  // =========================================================================
let currentFile = null;
let currentRenderedArtifactId = null;
  let currentMigrationMapping = { vdoms: {}, interfaces: {} };
  let currentPreviewId = null;
  let selectedSourceVendor = "fortigate";
  let selectedTargetVendor = "palo_alto";
  let offlineTargetVendor = "palo_alto";
  let activeMode = "download"; // 'download', 'live', 'extract', or 'report'
  let currentPolicies = [];
  let currentReport = null;
  let sourceReady = false;
  let sourceFailed = false;
  let sourceRevision = 0;
  let previewController = null;
  const busyButtons = new Set();

  const MODE_COPY = {
    report: [
      "View report",
      "Review the extracted source configuration before downloading Excel.",
    ],
    download: [
      "Plan migration",
      "Review supported mappings, manual-review items, and generated PAN-OS commands.",
    ],
    extract: [
      "Export to Excel",
      "Upload once, then download the complete Excel workbook.",
    ],
    collect: ["Live Collection", "Connect to a supported device and collect its configuration."],
    live: [
      "Live migration",
      "Validate your target, deploy CLI commands, then commit with confidence.",
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
          checked: true,
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
      fields: [
        { id: "collection-host", label: "Host", type: "text", required: true, col: "col-8" },
        { id: "collection-port", label: "SSH Port", type: "number", required: true, value: 22, col: "col-4" },
        { id: "collection-username", label: "Username", type: "text", required: true, col: "col-6" },
        { id: "collection-password", label: "Password", type: "password", required: true, col: "col-6" },
      ],
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
          checked: true,
          col: "col-12",
        },
      ],
    },
    juniper_srx: {
      name: "Juniper SRX",
      icon: "🌲",
      protocol: "JunOS NETCONF over SSH / PyEZ",
      desc: "Connects via NETCONF (Port 830) to retrieve JunOS security zones, address books, and policy sets.",
      defaultPort: 830,
      authTypes: [{ id: "userpass", label: "NETCONF SSH Admin Credentials" }],
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
          label: "NETCONF Port",
          type: "number",
          required: true,
          value: 830,
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
          id: "api-insecure",
          label: "Allow Self-Signed / Host Key Bypass",
          type: "checkbox",
          checked: true,
          col: "col-12",
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
  const tabExtract = document.getElementById("tab-extract");
  const tabCollect = document.getElementById("tab-collect");
  const developmentBanner = document.getElementById("development-banner");
  const modeDownloadForm = document.getElementById("mode-download-form");
  const modeLiveForm = document.getElementById("mode-live-form");
  const modeExtractForm = document.getElementById("mode-extract-form");
  const reportContainer = document.getElementById("report-container");
  const reportOverview = document.getElementById("report-overview");
  const reportData = document.getElementById("report-data");
  const reportSummary = document.getElementById("report-summary");
  const reportFilename = document.getElementById("report-filename");
  const reportVdomSummary = document.getElementById("report-vdom-summary");
  const reportObjectTabs = document.getElementById("report-object-tabs");
  const reportSearch = document.getElementById("report-search");
  const reportVdomFilter = document.getElementById("report-vdom-filter");
  const reportSeverityFilter = document.getElementById("report-severity-filter");
  const reportTableHead = document.getElementById("report-table-head");
  const reportTableBody = document.getElementById("report-table-body");
  const reportTable = document.querySelector(".report-table");
  const reportTableWrap = document.querySelector(".report-table-wrap");
  const reportTableCaption = document.getElementById("report-table-caption");
  const reportRowCount = document.getElementById("report-row-count");
  const reportScrollHint = document.getElementById("report-scroll-hint");
  const reportEmpty = document.getElementById("report-empty");
  let activeReportSection = "overview";
  let activeObjectSection = "addresses";

  // Ingestion Method Tabs
  const btnIngestFile = document.getElementById("btn-ingest-file");
  const btnIngestSnapshot = document.getElementById("btn-ingest-snapshot");
  const liveContainer = document.getElementById("ingest-live-container");
  let ingestMode = "file";

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

  // Optimizer Panel Stats
  const optimizerPanel = document.getElementById("optimizer-panel");
  const statTotalRules = document.getElementById("stat-total-rules");
  const statTotalObjects = document.getElementById("stat-total-objects");
  const statErrors = document.getElementById("stat-errors");
  const statWarnings = document.getElementById("stat-warnings");

  // Mode A Components
  const btnGenerateBundle = document.getElementById("btn-generate-bundle");
  const btnDownloadBundle = document.getElementById("btn-download-bundle");
  const btnExtractExcel = document.getElementById("btn-extract-excel");

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
    policies: [["policy_id", "ID", "compact"], ["name", "Name"], ["source_interfaces", "Source"], ["destination_interfaces", "Destination"], ["services", "Service"], ["action", "Action", "compact"], ["nat", "NAT", "compact"], ["review", "Review", "notes"]],
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

  function reportRows(section) {
    const sections = currentReport?.sections || {};
    if (section === "interfaces") return sections.interface_topology || sections.interfaces || [];
    if (section === "objects") return sections[activeObjectSection] || [];
    if (section === "vpn") return [
      ...(sections.vpn_tunnels || []).map((row) => ({ ...row, kind: "Tunnel", attachment: row.interface, peer: row.remote_gateway || row.ike_gateways, crypto: row.ike_version || row.ipsec_crypto_profile, topology: row.topology_path })),
      ...(sections.vpn_phase2 || []).map((row) => ({ ...row, kind: "Phase 2", attachment: row.phase1, peer: [row.source_range, row.destination_range].filter(Boolean).join(" → "), crypto: row.proposal, topology: [] })),
    ];
    return sections[section] || [];
  }

  function renderReportTable() {
    if (!currentReport || activeReportSection === "overview") return;
    const columnKey = activeReportSection === "objects" ? activeObjectSection : activeReportSection;
    const columns = reportColumns[columnKey] || [];
    const search = reportSearch?.value.trim().toLowerCase() || "";
    const vdom = reportVdomFilter?.value || "";
    const severity = reportSeverityFilter?.value || "";
    const sectionRows = reportRows(activeReportSection);
    const rows = sectionRows.filter((row) => {
      if (vdom && row.vdom !== vdom) return false;
      if (severity && row.severity !== severity) return false;
      return !search || Object.values(row).some((value) => reportCell(value).toLowerCase().includes(search));
    });
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
    rows.forEach((row) => {
      const tr = document.createElement("tr");
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
      reportRowCount.textContent = `${rows.length} of ${sectionRows.length} ${sectionRows.length === 1 ? "row" : "rows"}`;
    }
    reportTableWrap?.classList.toggle("hidden", rows.length === 0);
    reportEmpty?.classList.toggle("hidden", rows.length > 0);
    requestAnimationFrame(syncTableOverflow);
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
    const stats = [["Interfaces", objects.interfaces], ["Policies", objects.policies], ["Objects", objectTotal], ["Errors", severity.error], ["Warnings", severity.warning]];
    const fragment = document.createDocumentFragment();
    stats.forEach(([label, value]) => { const stat = document.createElement("div"); stat.className = "report-stat"; const number = document.createElement("strong"); number.textContent = String(count(value)); const caption = document.createElement("span"); caption.textContent = label; stat.append(number, caption); fragment.appendChild(stat); });
    reportSummary.replaceChildren(fragment);
    if (reportFilename) reportFilename.textContent = currentFile?.name || "";
    if (reportVdomSummary) reportVdomSummary.textContent = (summary.vdoms || []).length ? `VDOMs: ${summary.vdoms.join(", ")}` : "No VDOM data found.";
    const overview = activeReportSection === "overview";
    reportOverview?.classList.toggle("hidden", !overview);
    reportData?.classList.toggle("hidden", overview);
    reportObjectTabs?.classList.toggle("hidden", activeReportSection !== "objects");
    reportSeverityFilter?.classList.toggle("hidden", activeReportSection !== "validation");
    document.querySelectorAll("[data-report-section]").forEach((button) => button.classList.toggle("active", button.dataset.reportSection === activeReportSection));
    if (!overview) renderReportTable();
  }

  function syncWorkspace() {
    const hasFile = Boolean(currentFile);
    const hasInput = hasFile || Boolean(currentPreviewId);
    const migrationPairSupported = selectedSourceVendor === "fortigate" && selectedTargetVendor === "palo_alto";
    tabReport?.classList.toggle("hidden", !["fortigate", "palo_alto"].includes(selectedSourceVendor));
    if (btnGenerateBundle)
      btnGenerateBundle.disabled =
        !hasFile || !sourceReady || !migrationPairSupported || busyButtons.has(btnGenerateBundle);
    if (btnExtractExcel)
      btnExtractExcel.disabled =
        !hasInput || !sourceReady || busyButtons.has(btnExtractExcel);
    if (btnPushCandidate && !busyButtons.has(btnPushCandidate))
      btnPushCandidate.disabled = !hasFile || !sourceReady;
    const exportHint = document.querySelector(
      "#mode-download-form .export-hint",
    );
    if (exportHint) {
      const hintCopy = sourceReady && migrationPairSupported
        ? "Ready to build the migration plan."
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
    reportContainer?.classList.toggle("hidden", activeMode !== "report" || !currentReport);
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
    currentRenderedArtifactId = null;
    currentMigrationMapping = { vdoms: {}, interfaces: {} };
    document.getElementById("migration-mapping")?.classList.add("hidden");
    document.getElementById("migration-plan")?.classList.add("hidden");
    btnDownloadBundle?.classList.add("hidden");
    if (btnDownloadBundle) btnDownloadBundle.disabled = true;
    candidatePushed = false;
    candidateValidated = false;
    if (btnPushCandidate) btnPushCandidate.disabled = true;
    if (btnValidateCandidate) btnValidateCandidate.disabled = true;
    if (btnCommitCandidate) btnCommitCandidate.disabled = true;
    currentPolicies = [];
    currentReport = null;
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
  if (tabExtract) {
    tabExtract.addEventListener("click", () => switchMode("extract"));
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
      [tabExtract, "extract"],
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
    if (modeExtractForm)
      modeExtractForm.classList.toggle("hidden", mode !== "extract");
    document.querySelector(".ingest-tabs")?.classList.toggle("hidden", mode === "collect");
    document.getElementById("ingest-file-container")?.classList.toggle("hidden", mode === "collect");
    liveContainer?.classList.toggle("hidden", mode !== "collect");
    if (mode === "collect" && selectedSourceVendor !== "cisco_asa") {
      const status = document.getElementById("collection-status");
      status.textContent = "Live collection is currently available for Cisco ASA.";
      status.classList.remove("hidden");
    }
    developmentBanner?.classList.toggle("hidden", !["download", "live"].includes(mode));
    btnExtractExcel?.parentElement?.classList.toggle("hidden", mode !== "extract");
    reportContainer?.classList.toggle("hidden", mode !== "report" || !currentReport);
    if (targetVendorGroup)
      targetVendorGroup.classList.toggle("hidden", ["extract", "report", "collect"].includes(mode));
    if (vendorSelectorGrid)
      vendorSelectorGrid.classList.toggle(
        "extract-mode",
        ["extract", "report", "collect"].includes(mode),
      );
    setText("page-title", MODE_COPY[mode][0]);
    setText("page-description", MODE_COPY[mode][1]);
    syncWorkspace();

    if (mode === "report") {
      renderReport();
      logToTerminal("[MODE] Switched to FortiGate source report view.", "term-system");
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
    } else {
      logToTerminal(
        "[MODE] Switched to Vendor-Neutral Excel Extraction.",
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
  enableTabKeys([tabReport, tabExtract, tabCollect, tabDownload, tabLive]);
  enableTabKeys([btnIngestFile, btnIngestSnapshot]);

  // =========================================================================
  // 3. Vendor Selector Dropdowns
  // =========================================================================
  if (sourceVendorSelect) {
    selectedSourceVendor = sourceVendorSelect.value || "fortigate";
    sourceVendorSelect.addEventListener("change", (e) => {
      selectedSourceVendor = e.target.value;
      ["collection-host", "collection-username", "collection-password"].forEach((id) => { const field = document.getElementById(id); if (field) field.value = ""; });
      const collectionStatus = document.getElementById("collection-status");
      collectionStatus?.classList.add("hidden");
      if (activeMode === "collect" && selectedSourceVendor !== "cisco_asa") {
        collectionStatus.textContent = "Live collection is currently available for Cisco ASA.";
        collectionStatus.classList.remove("hidden");
      }
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
        if (fileInput) fileInput.accept = cfg.fileAccept;
      }

      syncWorkspace();
    });
  }

  if (targetVendorSelect) {
    selectedTargetVendor = targetVendorSelect.value || "palo_alto";
    targetVendorSelect.addEventListener("change", (e) => {
      selectedTargetVendor = e.target.value;
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

    fetchMigrationPreview();
  }

  if (btnRemoveFile) {
    btnRemoveFile.addEventListener("click", () => {
      clearSource();
      logToTerminal("[FILE] Configuration file unloaded.", "term-system");
    });
  }

  document.querySelectorAll("[data-report-section]").forEach((button) => button.addEventListener("click", () => {
    activeReportSection = button.dataset.reportSection;
    renderReport();
  }));
  document.querySelectorAll("[data-object-section]").forEach((button) => button.addEventListener("click", () => {
    activeObjectSection = button.dataset.objectSection;
    document.querySelectorAll("[data-object-section]").forEach((item) => item.classList.toggle("active", item === button));
    renderReportTable();
  }));
  reportSearch?.addEventListener("input", renderReportTable);
  reportVdomFilter?.addEventListener("change", renderReportTable);
  reportSeverityFilter?.addEventListener("change", renderReportTable);

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
      if (selectedSourceVendor === "fortigate" && currentPreviewId) {
        const response = await fetch("/api/migration/requirements", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ preview_id: currentPreviewId }),
        });
        const result = await readJson(response, "Could not load target mapping requirements");
        if (requestRevision !== sourceRevision) return;
        currentMigrationMapping = { vdoms: {}, interfaces: {} };
        const container = document.getElementById("migration-mapping-fields");
        const panel = document.getElementById("migration-mapping");
        if (container && panel) {
          const fragment = document.createDocumentFragment();
          result.requirements.vdoms.forEach(({ source_vdom }) => {
            currentMigrationMapping.vdoms[source_vdom] = { vsys: "", virtual_router: "" };
            const group = document.createElement("details"); group.open = true;
            const legend = document.createElement("summary"); legend.textContent = `VDOM ${source_vdom} · Scope`; group.appendChild(legend);
            [["vsys", "Target VSYS"], ["virtual_router", "Virtual Router"]].forEach(([key, label]) => {
              const row = document.createElement("label"); row.textContent = label;
              const input = document.createElement("input"); input.type = "text"; input.placeholder = label; input.setAttribute("aria-label", `${label} for ${source_vdom}`);
              input.dataset.mappingScope = "vdom"; input.dataset.vdom = source_vdom; input.dataset.field = key;
              input.addEventListener("input", () => { currentMigrationMapping.vdoms[source_vdom][key] = input.value.trim(); invalidateMigrationPlan(); updateMappingCompletion(); });
              row.append(input); group.append(row);
            });
            fragment.appendChild(group);
          });
          result.requirements.interfaces.forEach((item) => {
            const { source_vdom, source_interface, kind, requires, reasons, reference_count } = item;
            const vdom = source_vdom || "root";
            currentMigrationMapping.interfaces[vdom] ||= {};
            currentMigrationMapping.interfaces[vdom][source_interface] ||= { target_interface: "", target_zone: "" };
          });
          const optionalPanel = document.getElementById("optional-mappings");
          const optionalList = document.getElementById("optional-mapping-list");
          if (optionalPanel && optionalList) {
            optionalList.replaceChildren(...(result.requirements.optional || []).map(item => { const li = document.createElement("li"); li.textContent = `${item.source_vdom} · ${item.kind} · ${item.source_name}`; return li; }));
            optionalPanel.classList.toggle("hidden", !(result.requirements.optional || []).length);
          }
          const section = document.createElement("details"); section.open = true;
          const summary = document.createElement("summary"); summary.textContent = `Zones and interfaces · ${result.requirements.interfaces.length} required`; section.append(summary);
          const table = document.createElement("table"); table.className = "mapping-table";
          const head = document.createElement("tr");
          ["FortiGate", "Used by", "PAN Interface", "PAN Zone"].forEach(text => { const th = document.createElement("th"); th.textContent = text; head.append(th); });
          const thead = document.createElement("thead"); thead.append(head); table.append(thead);
          const body = document.createElement("tbody");
          result.requirements.interfaces.forEach(item => {
            const { source_vdom, source_interface, kind, requires, reasons, reference_count } = item;
            const vdom = source_vdom || "root"; const tr = document.createElement("tr");
            tr.dataset.kind = kind; tr.dataset.reasons = (reasons || []).join(","); tr.dataset.vdom = vdom;
            tr.dataset.name = source_interface;
            const source = document.createElement("td");
            const select = document.createElement("input"); select.type = "checkbox"; select.className = "mapping-select"; select.setAttribute("aria-label", `Select ${source_interface} in ${vdom}`); source.append(select, ` ${source_interface} (${vdom})`);
            const used = document.createElement("td"); used.textContent = `${(reasons || []).join(", ")} · ${reference_count || 1}`;
            tr.append(source, used);
            [["target_interface", "PAN interface"], ["target_zone", "PAN zone"]].forEach(([key, label]) => {
              const td = document.createElement("td");
              if ((requires || []).includes(key)) {
                const input = document.createElement("input"); input.type = "text"; input.placeholder = label; input.setAttribute("aria-label", `${label} for ${source_interface} in ${vdom}`);
                input.dataset.mappingScope = "interface"; input.dataset.vdom = vdom; input.dataset.name = source_interface; input.dataset.field = key;
                input.addEventListener("input", () => { currentMigrationMapping.interfaces[vdom][source_interface][key] = input.value.trim(); invalidateMigrationPlan(); updateMappingCompletion(); }); td.append(input);
                if (key === "target_zone" && kind === "zone") {
                  const suggest = document.createElement("button"); suggest.type = "button"; suggest.textContent = "Use same name"; suggest.title = "Apply the source zone name as a suggestion";
                  suggest.addEventListener("click", () => { input.value = source_interface; input.dispatchEvent(new Event("input", { bubbles: true })); }); td.append(suggest);
                }
              } else td.textContent = "—";
              tr.append(td);
            }); body.append(tr);
          });
          table.append(body); section.append(table); fragment.append(section);
          container.replaceChildren(fragment);
          panel.classList.remove("hidden");
          updateMappingCompletion();
        }
      }
      const stats = data.stats || data.summary || {};
      const objects = stats.objects || stats;
      const severityCounts = stats.validation?.severity_counts || {};
      if (optimizerPanel) optimizerPanel.classList.remove("hidden");
      if (statTotalRules) statTotalRules.textContent = count(objects.policies);
      if (statTotalObjects)
        statTotalObjects.textContent =
          ["addresses", "address_groups", "services", "service_groups"]
            .reduce((total, key) => total + count(objects[key]), 0);
      if (statErrors) statErrors.textContent = count(severityCounts.error);
      if (statWarnings) statWarnings.textContent = count(severityCounts.warning);
      currentPolicies = Array.isArray(data.policies) ? data.policies : [];
      currentReport = data;
      renderReport();
      sourceReady = true;
      const itemCount = Object.values(objects).reduce(
        (total, value) => total + count(value),
        0,
      );
      setPreviewStatus(
        itemCount
          ? "Configuration parsed successfully. The report is ready."
          : "No supported objects were found. Review the source file and extraction warnings in the Excel workbook.",
        itemCount ? "ready" : "empty",
      );
    } catch (err) {
      if (err.name === "AbortError" || requestRevision !== sourceRevision)
        return;
      sourceReady = false;
      sourceFailed = true;
      setPreviewStatus(err.message, "error");
      showError(`Configuration preview failed: ${err.message}`);
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
  function invalidateMigrationPlan() {
    currentRenderedArtifactId = null;
    candidatePushed = false;
    candidateValidated = false;
    btnDownloadBundle?.classList.add("hidden");
    if (btnDownloadBundle) btnDownloadBundle.disabled = true;
    document.getElementById("migration-plan")?.classList.add("hidden");
    if (btnValidateCandidate) btnValidateCandidate.disabled = true;
    if (btnCommitCandidate) btnCommitCandidate.disabled = true;
  }

  function switchIngestMode(mode) {
    ingestMode = mode;
    clearSource();
    const filePanel = document.getElementById("ingest-file-container");
    filePanel?.classList.toggle("hidden", mode === "live");
    liveContainer?.classList.toggle("hidden", mode !== "live");
    [[btnIngestFile, "file"], [btnIngestSnapshot, "snapshot"], [btnIngestLive, "live"]].forEach(([tab, value]) => {
      tab?.classList.toggle("active", value === mode);
      tab?.setAttribute("aria-selected", String(value === mode));
    });
    if (mode === "live" && selectedSourceVendor !== "cisco_asa") {
      document.getElementById("collection-status").textContent = "Live collection is currently available for Cisco ASA.";
      document.getElementById("collection-status").classList.remove("hidden");
    }
  }
  btnIngestFile?.addEventListener("click", () => switchIngestMode("file"));
  btnIngestSnapshot?.addEventListener("click", () => switchIngestMode("snapshot"));
  btnIngestLive?.addEventListener("click", () => switchIngestMode("live"));

  function collectionPayload() {
    return { vendor: selectedSourceVendor, connection: {
      host: document.getElementById("collection-host").value.trim(),
      port: Number(document.getElementById("collection-port").value || 22),
      username: document.getElementById("collection-username").value.trim(),
      password: document.getElementById("collection-password").value,
    }};
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
        currentPreviewId = data.preview_id;
        sourceReady = true;
        currentRenderedArtifactId = null;
        status.textContent = "✓ Connected · ✓ Configuration collected · ✓ Secrets sanitized · ✓ Ready for extraction";
        const report = data.preview || {};
        if (report.summary) {
          statTotalRules.textContent = report.summary.rules ?? 0;
          statTotalObjects.textContent = report.summary.objects ?? 0;
          statErrors.textContent = report.summary.errors ?? 0;
          statWarnings.textContent = report.summary.warnings ?? 0;
          optimizerPanel?.classList.remove("hidden");
        }
        syncWorkspace();
      }
    } catch (error) { status.textContent = `Collection failed: ${error.message}`; }
  }
  document.getElementById("btn-test-collection")?.addEventListener("click", () => collectionRequest("/api/collection/test"));
  document.getElementById("btn-collect-configuration")?.addEventListener("click", () => collectionRequest("/api/collection/collect"));

  function updateMappingCompletion() {
    const inputs = [...document.querySelectorAll("#migration-mapping-fields input[data-mapping-scope]")];
    const completed = inputs.filter(input => input.value.trim()).length;
    const status = document.getElementById("mapping-completion");
    const categories = { VSYS: inputs.filter(input => input.dataset.mappingScope === "vdom" && input.dataset.field === "vsys"), "Virtual routers": inputs.filter(input => input.dataset.mappingScope === "vdom" && input.dataset.field === "virtual_router"), Zones: [...document.querySelectorAll('.mapping-table input[data-field="target_zone"]')], Interfaces: [...document.querySelectorAll('.mapping-table input[data-field="target_interface"]')] };
    const breakdown = Object.entries(categories).map(([name, rows]) => `${name} ${rows.filter(input => input.value.trim()).length}/${rows.length}`).join(" · ");
    if (status) { status.textContent = `Required: ${inputs.length} · Completed: ${completed} · Missing: ${inputs.length - completed}  |  ${breakdown}`; status.onclick = () => { document.getElementById("mapping-filter").value = "unmapped"; document.getElementById("mapping-filter").dispatchEvent(new Event("change")); }; }
  }

  document.getElementById("mapping-filter")?.addEventListener("change", event => {
    const filter = event.target.value;
    document.querySelectorAll(".mapping-table tbody tr").forEach(row => {
      const reasons = row.dataset.reasons.split(",");
      const inputs = [...row.querySelectorAll("input")];
      const mapped = inputs.every(input => input.value.trim());
      row.hidden = filter === "unmapped" ? mapped : filter === "mapped" ? !mapped : filter === "zones" ? row.dataset.kind !== "zone" : filter === "interfaces" ? row.dataset.kind !== "interface" : filter === "route-nat" ? !reasons.some(reason => ["static_route", "source_nat"].includes(reason)) : false;
    });
  });

  document.getElementById("bulk-zone-apply")?.addEventListener("click", () => {
    const value = document.getElementById("bulk-zone-value")?.value.trim(); if (!value) return;
    document.querySelectorAll(".mapping-table tbody tr:has(.mapping-select:checked)").forEach(row => {
      const input = row.querySelector('input[data-field="target_zone"]'); if (input) { input.value = value; input.dispatchEvent(new Event("input", { bubbles: true })); }
    });
  });

  document.getElementById("bulk-zone-name")?.addEventListener("click", () => {
    document.querySelectorAll(".mapping-table tbody tr:has(.mapping-select:checked)").forEach(row => {
      if (row.dataset.kind !== "zone") return;
      const input = row.querySelector('input[data-field="target_zone"]'); if (input) { input.value = row.dataset.name; input.dispatchEvent(new Event("input", { bubbles: true })); }
    });
  });

  document.getElementById("bulk-mapping-clear")?.addEventListener("click", () => {
    document.querySelectorAll(".mapping-table tbody tr:has(.mapping-select:checked) input[data-mapping-scope]").forEach(input => { input.value = ""; input.dispatchEvent(new Event("input", { bubbles: true })); });
  });

  document.getElementById("mapping-template")?.addEventListener("click", () => {
    const yaml = ["vdoms:", ...Object.keys(currentMigrationMapping.vdoms).flatMap(vdom => [`  ${JSON.stringify(vdom)}:`, "    vsys:", "    virtual_router:"]), "interfaces:", ...Object.entries(currentMigrationMapping.interfaces).flatMap(([vdom, items]) => [`  ${JSON.stringify(vdom)}:`, ...Object.keys(items).flatMap(name => [`    ${JSON.stringify(name)}:`, "      target_interface:", "      target_zone:"])])].join("\n") + "\n";
    const link = document.createElement("a"); link.href = URL.createObjectURL(new Blob([yaml], { type: "text/yaml" })); link.download = "target-mapping.yaml"; link.click(); URL.revokeObjectURL(link.href);
  });

  document.getElementById("mapping-import")?.addEventListener("change", async event => {
    const file = event.target.files?.[0]; if (!file) return;
    try {
      const response = await fetch("/api/migration/mapping/import", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ yaml: await file.text() }) });
      const imported = await readJson(response, "Could not import mapping YAML");
      currentMigrationMapping = JSON.parse(JSON.stringify(currentMigrationMapping));
      for (const [vdom, value] of Object.entries(imported.mapping.vdoms || {})) Object.assign(currentMigrationMapping.vdoms[vdom] ||= {}, value);
      for (const [vdom, entries] of Object.entries(imported.mapping.interfaces || {})) {
        currentMigrationMapping.interfaces[vdom] ||= {};
        for (const [name, value] of Object.entries(entries)) Object.assign(currentMigrationMapping.interfaces[vdom][name] ||= {}, value);
      }
      document.querySelectorAll("#migration-mapping-fields input[data-mapping-scope]").forEach(input => {
        input.value = input.dataset.mappingScope === "vdom" ? currentMigrationMapping.vdoms?.[input.dataset.vdom]?.[input.dataset.field] || "" : currentMigrationMapping.interfaces?.[input.dataset.vdom]?.[input.dataset.name]?.[input.dataset.field] || "";
      });
      invalidateMigrationPlan(); updateMappingCompletion();
    } catch (error) { showError(error.message); }
    event.target.value = "";
  });

  if (btnGenerateBundle) {
    btnGenerateBundle.addEventListener("click", async () => {
      if (!currentFile || !currentPreviewId) return;
      setBusy(btnGenerateBundle, true);
      hideError();
      try {
        const resp = await fetch("/api/migrate", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ preview_id: currentPreviewId, source_vendor: selectedSourceVendor, target_vendor: selectedTargetVendor, mapping: currentMigrationMapping }),
        });
        const artifact = await readJson(resp, "Migration planning failed");
        currentRenderedArtifactId = artifact.artifact_id;
        document.getElementById("migration-plan")?.classList.remove("hidden");
        const counts = artifact.counts || {};
        const summary = document.getElementById("migration-plan-summary");
        if (summary) summary.textContent = `${artifact.plan_status === "READY" ? "Migration artifact ready." : artifact.plan_status === "PARTIAL" ? "Plan created. Partial commands are ready." : "Plan created. Target mappings required."} ${counts.SUPPORTED || 0} supported, ${counts.renderable || 0} renderable, ${counts.MANUAL_REVIEW || 0} manual review, ${counts.UNSUPPORTED || 0} unsupported, ${artifact.commands} commands. ${artifact.blocking_reasons.join("; ")}`;
        btnDownloadBundle?.classList.toggle("hidden", artifact.commands === 0);
        if (btnDownloadBundle) {
          btnDownloadBundle.disabled = artifact.commands === 0;
          const label = btnDownloadBundle.querySelector("span:last-child");
          if (label) label.textContent = artifact.plan_status === "PARTIAL" ? "Generate partial bundle" : "Download bundle";
        }
        logToTerminal(`[PLAN] ${artifact.plan_status}: ${artifact.commands} commands ready.`, artifact.commands ? "term-success" : "term-error");
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
      formData.append("excel_profile", "fast");

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
    if (!currentFile || !sourceReady) return;
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
      btnPushCandidate.disabled = !sourceReady;
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

  const guideModal = document.getElementById("guide-modal");
  let guideTrigger = null;
  function closeGuide() {
    guideModal?.classList.add("hidden");
    if (guideModal) guideModal.setAttribute("aria-hidden", "true");
    document.body.classList.remove("modal-open");
    guideTrigger?.focus();
  }
  document
    .getElementById("btn-open-guide")
    ?.addEventListener("click", (event) => {
      if (!guideModal) return;
      guideTrigger = event.currentTarget;
      guideModal.classList.remove("hidden");
      guideModal.setAttribute("aria-hidden", "false");
      document.body.classList.add("modal-open");
      document.getElementById("btn-close-guide")?.focus();
    });
  document
    .getElementById("btn-close-guide")
    ?.addEventListener("click", closeGuide);
  guideModal?.addEventListener("click", (event) => {
    if (event.target === guideModal) closeGuide();
  });
  document.addEventListener("keydown", (event) => {
    if (!guideModal || guideModal.classList.contains("hidden")) return;
    if (event.key === "Escape") closeGuide();
    if (event.key !== "Tab") return;
    const focusable = [
      ...guideModal.querySelectorAll('button, a[href], input, [tabindex="0"]'),
    ].filter((element) => !element.disabled);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
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

  switchMode(activeMode);
  syncWorkspace();
});
