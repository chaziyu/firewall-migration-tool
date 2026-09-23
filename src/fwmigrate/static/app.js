document.addEventListener("DOMContentLoaded", () => {
  // =========================================================================
  // Application State
  // =========================================================================
  let currentFile = null;
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
      "Convert configuration",
      "Bring your firewall configuration to its next home.",
    ],
    extract: [
      "Extract an inventory",
      "Explore your source configuration in a reviewable Excel workbook.",
    ],
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
      name: "Cisco ASA / FTD",
      icon: "🌐",
      protocol: "Cisco Firepower Management Center (FMC) / ASA REST API",
      desc: "Authenticates with Cisco FMC REST API / ASA to pull network objects, ACL policies, and NAT definitions.",
      defaultPort: 443,
      authTypes: [{ id: "userpass", label: "Admin Credentials" }],
      fileAccept: ".cfg,.txt,.conf",
      dropText:
        "Supports Cisco ASA / Firepower <code>.cfg</code> or <code>.txt</code> configuration files",
      fields: [
        {
          id: "api-host",
          label: "FMC / ASA Host or IP",
          type: "text",
          required: true,
          placeholder: "fmc.corp.local or 192.168.1.1",
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
          placeholder: "apiadmin",
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
          label: "Domain UUID / Context",
          type: "text",
          required: false,
          placeholder: "e276abec-e0f2-11e3-8169-6d9ed49b625f",
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
  const optPruneObjects = document.getElementById("opt-prune-objects");
  const statTotalRules = document.getElementById("stat-total-rules");
  const statTotalObjects = document.getElementById("stat-total-objects");
  const statErrors = document.getElementById("stat-errors");
  const statWarnings = document.getElementById("stat-warnings");

  // Mode A Components
  const btnGenerateBundle = document.getElementById("btn-generate-bundle");
  const btnExtractExcel = document.getElementById("btn-extract-excel");

  // Mode B Target Form & Diagnostics
  const panHost = document.getElementById("pan-host");
  const panPort = document.getElementById("pan-port");
  const radioAuthTypes = document.querySelectorAll('input[name="auth-type"]');
  const authApikeyGroup = document.getElementById("auth-apikey-group");
  const authUserGroup = document.getElementById("auth-user-group");
  const authPassGroup = document.getElementById("auth-pass-group");
  const panApikey = document.getElementById("pan-apikey");
  const panUser = document.getElementById("pan-user");
  const panPass = document.getElementById("pan-pass");
  const panInsecure = document.getElementById("pan-insecure");
  const btnRunDiagnostics = document.getElementById("btn-run-diagnostics");

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
    const hasInput = hasFile;
    tabReport?.classList.toggle("hidden", !["fortigate", "palo_alto"].includes(selectedSourceVendor));
    if (btnGenerateBundle)
      btnGenerateBundle.disabled =
        !hasFile || !sourceReady || busyButtons.has(btnGenerateBundle);
    if (btnExtractExcel)
      btnExtractExcel.disabled =
        !hasInput || !sourceReady || busyButtons.has(btnExtractExcel);
    const exportHint = document.querySelector(
      "#mode-download-form .export-hint",
    );
    if (exportHint) {
      const hintCopy = sourceReady
        ? "Ready to generate your migration bundle."
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

  function switchMode(mode) {
    if (!MODE_COPY[mode]) return;
    if (mode === "live" && activeMode !== "live") {
      offlineTargetVendor = selectedTargetVendor;
      selectedTargetVendor = "palo_alto";
    } else if (mode !== "live" && activeMode === "live") {
      selectedTargetVendor = offlineTargetVendor;
    }
    if (targetVendorSelect) targetVendorSelect.value = selectedTargetVendor;
    updateTargetBundleDescriptions(selectedTargetVendor);
    activeMode = mode;
    [
      [tabDownload, "download"],
      [tabReport, "report"],
      [tabLive, "live"],
      [tabExtract, "extract"],
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
    reportContainer?.classList.toggle("hidden", mode !== "report" || !currentReport);
    if (targetVendorGroup)
      targetVendorGroup.classList.toggle("hidden", ["extract", "report"].includes(mode));
    if (vendorSelectorGrid)
      vendorSelectorGrid.classList.toggle(
        "extract-mode",
        ["extract", "report"].includes(mode),
      );
    document
      .getElementById("optimizer-controls")
      ?.classList.toggle("hidden", mode === "extract");
    setText("page-title", MODE_COPY[mode][0]);
    setText("page-description", MODE_COPY[mode][1]);
    syncWorkspace();

    if (mode === "report") {
      renderReport();
      logToTerminal("[MODE] Switched to FortiGate source report view.", "term-system");
    } else if (mode === "download") {
      logToTerminal(
        "[MODE] Switched to Package Export Mode (native configuration bundle).",
        "term-system",
      );
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
  enableTabKeys([tabReport, tabDownload, tabExtract, tabLive]);
  enableTabKeys([btnIngestFile]);

  // =========================================================================
  // 3. Vendor Selector Dropdowns
  // =========================================================================
  if (sourceVendorSelect) {
    selectedSourceVendor = sourceVendorSelect.value || "fortigate";
    sourceVendorSelect.addEventListener("change", (e) => {
      selectedSourceVendor = e.target.value;
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
      const targetName =
        targetVendorSelect.options[targetVendorSelect.selectedIndex]?.text ||
        selectedTargetVendor;
      logToTerminal(
        `[VENDOR] Target platform selected: ${targetName}`,
        "term-system",
      );
      updateTargetBundleDescriptions(selectedTargetVendor);
      syncWorkspace();
    });
  }

  function updateTargetBundleDescriptions(target) {
    const panDesc = document.getElementById("feature-card-pan-desc");
    const auditDesc = document.getElementById("feature-card-audit-desc");

    if (target === "fortigate") {
      if (panDesc)
        panDesc.innerHTML =
          "Native <code>fortigate_config.conf</code> script for FortiOS CLI execution";
    } else if (target === "cisco_asa") {
      if (panDesc)
        panDesc.innerHTML =
          "Native <code>cisco_asa_config.cfg</code> CLI commands for ASA / Firepower import";
    } else if (target === "checkpoint") {
      if (panDesc)
        panDesc.innerHTML =
          "Native <code>checkpoint_mgmt_cli.sh</code> automation script for Check Point MDS";
    } else if (target === "juniper_srx") {
      if (panDesc)
        panDesc.innerHTML =
          "Native <code>junos_srx_config.set</code> batch configuration syntax";
    } else {
      if (panDesc)
        panDesc.innerHTML =
          "Native <code>palo_alto_config.xml</code> ready for Panorama / Firewall WebGUI import";
    }
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
          ? "Configuration read. Review the inventory before continuing."
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
  if (btnGenerateBundle) {
    btnGenerateBundle.addEventListener("click", async () => {
      if (!currentFile) {
        showToast(
          "info",
          "No Input",
          "Please upload a configuration file first. Live collections are available for Excel extraction only.",
        );
        return;
      }

      setBusy(btnGenerateBundle, true);
      const exportSource = selectedSourceVendor;
      const exportTarget = selectedTargetVendor;
      const btnText = btnGenerateBundle.querySelector("span:last-child");
      const originalText = btnText
        ? btnText.textContent
        : "Generate Migration Bundle (.zip)";
      if (btnText) btnText.textContent = "Compiling Migration Package...";
      hideError();

      const formData = new FormData();
      if (currentFile) {
        formData.append("file", currentFile);
      }
      formData.append("source_vendor", selectedSourceVendor);
      formData.append("target_vendor", selectedTargetVendor);
      formData.append(
        "optimize",
        optPruneObjects
          ? optPruneObjects.checked
            ? "true"
            : "false"
          : "false",
      );

      logToTerminal(
        `[EXPORT] Compiling ${selectedSourceVendor} -> ${selectedTargetVendor} migration bundle...`,
        "term-system",
      );

      try {
        const resp = await fetch("/api/migrate", {
          method: "POST",
          body: formData,
        });

        if (!resp.ok) {
          const errData = await resp.json().catch(() => ({}));
          const blockingReasons = Array.isArray(errData.blocking_reasons)
            ? errData.blocking_reasons.filter(Boolean)
            : [];
          blockingReasons.forEach((reason) =>
            logToTerminal(`[SAFETY] ${reason}`, "term-error"),
          );
          const detail = blockingReasons.length
            ? ` ${blockingReasons[0]}${
                blockingReasons.length > 1
                  ? ` (+${blockingReasons.length - 1} more)`
                  : ""
              }`
            : "";
          throw new Error(
            `${errData.error || "Failed to generate package"}${detail}`,
          );
        }

        const blob = await resp.blob();
        const saved = await downloadBlob(
          blob,
          `migration_${exportSource}_to_${exportTarget}.zip`,
        );
        if (saved) {
          showToast(
            "success",
            "Bundle Generated",
            `Your migration bundle for ${VENDOR_CONFIGS[exportTarget]?.name || exportTarget} is ready.`,
          );
          logToTerminal(
            `[EXPORT] Generated migration_${exportSource}_to_${exportTarget}.zip`,
            "term-success",
          );
        }
      } catch (err) {
        showError(err.message);
        showToast("error", "Export Failed", err.message);
        logToTerminal(
          `[ERROR] Bundle generation failed: ${err.message}`,
          "term-error",
        );
      } finally {
        setBusy(btnGenerateBundle, false);
        if (btnText) btnText.textContent = originalText;
      }
    });
  }

  // =========================================================================
  // 8b. Vendor-native Excel source report
  // =========================================================================
  if (btnExtractExcel) {
    btnExtractExcel.addEventListener("click", async () => {
      if (!currentFile) {
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
  radioAuthTypes.forEach((radio) => {
    radio.addEventListener("change", (e) => {
      if (e.target.value === "apikey") {
        if (authApikeyGroup) authApikeyGroup.classList.remove("hidden");
        if (authUserGroup) authUserGroup.classList.add("hidden");
        if (authPassGroup) authPassGroup.classList.add("hidden");
      } else {
        if (authApikeyGroup) authApikeyGroup.classList.add("hidden");
        if (authUserGroup) authUserGroup.classList.remove("hidden");
        if (authPassGroup) authPassGroup.classList.remove("hidden");
      }
    });
  });

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
  [panHost, panPort, panApikey, panUser, panPass, panInsecure].forEach(
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

  if (btnRunDiagnostics) {
    btnRunDiagnostics.addEventListener("click", async () => {
      const host = panHost ? panHost.value.trim() : "";
      const port = panPort ? parseInt(panPort.value.trim() || "443") : 443;
      const authType =
        document.querySelector('input[name="auth-type"]:checked')?.value ||
        "apikey";
      const apiKey = panApikey ? panApikey.value.trim() : "";
      const username = panUser ? panUser.value.trim() : "";
      const password = panPass ? panPass.value.trim() : "";
      const verifySsl = panInsecure ? !panInsecure.checked : true;

      logToTerminal(
        `[DIAGNOSTICS] Probing environment and target diagnostics (${host}:${port})...`,
        "term-system",
      );
      btnRunDiagnostics.disabled = true;
      setDiagLoadingAll();

      try {
        const payload = {
          host,
          port,
          verify_ssl: verifySsl,
        };

        if (authType === "apikey") {
          payload.api_key = apiKey;
        } else {
          payload.username = username;
          payload.password = password;
        }

        const resp = await fetch("/api/diagnostics", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        const data = await readJson(resp, "Diagnostics failed");
        if (!Array.isArray(data.results))
          throw new Error("The server returned no diagnostic results.");
        data.results.forEach((res) => {
          updateDiagCard(res.name, res.status, res.message);
          logToTerminal(
            `[DIAGNOSTICS] ${res.name.toUpperCase()}: ${res.status.toUpperCase()} - ${res.message}`,
            res.status === "ok"
              ? "term-success"
              : res.status === "error"
                ? "term-error"
                : "term-system",
          );
        });
        showToast(
          "info",
          "Diagnostics Complete",
          "Environment and line-of-sight checks finished.",
        );
      } catch (err) {
        document.querySelectorAll(".diag-card.running").forEach((card) => {
          card.className = "diag-card failed";
          const message = card.querySelector(".diag-msg");
          if (message) message.textContent = "Unable to complete check";
        });
        showError(`Diagnostics error: ${err.message}`);
        logToTerminal(
          `[ERROR] Diagnostics failed: ${err.message}`,
          "term-error",
        );
      } finally {
        btnRunDiagnostics.disabled = false;
        document.querySelectorAll(".diag-card.running").forEach((card) => {
          card.className = "diag-card pending";
          const message = card.querySelector(".diag-msg");
          if (message) message.textContent = "No result returned";
        });
      }
    });
  }

  function setDiagLoadingAll() {
    ["diag-cli", "diag-ssh", "diag-tcp", "diag-panos"].forEach((id) => {
      const card = document.getElementById(id);
      if (card) {
        card.className = "diag-card running";
        const msg = document.getElementById(`${id}-msg`);
        if (msg) msg.textContent = "Probing...";
      }
    });
  }

  function updateDiagCard(name, status, msg) {
    let cardId = "diag-cli";
    if (name === "cli") cardId = "diag-cli";
    else if (name === "ssh") cardId = "diag-ssh";
    else if (name === "palo_alto_line_of_sight") cardId = "diag-tcp";
    else if (name === "palo_alto_auth") cardId = "diag-panos";

    const card = document.getElementById(cardId);
    const msgEl = document.getElementById(`${cardId}-msg`);

    if (card) {
      const cardClass =
        status === "ok" ? "success" : status === "error" ? "failed" : "pending";
      card.className = `diag-card ${cardClass}`;
    }
    if (msgEl) {
      msgEl.textContent = msg;
    }
  }

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
      [panHost, panApikey, panUser, panPass].forEach((input) => {
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

  updateTargetBundleDescriptions(selectedTargetVendor);
  switchMode(activeMode);
  syncWorkspace();
});
