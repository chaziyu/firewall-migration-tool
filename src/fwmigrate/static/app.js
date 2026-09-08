document.addEventListener("DOMContentLoaded", () => {
  // =========================================================================
  // Application State
  // =========================================================================
  let currentFile = null;
  let currentApiSessionId = null;
  let currentSessionId = null;
  let selectedSourceVendor = "fortigate";
  let selectedTargetVendor = "palo_alto";
  let offlineTargetVendor = "palo_alto";
  let activeMode = "download"; // 'download', 'live', or 'extract'
  let activeIngestMethod = "file"; // 'file' or 'api'
  let currentPolicies = [];
  let sourceReady = false;
  let sourceFailed = false;
  let sourceRevision = 0;
  let previewController = null;
  let liveOperationRunning = false;
  let sessionApproved = false;
  const busyButtons = new Set();

  const MODE_COPY = {
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
      "Verify your target, review a plan, then apply with confidence.",
    ],
  };

  // Vendor metadata specifications for dynamic API credential forms & guides
  const VENDOR_CONFIGS = {
    fortigate: {
      name: "Fortinet FortiGate",
      icon: "🛡️",
      protocol: "FortiOS REST API (HTTPS /api/v2/cmdb)",
      desc: "Directly connects over HTTPS to extract interfaces, policies, addresses, VIPs, and services in real-time.",
      defaultPort: 443,
      authTypes: [
        { id: "apikey", label: "REST API Token" },
        { id: "userpass", label: "Admin Username & Password" },
      ],
      fileAccept: ".conf,.cfg,.txt",
      dropText:
        "Supports FortiOS <code>.conf</code>, <code>.cfg</code>, or <code>.txt</code> backup files",
      fields: [
        {
          id: "api-host",
          label: "FortiGate IP / Hostname",
          type: "text",
          required: true,
          placeholder: "192.168.1.99 or fg.corp.local",
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
          id: "api-vdom",
          label: "Virtual Domain (VDOM)",
          type: "text",
          required: false,
          value: "root",
          placeholder: "root",
          col: "col-6",
        },
        {
          id: "api-token",
          label: "REST API Token",
          type: "password",
          required: true,
          placeholder: "Bearer token",
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
  const tabLive = document.getElementById("tab-live");
  const tabExtract = document.getElementById("tab-extract");
  const modeDownloadForm = document.getElementById("mode-download-form");
  const modeLiveForm = document.getElementById("mode-live-form");
  const modeExtractForm = document.getElementById("mode-extract-form");

  // Ingestion Method Tabs
  const btnIngestFile = document.getElementById("btn-ingest-file");
  const btnIngestApi = document.getElementById("btn-ingest-api");
  const ingestFileContainer = document.getElementById("ingest-file-container");
  const ingestApiContainer = document.getElementById("ingest-api-container");

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

  // API Ingest Components
  const apiCredentialFields = document.getElementById("api-credential-fields");
  const btnApiExtract = document.getElementById("btn-api-extract");
  const apiIngestSuccess = document.getElementById("api-ingest-success");
  const apiHostname = document.getElementById("api-hostname");
  const apiStatsSummary = document.getElementById("api-stats-summary");
  const btnClearApiIngest = document.getElementById("btn-clear-api-ingest");
  const apiIngestError = document.getElementById("api-ingest-error");
  const apiErrorTitle = document.getElementById("api-error-title");
  const apiErrorDetail = document.getElementById("api-error-detail");
  const apiErrorHint = document.getElementById("api-error-hint");
  const btnDismissApiError = document.getElementById("btn-dismiss-api-error");

  // Optimizer Panel Stats
  const optimizerPanel = document.getElementById("optimizer-panel");
  const optPruneObjects = document.getElementById("opt-prune-objects");
  const statTotalRules = document.getElementById("stat-total-rules");
  const statTotalObjects = document.getElementById("stat-total-objects");
  const statUnusedObjects = document.getElementById("stat-unused-objects");
  const statShadowedRules = document.getElementById("stat-shadowed-rules");

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

  // Mode B Stepper & Action Buttons
  const btnPlanDryrun = document.getElementById("btn-plan-dryrun");
  const planSummaryBadges = document.getElementById("plan-summary-badges");
  const badgeAdd = document.getElementById("badge-add");
  const badgeChange = document.getElementById("badge-change");
  const badgeDestroy = document.getElementById("badge-destroy");
  const planStatusMsg = document.getElementById("plan-status-msg");
  const btnApplyLive = document.getElementById("btn-apply-live");
  const applyStatusMsg = document.getElementById("apply-status-msg");
  const btnRollback = document.getElementById("btn-rollback");
  const rollbackStatusMsg = document.getElementById("rollback-status-msg");

  // Terminal
  const terminalStreamBody = document.getElementById("terminal-stream-body");
  const termAutoscroll = document.getElementById("term-autoscroll");
  const btnClearTerm = document.getElementById("btn-clear-term");
  const btnCopyTerm = document.getElementById("btn-copy-term");

  // Post Actions Bar
  const postActionsBar = document.getElementById("post-actions-bar");
  const btnDownloadState = document.getElementById("btn-download-state");
  const btnDownloadAudit = document.getElementById("btn-download-audit");

  // Toast Container & Error Banner
  const toastContainer = document.getElementById("toast-container");
  const errorBanner = document.getElementById("error-message");

  function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
  }

  function syncWorkspace() {
    const hasInput = Boolean(currentFile || currentApiSessionId);
    [btnGenerateBundle, btnExtractExcel, btnPlanDryrun].forEach((button) => {
      if (button)
        button.disabled =
          !sourceReady || busyButtons.has(button) || liveOperationRunning;
    });
    setText(
      "summary-source",
      VENDOR_CONFIGS[selectedSourceVendor]?.name || selectedSourceVendor,
    );
    setText(
      "summary-target",
      activeMode === "extract"
        ? "Source inventory"
        : VENDOR_CONFIGS[selectedTargetVendor]?.name || selectedTargetVendor,
    );
    setText(
      "summary-file",
      currentFile?.name ||
        (currentApiSessionId
          ? "Live device configuration"
          : "No configuration selected"),
    );
    setText(
      "summary-state",
      sourceReady
        ? "Ready for review"
        : sourceFailed
          ? "Review source file"
          : hasInput
            ? "Reading configuration"
            : "Awaiting source",
    );
    const summaryState = document.getElementById("summary-state");
    if (summaryState)
      summaryState.dataset.state = sourceReady
        ? "ready"
        : sourceFailed
          ? "error"
          : hasInput
            ? "loading"
            : "idle";
    setText(
      "sidebar-workspace-status",
      sourceReady
        ? "Configuration ready"
        : sourceFailed
          ? "Source needs attention"
          : hasInput
            ? "Reading configuration"
            : "No source connected",
    );
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
        liveOperationRunning || activeMode === "live";
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

  function resetDeployment() {
    currentSessionId = null;
    sessionApproved = false;
    if (btnApplyLive) btnApplyLive.disabled = true;
    if (btnRollback) btnRollback.disabled = true;
    planSummaryBadges?.classList.add("hidden");
    postActionsBar?.classList.add("hidden");
    if (planStatusMsg)
      planStatusMsg.textContent =
        "Review a dry-run plan before applying changes.";
    if (applyStatusMsg)
      applyStatusMsg.textContent =
        "A reviewed plan is required before live deployment.";
    if (rollbackStatusMsg)
      rollbackStatusMsg.textContent =
        "Remove resources managed by this deployment.";
  }

  function resetPreview() {
    sourceRevision += 1;
    previewController?.abort();
    previewController = null;
    sourceReady = false;
    sourceFailed = false;
    currentPolicies = [];
    optimizerPanel?.classList.add("hidden");
    [
      statTotalRules,
      statTotalObjects,
      statUnusedObjects,
      statShadowedRules,
    ].forEach((element) => {
      if (element) element.textContent = "0";
    });
    setText("inventory-interface-count", "—");
    setText("inventory-policy-count", "—");
    setPreviewStatus("");
    resetDeployment();
    syncWorkspace();
  }

  function setLiveOperationRunning(running) {
    liveOperationRunning = running;
    [
      sourceVendorSelect,
      targetVendorSelect,
      btnRemoveFile,
      btnClearApiIngest,
      btnIngestFile,
      btnIngestApi,
      fileInput,
      btnApiExtract,
      panHost,
      panPort,
      panApikey,
      panUser,
      panPass,
      panInsecure,
      optPruneObjects,
      document.getElementById("btn-new-workspace"),
      ...radioAuthTypes,
      ...document.querySelectorAll("#api-credential-fields input"),
    ].forEach((element) => {
      if (element) element.disabled = running;
    });
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
  if (tabLive) {
    tabLive.addEventListener("click", () => switchMode("live"));
  }
  if (tabExtract) {
    tabExtract.addEventListener("click", () => switchMode("extract"));
  }

  function switchMode(mode) {
    if (!MODE_COPY[mode]) return;
    if (liveOperationRunning && mode !== activeMode) return;
    // The existing deployment endpoint provisions PAN-OS. Other targets remain
    // available for downloadable bundles; the live form must reflect its target.
    if (mode === "live" && activeMode !== "live") {
      offlineTargetVendor = selectedTargetVendor;
      selectedTargetVendor = "palo_alto";
      resetDeployment();
    } else if (mode !== "live" && activeMode === "live") {
      selectedTargetVendor = offlineTargetVendor;
      resetDeployment();
    }
    if (targetVendorSelect) targetVendorSelect.value = selectedTargetVendor;
    updateTargetBundleDescriptions(selectedTargetVendor);
    activeMode = mode;
    [
      [tabDownload, "download"],
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
    if (targetVendorGroup)
      targetVendorGroup.classList.toggle("hidden", mode === "extract");
    if (vendorSelectorGrid)
      vendorSelectorGrid.classList.toggle("extract-mode", mode === "extract");
    document
      .getElementById("optimizer-controls")
      ?.classList.toggle("hidden", mode === "extract");
    setText("page-title", MODE_COPY[mode][0]);
    setText("page-description", MODE_COPY[mode][1]);
    syncWorkspace();

    if (mode === "download") {
      logToTerminal(
        "[MODE] Switched to Package Export Mode (XML/CLI & Terraform Bundle).",
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

  // =========================================================================
  // 2. Ingestion Method Tabs (Upload File vs Live REST API)
  // =========================================================================
  function switchIngestMethod(method) {
    if (liveOperationRunning || activeIngestMethod === method) return;
    activeIngestMethod = method;
    clearSource();
    [btnIngestFile, btnIngestApi].forEach((button, index) => {
      if (!button) return;
      const selected = method === (index === 0 ? "file" : "api");
      button.classList.toggle("active", selected);
      button.setAttribute("aria-selected", String(selected));
      button.tabIndex = selected ? 0 : -1;
    });
    ingestFileContainer?.classList.toggle("hidden", method !== "file");
    ingestApiContainer?.classList.toggle("hidden", method !== "api");
    logToTerminal(
      `[INGEST] Switched to ${method === "file" ? "configuration upload" : "live API extraction"}.`,
      "term-system",
    );
  }

  btnIngestFile?.addEventListener("click", () => switchIngestMethod("file"));
  btnIngestApi?.addEventListener("click", () => switchIngestMethod("api"));

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
  enableTabKeys([tabDownload, tabExtract, tabLive]);
  enableTabKeys([btnIngestFile, btnIngestApi]);

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

      renderApiCredentialFields(selectedSourceVendor);
      syncWorkspace();
    });
  }

  if (targetVendorSelect) {
    selectedTargetVendor = targetVendorSelect.value || "palo_alto";
    targetVendorSelect.addEventListener("change", (e) => {
      selectedTargetVendor = e.target.value;
      resetDeployment();
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
    const tfDesc = document.getElementById("feature-card-tf-desc");
    const auditDesc = document.getElementById("feature-card-audit-desc");

    if (target === "fortigate") {
      if (panDesc)
        panDesc.innerHTML =
          "Native <code>fortigate_config.conf</code> script for FortiOS CLI execution";
      if (tfDesc)
        tfDesc.innerHTML =
          "Production HCL targeting <code>fortinetdev/fortios</code> (<code>main.tf</code>, <code>variables.tf</code>)";
    } else if (target === "cisco_asa") {
      if (panDesc)
        panDesc.innerHTML =
          "Native <code>cisco_asa_config.cfg</code> CLI commands for ASA / Firepower import";
      if (tfDesc)
        tfDesc.innerHTML =
          "Production HCL targeting <code>CiscoDevNet/ciscoasa</code> (<code>main.tf</code>, <code>variables.tf</code>)";
    } else if (target === "checkpoint") {
      if (panDesc)
        panDesc.innerHTML =
          "Native <code>checkpoint_mgmt_cli.sh</code> automation script for Check Point MDS";
      if (tfDesc)
        tfDesc.innerHTML =
          "Production HCL targeting <code>CheckPointSW/checkpoint</code> (<code>main.tf</code>, <code>variables.tf</code>)";
    } else if (target === "juniper_srx") {
      if (panDesc)
        panDesc.innerHTML =
          "Native <code>junos_srx_config.set</code> batch configuration syntax";
      if (tfDesc)
        tfDesc.innerHTML =
          "Production HCL targeting <code>juniper/junos</code> (<code>main.tf</code>, <code>variables.tf</code>)";
    } else {
      if (panDesc)
        panDesc.innerHTML =
          "Native <code>palo_alto_config.xml</code> ready for Panorama / Firewall WebGUI import";
      if (tfDesc)
        tfDesc.innerHTML =
          "Production HCL targeting <code>PaloAltoNetworks/panos</code> (<code>main.tf</code>, <code>terraform.tfvars</code>)";
    }
  }

  // =========================================================================
  // 4. Dynamic API Credential Form Generator
  // =========================================================================
  function renderApiCredentialFields(vendorId) {
    if (!apiCredentialFields) return;
    const config = VENDOR_CONFIGS[vendorId] || VENDOR_CONFIGS["fortigate"];

    // Build HTML for fields
    let html = "";

    // If vendor supports multiple auth types, render an auth switcher
    if (config.authTypes && config.authTypes.length > 1) {
      html += `
                <div class="form-group col-12">
                    <label>Authentication Method</label>
                    <div class="radio-toggle" id="api-auth-toggle-group">
                        ${config.authTypes
                          .map(
                            (at, idx) => `
                            <label class="radio-label">
                                <input type="radio" name="api-auth-type" value="${at.id}" ${idx === 0 ? "checked" : ""}>
                                <span>${at.label}</span>
                            </label>
                        `,
                          )
                          .join("")}
                    </div>
                </div>
            `;
    }

    // Render input fields
    config.fields.forEach((field) => {
      const colClass = field.col || "col-6";
      const authFilter = field.authType
        ? `data-auth-type="${field.authType}"`
        : "";
      const hideClass =
        field.authType && field.authType !== config.authTypes?.[0]?.id
          ? "hidden"
          : "";

      if (field.type === "checkbox") {
        html += `
                    <div class="form-group ${colClass} ${hideClass}" ${authFilter}>
                        <label class="checkbox-label">
                            <input type="checkbox" id="${field.id}" ${field.checked ? "checked" : ""}>
                            <span>${field.label}</span>
                        </label>
                    </div>
                `;
      } else if (field.type === "password") {
        html += `
                    <div class="form-group ${colClass} ${hideClass}" ${authFilter} id="group-${field.id}">
                        <label for="${field.id}">${field.label} ${field.required ? '<span class="req">*</span>' : ""}</label>
                        <div class="password-wrapper">
                            <input type="password" id="${field.id}" placeholder="${field.placeholder || ""}" ${field.required ? "required" : ""}>
                            <button type="button" class="btn-toggle-password" data-target="${field.id}" aria-label="Show password" aria-pressed="false">Show</button>
                        </div>
                    </div>
                `;
      } else {
        html += `
                    <div class="form-group ${colClass} ${hideClass}" ${authFilter} id="group-${field.id}">
                        <label for="${field.id}">${field.label} ${field.required ? '<span class="req">*</span>' : ""}</label>
                        <input type="${field.type}" id="${field.id}" value="${field.value !== undefined ? field.value : ""}" placeholder="${field.placeholder || ""}" ${field.required ? "required" : ""}>
                    </div>
                `;
      }
    });

    apiCredentialFields.innerHTML = html;

    // Wire up auth radio toggle if present
    const authRadios = apiCredentialFields.querySelectorAll(
      'input[name="api-auth-type"]',
    );
    authRadios.forEach((radio) => {
      radio.addEventListener("change", (e) => {
        if (currentApiSessionId || busyButtons.has(btnApiExtract))
          clearSource();
        const selectedAuth = e.target.value;
        apiCredentialFields
          .querySelectorAll("[data-auth-type]")
          .forEach((el) => {
            if (el.getAttribute("data-auth-type") === selectedAuth) {
              el.classList.remove("hidden");
            } else {
              el.classList.add("hidden");
            }
          });
      });
    });

    // Clear validation errors on typing
    apiCredentialFields.querySelectorAll("input").forEach((inp) => {
      inp.addEventListener("input", () => {
        inp.classList.remove("input-invalid");
        inp.removeAttribute("aria-invalid");
        const parent = inp.closest(".form-group") || inp.parentElement;
        const err = parent.querySelector(".field-error-text");
        if (err) err.remove();
        if (currentApiSessionId || busyButtons.has(btnApiExtract))
          clearSource();
      });
    });
  }

  // Initial render for default vendor
  renderApiCredentialFields(selectedSourceVendor);

  // =========================================================================
  // 5. Live REST API Ingestion Handler
  // =========================================================================
  if (btnApiExtract) {
    btnApiExtract.addEventListener("click", async () => {
      clearInputErrors();
      hideApiIngestError();
      hideError();

      const hostEl = document.getElementById("api-host");
      const portEl = document.getElementById("api-port");
      const tokenEl = document.getElementById("api-token");
      const userEl = document.getElementById("api-username");
      const passEl = document.getElementById("api-password");
      const vdomEl = document.getElementById("api-vdom");
      const vsysEl = document.getElementById("api-vsys");
      const domainEl = document.getElementById("api-domain");
      const insecureEl = document.getElementById("api-insecure");

      const host = hostEl ? hostEl.value.trim() : "";
      const port = portEl ? parseInt(portEl.value.trim() || "443") : 443;
      const verifySsl = insecureEl ? !insecureEl.checked : true;

      const authTypeRadio = document.querySelector(
        'input[name="api-auth-type"]:checked',
      );
      const authType = authTypeRadio
        ? authTypeRadio.value
        : tokenEl
          ? "apikey"
          : "userpass";

      // Validation
      if (!host) {
        showInputError("api-host", "Host or IP address is required.");
        showToast(
          "error",
          "Missing Host",
          "Please specify a device IP address or hostname.",
        );
        return;
      }
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        showInputError("api-port", "Enter a port between 1 and 65535.");
        return;
      }

      if (authType === "apikey" && tokenEl && !tokenEl.value.trim()) {
        showInputError(
          "api-token",
          "API Token is required for token authentication.",
        );
        showToast(
          "error",
          "Missing API Token",
          "Please enter your REST API token.",
        );
        return;
      }

      if (authType === "userpass") {
        let hasErr = false;
        if (userEl && !userEl.value.trim()) {
          showInputError("api-username", "Admin Username is required.");
          hasErr = true;
        }
        if (passEl && !passEl.value.trim()) {
          showInputError("api-password", "Admin Password is required.");
          hasErr = true;
        }
        if (hasErr) {
          showToast(
            "error",
            "Missing Credentials",
            "Please provide admin username and password.",
          );
          return;
        }
      }

      // Prepare Payload
      const payload = {
        host,
        port,
        verify_ssl: verifySsl,
      };

      if (authType === "apikey" && tokenEl) {
        payload.api_key = tokenEl.value.trim();
      }
      if (authType === "userpass" && userEl && userEl.value.trim()) {
        payload.username = userEl.value.trim();
      }
      if (authType === "userpass" && passEl && passEl.value) {
        payload.password = passEl.value;
      }
      if (vdomEl) payload.vdom = vdomEl.value.trim() || "root";
      if (vsysEl) payload.vsys = vsysEl.value.trim() || "vsys1";
      if (domainEl) payload.domain = domainEl.value.trim();

      clearSource();
      const requestRevision = sourceRevision;
      setBusy(btnApiExtract, true);
      const btnText = btnApiExtract.querySelector(".btn-text");
      const spinner = btnApiExtract.querySelector(".spinner");
      if (btnText) btnText.textContent = `Connecting to ${host}:${port}...`;
      if (spinner) spinner.classList.remove("hidden");
      if (apiIngestSuccess) apiIngestSuccess.classList.add("hidden");

      const vendorName =
        VENDOR_CONFIGS[selectedSourceVendor]?.name || selectedSourceVendor;
      logToTerminal(
        `[INGEST] Connecting to ${vendorName} live API (${host}:${port})...`,
        "term-system",
      );

      try {
        const endpoint = `/api/ingest/${selectedSourceVendor}`;
        const resp = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        const data = await readJson(
          resp,
          `Failed to extract configuration from ${vendorName}`,
        );
        if (requestRevision !== sourceRevision) return;
        if (!data.session_id)
          throw new Error(
            "The server did not return a configuration session. Please reconnect.",
          );
        const stats = data.stats || {};

        currentApiSessionId = data.session_id;
        currentFile = null; // Clear active file

        if (apiHostname)
          apiHostname.textContent = `${data.hostname || host} (Live Connected)`;
        if (apiStatsSummary) {
          apiStatsSummary.textContent = `${stats.interfaces || 0} interfaces • ${stats.addresses || 0} addresses • ${stats.policies || 0} policies • ${stats.nat_rules || 0} NAT rules`;
        }
        if (apiIngestSuccess) apiIngestSuccess.classList.remove("hidden");
        hideApiIngestError();

        showToast(
          "success",
          "Extraction Successful",
          `Extracted configuration from ${vendorName} '${data.hostname || host}'`,
        );
        logToTerminal(
          `[INGEST] Pulled running configuration from '${data.hostname || host}' (${stats.interfaces || 0} interfaces, ${stats.policies || 0} policies).`,
          "term-success",
        );

        // Load Migration Preview & Rule Matrix
        fetchMigrationPreview();
      } catch (err) {
        if (requestRevision !== sourceRevision) return;
        currentApiSessionId = null;
        if (apiIngestSuccess) apiIngestSuccess.classList.add("hidden");
        if (!currentFile) {
          if (btnGenerateBundle) btnGenerateBundle.disabled = true;
          if (btnExtractExcel) btnExtractExcel.disabled = true;
          if (btnPlanDryrun) btnPlanDryrun.disabled = true;
        }
        showApiIngestError(err.message, vendorName);
        logToTerminal(
          `[ERROR] Live API Extraction failed: ${err.message}`,
          "term-error",
        );
      } finally {
        setBusy(btnApiExtract, false);
        if (btnText)
          btnText.textContent = "Connect & Pull Running Configuration";
        if (spinner) spinner.classList.add("hidden");
      }
    });
  }

  if (btnClearApiIngest) {
    btnClearApiIngest.addEventListener("click", () => {
      clearSource();
      logToTerminal("[INGEST] Live API session cleared.", "term-system");
    });
  }

  if (btnDismissApiError) {
    btnDismissApiError.addEventListener("click", hideApiIngestError);
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
    if (!file || liveOperationRunning) return;
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
    currentApiSessionId = null;

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

  function clearSource() {
    currentFile = null;
    currentApiSessionId = null;
    if (fileInput) fileInput.value = "";
    selectedFileCard?.classList.add("hidden");
    dropzone?.classList.remove("hidden");
    apiIngestSuccess?.classList.add("hidden");
    hideApiIngestError();
    hideError();
    resetPreview();
  }

  // =========================================================================
  // 7. Migration Intelligence Preview
  // =========================================================================
  async function fetchMigrationPreview() {
    if (!currentFile && !currentApiSessionId) return;
    previewController?.abort();
    const controller = new AbortController();
    previewController = controller;
    const requestRevision = sourceRevision;
    sourceReady = false;
    sourceFailed = false;
    setPreviewStatus(
      "Reading your configuration and preparing the inventory…",
      "loading",
    );
    syncWorkspace();

    const formData = new FormData();
    if (currentFile) {
      formData.append("file", currentFile);
    } else if (currentApiSessionId) {
      formData.append("session_id", currentApiSessionId);
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
      const stats = data.stats || {};
      const optimization = data.optimization || {};
      const count = (value) => Math.max(0, Number(value) || 0);
      if (optimizerPanel) optimizerPanel.classList.remove("hidden");
      if (statTotalRules) statTotalRules.textContent = count(stats.policies);
      if (statTotalObjects)
        statTotalObjects.textContent =
          count(stats.addresses) + count(stats.services);
      if (statUnusedObjects)
        statUnusedObjects.textContent =
          count(optimization.unused_addresses_count) +
          count(optimization.unused_services_count);
      if (statShadowedRules)
        statShadowedRules.textContent = count(
          optimization.shadowed_rules_count,
        );
      setText("inventory-interface-count", count(stats.interfaces));
      setText("inventory-policy-count", count(stats.policies));
      currentPolicies = Array.isArray(data.policies) ? data.policies : [];
      sourceReady = true;
      const itemCount = Object.values(stats).reduce(
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
      setText("summary-state", "Could not read source");
    } finally {
      if (requestRevision === sourceRevision) {
        previewController = null;
        syncWorkspace();
        if (!sourceReady) {
          setText("summary-state", "Review source file");
          setText("sidebar-workspace-status", "Source needs attention");
        }
      }
    }
  }

  // =========================================================================
  // 8. Mode A: Export Target Migration Bundle (.zip)
  // =========================================================================
  if (btnGenerateBundle) {
    btnGenerateBundle.addEventListener("click", async () => {
      if (!currentFile && !currentApiSessionId) {
        showToast(
          "info",
          "No Input",
          "Please upload a configuration file or pull from Live REST API first.",
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
      } else if (currentApiSessionId) {
        formData.append("session_id", currentApiSessionId);
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
          throw new Error(errData.error || "Failed to generate package");
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
  // 8b. Vendor-neutral Excel source inventory
  // =========================================================================
  if (btnExtractExcel) {
    btnExtractExcel.addEventListener("click", async () => {
      if (!currentFile && !currentApiSessionId) {
        showToast(
          "info",
          "No Input",
          "Please upload a configuration file or pull from Live REST API first.",
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
      } else {
        formData.append("session_id", currentApiSessionId);
      }
      formData.append("source_vendor", selectedSourceVendor);

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
      resetDeployment();
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
        resetDeployment();
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
          auto_download_tf: true,
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
    ["diag-tf-local", "diag-tf-reg", "diag-tcp", "diag-panos"].forEach((id) => {
      const card = document.getElementById(id);
      if (card) {
        card.className = "diag-card running";
        const msg = document.getElementById(`${id}-msg`);
        if (msg) msg.textContent = "Probing...";
      }
    });
  }

  function updateDiagCard(name, status, msg) {
    let cardId = "diag-tf-local";
    if (name === "terraform_cli") cardId = "diag-tf-local";
    else if (name === "registry_access") cardId = "diag-tf-reg";
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
  // 10. Mode B: Step 1 - Execute Dry-Run Plan (`terraform plan`)
  // =========================================================================
  if (btnPlanDryrun) {
    btnPlanDryrun.addEventListener("click", async () => {
      if (!currentFile && !currentApiSessionId) {
        showToast(
          "error",
          "No Configuration",
          "Please upload a configuration or extract via API first.",
        );
        return;
      }

      const host = panHost ? panHost.value.trim() : "";
      if (!host) {
        showInputError(
          "pan-host",
          "Target Hostname or IP is required for Live Apply.",
        );
        showToast(
          "error",
          "Missing Target Host",
          "Please specify target firewall management IP.",
        );
        return;
      }

      resetDeployment();
      setBusy(btnPlanDryrun, true);
      setLiveOperationRunning(true);
      if (planStatusMsg)
        planStatusMsg.textContent =
          "Preparing the workspace and calculating a dry-run plan…";
      logToTerminal(
        `[PREPARE] Initializing deployment sandbox for ${selectedSourceVendor} -> ${selectedTargetVendor}...`,
        "term-system",
      );

      const formData = new FormData();
      if (currentFile) {
        formData.append("file", currentFile);
      } else if (currentApiSessionId) {
        formData.append("session_id", currentApiSessionId);
      }

      formData.append("source_vendor", selectedSourceVendor);
      formData.append("target_vendor", selectedTargetVendor);
      formData.append("host", host);
      formData.append("port", panPort ? panPort.value.trim() : "443");
      formData.append("vsys", "vsys1");
      formData.append("device_group", "shared");

      const authType =
        document.querySelector('input[name="auth-type"]:checked')?.value ||
        "apikey";
      if (authType === "apikey") {
        formData.append("api_key", panApikey ? panApikey.value.trim() : "");
      } else {
        formData.append("username", panUser ? panUser.value.trim() : "");
        formData.append("password", panPass ? panPass.value.trim() : "");
      }

      try {
        // 1. Prepare Sandbox
        const prepResp = await fetch("/api/terraform/prepare", {
          method: "POST",
          body: formData,
        });
        const prepData = await readJson(prepResp, "Preparation failed");
        if (!prepData.session_id)
          throw new Error("The server did not return a deployment session.");

        currentSessionId = prepData.session_id;
        logToTerminal(
          `[PREPARE] Sandbox ${currentSessionId} ready. Running Terraform Init & Plan...`,
          "term-system",
        );

        // 2. Run Terraform Plan
        const planResp = await fetch("/api/terraform/plan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ session_id: currentSessionId }),
        });

        const planData = await planResp.json();
        if (!planData.success) {
          if (planData.init_log) logToTerminal(planData.init_log, "term-log");
          if (planData.plan_log) logToTerminal(planData.plan_log, "term-log");
          throw new Error(planData.error || "Terraform plan failed");
        }

        if (planData.init_log) logToTerminal(planData.init_log, "term-log");
        if (planData.plan_log) logToTerminal(planData.plan_log, "term-log");

        const summary = planData.summary || { add: 0, change: 0, destroy: 0 };
        if (badgeAdd) badgeAdd.textContent = `+${summary.add} add`;
        if (badgeChange) badgeChange.textContent = `~${summary.change} change`;
        if (badgeDestroy)
          badgeDestroy.textContent = `-${summary.destroy} destroy`;
        if (planSummaryBadges) planSummaryBadges.classList.remove("hidden");

        if (planStatusMsg)
          planStatusMsg.textContent = `Plan verified (+${summary.add}, ~${summary.change}, -${summary.destroy}). Ready for Live Push.`;
        if (btnApplyLive) btnApplyLive.disabled = false;

        showToast(
          "success",
          "Plan Ready",
          `Dry-run plan computed (+${summary.add}, ~${summary.change}, -${summary.destroy}).`,
        );
        logToTerminal(
          `[PLAN] Plan complete: +${summary.add} to add, ~${summary.change} to change, -${summary.destroy} to destroy. Ready for Live Apply.`,
          "term-success",
        );
      } catch (err) {
        resetDeployment();
        if (planStatusMsg)
          planStatusMsg.textContent =
            "Plan failed. Check the execution log and try again.";
        showError(`Plan error: ${err.message}`);
        logToTerminal(`[ERROR] Plan failed: ${err.message}`, "term-error");
        showToast("error", "Plan Error", err.message);
      } finally {
        setLiveOperationRunning(false);
        setBusy(btnPlanDryrun, false);
      }
    });
  }

  // =========================================================================
  // 11. Mode B: Step 2 - Live Apply (`terraform apply` via SSE)
  // =========================================================================
  if (btnApplyLive) {
    btnApplyLive.addEventListener("click", async () => {
      if (!currentSessionId) {
        showToast(
          "error",
          "No Active Plan",
          "Please execute dry-run plan before applying changes.",
        );
        return;
      }

      const confirmApply = confirm(
        "Are you sure you want to commit this configuration to the live firewall?",
      );
      if (!confirmApply) return;

      btnApplyLive.disabled = true;
      if (btnRollback) btnRollback.disabled = true;
      setLiveOperationRunning(true);
      try {
        if (!sessionApproved) {
          const approval = await fetch("/api/terraform/approve", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: currentSessionId }),
          });
          await readJson(approval, "The deployment plan could not be approved");
          sessionApproved = true;
        }
      } catch (err) {
        showError(err.message);
        showToast("error", "Approval Failed", err.message);
        btnApplyLive.disabled = false;
        setLiveOperationRunning(false);
        return;
      }
      if (applyStatusMsg)
        applyStatusMsg.textContent =
          "Deployment in progress. Follow the execution log below.";
      logToTerminal(
        "[APPLY] Commencing live Server-Sent Events (SSE) streaming...",
        "term-system",
      );

      const evtSource = new EventSource(
        `/api/terraform/apply/stream?session_id=${encodeURIComponent(currentSessionId)}`,
      );

      const finishApply = () => {
        evtSource.close();
        btnApplyLive.disabled = false;
        if (btnRollback) btnRollback.disabled = false;
        setLiveOperationRunning(false);
      };

      evtSource.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data.event === "log") {
            logToTerminal(data.line, "term-log");
          } else if (data.event === "status") {
            logToTerminal(`[STATUS] ${data.message}`, "term-system");
          } else if (data.event === "complete") {
            finishApply();
            if (data.success) {
              logToTerminal(`[SUCCESS] ${data.message}`, "term-success");
              if (postActionsBar) postActionsBar.classList.remove("hidden");
              if (applyStatusMsg)
                applyStatusMsg.textContent =
                  "Deployment committed successfully.";
              showToast(
                "success",
                "Apply Complete",
                "Terraform completed. Review the log and audit before validating the target.",
              );
            } else {
              logToTerminal(`[FAILED] ${data.message}`, "term-error");
              showError(data.message);
            }
          } else if (data.event === "error") {
            finishApply();
            logToTerminal(`[ERROR] ${data.message}`, "term-error");
            showError(data.message);
            if (applyStatusMsg)
              applyStatusMsg.textContent =
                "Deployment reported an error. Review the execution log.";
          }
        } catch (err) {
          finishApply();
          showError(
            "The deployment stream returned an unreadable response. Check the target state before retrying.",
          );
        }
      };

      evtSource.onerror = () => {
        finishApply();
        logToTerminal(
          "[ERROR] Live deployment event stream disconnected.",
          "term-error",
        );
        if (applyStatusMsg)
          applyStatusMsg.textContent =
            "Connection interrupted. Target state is unknown; inspect it before retrying.";
        showError(
          "The live stream disconnected. The operation may still be running; check the target and server before retrying.",
        );
      };
    });
  }

  // =========================================================================
  // 12. Mode B: Step 3 - Emergency Rollback / Destroy
  // =========================================================================
  if (btnRollback) {
    btnRollback.addEventListener("click", () => {
      if (!currentSessionId) return;

      const confirmDestroy = confirm(
        "WARNING: This will DESTROY and remove all provisioned resources from the firewall. Proceed with rollback?",
      );
      if (!confirmDestroy) return;

      btnRollback.disabled = true;
      btnApplyLive.disabled = true;
      setLiveOperationRunning(true);
      if (rollbackStatusMsg)
        rollbackStatusMsg.textContent =
          "Removing managed resources. Follow the execution log below.";
      logToTerminal(
        "[ROLLBACK] Starting live terraform destroy streaming...",
        "term-warning",
      );

      const evtSource = new EventSource(
        `/api/terraform/destroy/stream?session_id=${encodeURIComponent(currentSessionId)}`,
      );
      const finishRollback = () => {
        evtSource.close();
        btnRollback.disabled = false;
        btnApplyLive.disabled = false;
        setLiveOperationRunning(false);
      };

      evtSource.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data.event === "log") {
            logToTerminal(data.line, "term-log");
          } else if (data.event === "status") {
            logToTerminal(`[STATUS] ${data.message}`, "term-system");
          } else if (data.event === "complete") {
            finishRollback();
            if (data.success) {
              logToTerminal(
                `[ROLLBACK COMPLETE] ${data.message}`,
                "term-warning",
              );
              if (rollbackStatusMsg)
                rollbackStatusMsg.textContent =
                  "Rollback finished. Managed resources removed.";
              postActionsBar?.classList.add("hidden");
              showToast(
                "info",
                "Rollback Finished",
                "Terraform completed resource removal. Review the log to verify the result.",
              );
            } else {
              if (rollbackStatusMsg)
                rollbackStatusMsg.textContent =
                  "Rollback failed. Review the execution log.";
              showError(data.message || "Rollback failed.");
            }
          } else if (data.event === "error") {
            finishRollback();
            logToTerminal(`[ERROR] ${data.message}`, "term-error");
            showError(data.message);
          }
        } catch (err) {
          finishRollback();
          showError(
            "The rollback stream returned an unreadable response. Check the target state before retrying.",
          );
        }
      };

      evtSource.onerror = () => {
        finishRollback();
        logToTerminal("[ERROR] Rollback stream disconnected.", "term-error");
        if (rollbackStatusMsg)
          rollbackStatusMsg.textContent =
            "Connection interrupted. Check the target state before retrying.";
        showError(
          "The rollback stream disconnected. The operation may still be running; check the target and server before retrying.",
        );
      };
    });
  }

  // =========================================================================
  // 13. Terminal Helpers (Clear, Copy, Log)
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

  // =========================================================================
  // 14. Post Actions & Downloads
  // =========================================================================
  if (btnDownloadState) {
    btnDownloadState.addEventListener("click", async () => {
      if (!currentSessionId) return;
      try {
        const resp = await fetch(
          `/api/download/state?session_id=${currentSessionId}`,
        );
        if (!resp.ok) throw new Error("Failed to download state file");
        const blob = await resp.blob();
        await downloadBlob(blob, `terraform_${currentSessionId}.tfstate`);
      } catch (err) {
        showToast("error", "Download Failed", err.message);
      }
    });
  }

  if (btnDownloadAudit) {
    btnDownloadAudit.addEventListener("click", async () => {
      if (!currentSessionId) return;
      try {
        const resp = await fetch(
          `/api/download/package?session_id=${currentSessionId}`,
        );
        if (!resp.ok) throw new Error("Failed to download package");
        const blob = await resp.blob();
        await downloadBlob(blob, `terraform_package_${currentSessionId}.zip`);
      } catch (err) {
        showToast("error", "Download Failed", err.message);
      }
    });
  }

  // =========================================================================
  // 15. Feedback, Errors & Toast System
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

  function formatApiErrorMessage(errMessage, vendorName = "Firewall") {
    const msg = (errMessage || "").toLowerCase();

    if (
      msg.includes("401") ||
      msg.includes("403") ||
      msg.includes("authentication failed") ||
      msg.includes("login failed") ||
      msg.includes("unauthorized") ||
      msg.includes("forbidden")
    ) {
      return {
        title: `${vendorName} Authentication Failed`,
        detail: errMessage || "Invalid API Token or Admin Credentials.",
        hint: `💡 <strong>Troubleshooting:</strong> Verify your REST API token or admin credentials. Ensure the user profile has configuration read permissions.`,
      };
    }
    if (
      msg.includes("ssl") ||
      msg.includes("certificate") ||
      msg.includes("cert") ||
      msg.includes("tlsv1")
    ) {
      return {
        title: "TLS / SSL Certificate Verification Error",
        detail: errMessage,
        hint: `💡 <strong>Troubleshooting:</strong> If this firewall uses a self-signed HTTPS certificate, check <em>'Allow Self-Signed TLS Certificates'</em>.`,
      };
    }
    if (
      msg.includes("connection refused") ||
      msg.includes("timed out") ||
      msg.includes("timeout") ||
      msg.includes("failed to reach") ||
      msg.includes("name or service not known") ||
      msg.includes("gaierror")
    ) {
      return {
        title: `${vendorName} Host Unreachable`,
        detail: errMessage,
        hint: `💡 <strong>Troubleshooting:</strong> Check the host IP address and HTTPS port. Ensure line-of-sight and that management API access is enabled on the interface.`,
      };
    }
    return {
      title: `${vendorName} Connection Error`,
      detail:
        errMessage ||
        "An unexpected error occurred while communicating with the device API.",
      hint: `💡 <strong>Troubleshooting:</strong> Check device connection parameters and network routing.`,
    };
  }

  function showApiIngestError(errMessage, vendorName = "Firewall") {
    if (!apiIngestError) return;
    const parsed = formatApiErrorMessage(errMessage, vendorName);
    if (apiErrorTitle) apiErrorTitle.textContent = parsed.title;
    if (apiErrorDetail) apiErrorDetail.textContent = parsed.detail;
    if (apiErrorHint) {
      if (parsed.hint) {
        apiErrorHint.innerHTML = parsed.hint;
        apiErrorHint.classList.remove("hidden");
      } else {
        apiErrorHint.classList.add("hidden");
      }
    }
    apiIngestError.classList.remove("hidden");
    showToast("error", parsed.title, parsed.detail);
  }

  function hideApiIngestError() {
    if (apiIngestError) apiIngestError.classList.add("hidden");
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
      if (liveOperationRunning) return;
      if (
        (currentFile || currentApiSessionId || currentSessionId) &&
        !confirm(
          "Start a new workspace? This clears the current source and plan from this window. Downloaded files are kept.",
        )
      )
        return;
      clearSource();
      clearInputErrors();
      renderApiCredentialFields(selectedSourceVendor);
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
