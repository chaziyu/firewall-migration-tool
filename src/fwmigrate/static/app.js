document.addEventListener('DOMContentLoaded', () => {
    // =========================================================================
    // Application State
    // =========================================================================
    let currentFile = null;
    let currentApiSessionId = null;
    let currentSessionId = null;
    let selectedSourceVendor = 'fortigate';
    let selectedTargetVendor = 'palo_alto';
    let activeMode = 'download'; // 'download' or 'live'
    let activeIngestMethod = 'file'; // 'file' or 'api'
    let currentPolicies = [];

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
                { id: "userpass", label: "Admin Username & Password" }
            ],
            fileAccept: ".conf,.cfg,.txt",
            dropText: "Supports FortiOS <code>.conf</code>, <code>.cfg</code>, or <code>.txt</code> backup files",
            fields: [
                { id: "api-host", label: "FortiGate IP / Hostname", type: "text", required: true, placeholder: "192.168.1.99 or fg.corp.local", col: "col-8" },
                { id: "api-port", label: "HTTPS Port", type: "number", required: true, value: 443, col: "col-4" },
                { id: "api-vdom", label: "Virtual Domain (VDOM)", type: "text", required: false, value: "root", placeholder: "root", col: "col-6" },
                { id: "api-token", label: "REST API Token", type: "password", required: true, placeholder: "Bearer token", col: "col-6", authType: "apikey" },
                { id: "api-username", label: "Admin Username", type: "text", required: true, placeholder: "admin", col: "col-6", authType: "userpass" },
                { id: "api-password", label: "Admin Password", type: "password", required: true, placeholder: "••••••••", col: "col-6", authType: "userpass" },
                { id: "api-insecure", label: "Allow Self-Signed TLS Certificates (Disable SSL Verification)", type: "checkbox", checked: true, col: "col-12" }
            ]
        },
        palo_alto: {
            name: "Palo Alto Networks",
            icon: "🔥",
            protocol: "PAN-OS XML / REST API (HTTPS /api/)",
            desc: "Connects to PAN-OS XML API to retrieve active candidate/running configurations and security rulebases.",
            defaultPort: 443,
            authTypes: [
                { id: "apikey", label: "PAN-OS API Key" },
                { id: "userpass", label: "Admin Username & Password" }
            ],
            fileAccept: ".xml,.txt,.conf",
            dropText: "Supports Palo Alto Networks PAN-OS <code>.xml</code> or <code>.txt</code> configuration exports",
            fields: [
                { id: "api-host", label: "PAN-OS IP / Hostname", type: "text", required: true, placeholder: "192.168.1.1 or panorama.corp.local", col: "col-8" },
                { id: "api-port", label: "HTTPS Port", type: "number", required: true, value: 443, col: "col-4" },
                { id: "api-vsys", label: "Virtual System (VSYS)", type: "text", required: false, value: "vsys1", placeholder: "vsys1", col: "col-6" },
                { id: "api-token", label: "PAN-OS API Key", type: "password", required: true, placeholder: "LUFRPT14MW5xV05xWDV...", col: "col-6", authType: "apikey" },
                { id: "api-username", label: "Admin Username", type: "text", required: true, placeholder: "admin", col: "col-6", authType: "userpass" },
                { id: "api-password", label: "Admin Password", type: "password", required: true, placeholder: "••••••••", col: "col-6", authType: "userpass" },
                { id: "api-insecure", label: "Allow Self-Signed TLS Certificates (Disable SSL Verification)", type: "checkbox", checked: true, col: "col-12" }
            ]
        },
        cisco_asa: {
            name: "Cisco ASA / FTD",
            icon: "🌐",
            protocol: "Cisco Firepower Management Center (FMC) / ASA REST API",
            desc: "Authenticates with Cisco FMC REST API / ASA to pull network objects, ACL policies, and NAT definitions.",
            defaultPort: 443,
            authTypes: [
                { id: "userpass", label: "Admin Credentials" }
            ],
            fileAccept: ".cfg,.txt,.conf",
            dropText: "Supports Cisco ASA / Firepower <code>.cfg</code> or <code>.txt</code> configuration files",
            fields: [
                { id: "api-host", label: "FMC / ASA Host or IP", type: "text", required: true, placeholder: "fmc.corp.local or 192.168.1.1", col: "col-8" },
                { id: "api-port", label: "HTTPS Port", type: "number", required: true, value: 443, col: "col-4" },
                { id: "api-username", label: "Admin Username", type: "text", required: true, placeholder: "apiadmin", col: "col-6" },
                { id: "api-password", label: "Admin Password", type: "password", required: true, placeholder: "••••••••", col: "col-6" },
                { id: "api-domain", label: "Domain UUID / Context", type: "text", required: false, placeholder: "e276abec-e0f2-11e3-8169-6d9ed49b625f", col: "col-12" },
                { id: "api-insecure", label: "Allow Self-Signed TLS Certificates (Disable SSL Verification)", type: "checkbox", checked: true, col: "col-12" }
            ]
        },
        checkpoint: {
            name: "Check Point",
            icon: "🔒",
            protocol: "Check Point Management Web API (/web_api/)",
            desc: "Queries Check Point R80/R81 SmartCenter Web API to extract network objects, rulebases, and NAT tables.",
            defaultPort: 443,
            authTypes: [
                { id: "userpass", label: "Management Admin Credentials" }
            ],
            fileAccept: ".json,.txt",
            dropText: "Supports Check Point R80/R81 <code>.json</code> database dumps or export files",
            fields: [
                { id: "api-host", label: "Management Server IP / Hostname", type: "text", required: true, placeholder: "192.168.1.10", col: "col-8" },
                { id: "api-port", label: "HTTPS Port", type: "number", required: true, value: 443, col: "col-4" },
                { id: "api-username", label: "Admin Username", type: "text", required: true, placeholder: "admin", col: "col-6" },
                { id: "api-password", label: "Admin Password", type: "password", required: true, placeholder: "••••••••", col: "col-6" },
                { id: "api-domain", label: "Domain (MDS / Multi-Domain)", type: "text", required: false, placeholder: "Default", col: "col-12" },
                { id: "api-insecure", label: "Allow Self-Signed TLS Certificates (Disable SSL Verification)", type: "checkbox", checked: true, col: "col-12" }
            ]
        },
        juniper_srx: {
            name: "Juniper SRX",
            icon: "🌲",
            protocol: "JunOS NETCONF over SSH / PyEZ",
            desc: "Connects via NETCONF (Port 830) to retrieve JunOS security zones, address books, and policy sets.",
            defaultPort: 830,
            authTypes: [
                { id: "userpass", label: "NETCONF SSH Admin Credentials" }
            ],
            fileAccept: ".set,.conf,.txt",
            dropText: "Supports JunOS SRX <code>.set</code>, <code>.conf</code>, or <code>.txt</code> files",
            fields: [
                { id: "api-host", label: "JunOS Device IP / Hostname", type: "text", required: true, placeholder: "192.168.1.1 or srx.corp.local", col: "col-8" },
                { id: "api-port", label: "NETCONF Port", type: "number", required: true, value: 830, col: "col-4" },
                { id: "api-username", label: "Admin Username", type: "text", required: true, placeholder: "admin", col: "col-6" },
                { id: "api-password", label: "Admin Password", type: "password", required: true, placeholder: "••••••••", col: "col-6" },
                { id: "api-insecure", label: "Allow Self-Signed / Host Key Bypass", type: "checkbox", checked: true, col: "col-12" }
            ]
        }
    };

    // =========================================================================
    // DOM Elements Cache
    // =========================================================================
    // Mode Switcher Tabs
    const tabDownload = document.getElementById('tab-download');
    const tabLive = document.getElementById('tab-live');
    const modeDownloadForm = document.getElementById('mode-download-form');
    const modeLiveForm = document.getElementById('mode-live-form');

    // Ingestion Method Tabs
    const btnIngestFile = document.getElementById('btn-ingest-file');
    const btnIngestApi = document.getElementById('btn-ingest-api');
    const ingestFileContainer = document.getElementById('ingest-file-container');
    const ingestApiContainer = document.getElementById('ingest-api-container');

    // Vendor Selection Dropdowns
    const sourceVendorSelect = document.getElementById('source-vendor-select');
    const targetVendorSelect = document.getElementById('target-vendor-select');

    // File Ingest Dropzone
    const dropzone = document.getElementById('file-dropzone');
    const fileInput = document.getElementById('file-input');
    const dropzoneSubtext = document.getElementById('dropzone-subtext');
    const selectedFileCard = document.getElementById('selected-file-card');
    const selectedFilename = document.getElementById('selected-filename');
    const selectedFilesize = document.getElementById('selected-filesize');
    const btnRemoveFile = document.getElementById('btn-remove-file');

    // API Ingest Components
    const apiCredentialFields = document.getElementById('api-credential-fields');
    const btnApiExtract = document.getElementById('btn-api-extract');
    const apiIngestSuccess = document.getElementById('api-ingest-success');
    const apiHostname = document.getElementById('api-hostname');
    const apiStatsSummary = document.getElementById('api-stats-summary');
    const btnClearApiIngest = document.getElementById('btn-clear-api-ingest');
    const apiIngestError = document.getElementById('api-ingest-error');
    const apiErrorTitle = document.getElementById('api-error-title');
    const apiErrorDetail = document.getElementById('api-error-detail');
    const apiErrorHint = document.getElementById('api-error-hint');
    const btnDismissApiError = document.getElementById('btn-dismiss-api-error');

    // Optimizer Panel Stats
    const optimizerPanel = document.getElementById('optimizer-panel');
    const optPruneObjects = document.getElementById('opt-prune-objects');
    const statTotalRules = document.getElementById('stat-total-rules');
    const statTotalObjects = document.getElementById('stat-total-objects');
    const statUnusedObjects = document.getElementById('stat-unused-objects');
    const statShadowedRules = document.getElementById('stat-shadowed-rules');

    // Mode A Components
    const btnGenerateBundle = document.getElementById('btn-generate-bundle');

    // Mode B Target Form & Diagnostics
    const panHost = document.getElementById('pan-host');
    const panPort = document.getElementById('pan-port');
    const radioAuthTypes = document.querySelectorAll('input[name="auth-type"]');
    const authApikeyGroup = document.getElementById('auth-apikey-group');
    const authUserGroup = document.getElementById('auth-user-group');
    const authPassGroup = document.getElementById('auth-pass-group');
    const panApikey = document.getElementById('pan-apikey');
    const panUser = document.getElementById('pan-user');
    const panPass = document.getElementById('pan-pass');
    const panInsecure = document.getElementById('pan-insecure');
    const btnRunDiagnostics = document.getElementById('btn-run-diagnostics');

    // Mode B Stepper & Action Buttons
    const btnPlanDryrun = document.getElementById('btn-plan-dryrun');
    const planSummaryBadges = document.getElementById('plan-summary-badges');
    const badgeAdd = document.getElementById('badge-add');
    const badgeChange = document.getElementById('badge-change');
    const badgeDestroy = document.getElementById('badge-destroy');
    const planStatusMsg = document.getElementById('plan-status-msg');
    const btnApplyLive = document.getElementById('btn-apply-live');
    const applyStatusMsg = document.getElementById('apply-status-msg');
    const btnRollback = document.getElementById('btn-rollback');
    const rollbackStatusMsg = document.getElementById('rollback-status-msg');

    // Terminal
    const terminalStreamBody = document.getElementById('terminal-stream-body');
    const termAutoscroll = document.getElementById('term-autoscroll');
    const btnClearTerm = document.getElementById('btn-clear-term');
    const btnCopyTerm = document.getElementById('btn-copy-term');

    // Post Actions Bar
    const postActionsBar = document.getElementById('post-actions-bar');
    const btnDownloadState = document.getElementById('btn-download-state');
    const btnDownloadAudit = document.getElementById('btn-download-audit');

    // Toast Container & Error Banner
    const toastContainer = document.getElementById('toast-container');
    const errorBanner = document.getElementById('error-message');

    // =========================================================================
    // 1. Mode Tab Switching (Package Export vs Direct Live Migration)
    // =========================================================================
    if (tabDownload) {
        tabDownload.addEventListener('click', () => switchMode('download'));
    }
    if (tabLive) {
        tabLive.addEventListener('click', () => switchMode('live'));
    }

    function switchMode(mode) {
        activeMode = mode;
        if (mode === 'download') {
            tabDownload.classList.add('active');
            tabDownload.setAttribute('aria-selected', 'true');
            tabLive.classList.remove('active');
            tabLive.setAttribute('aria-selected', 'false');

            if (modeDownloadForm) modeDownloadForm.classList.remove('hidden');
            if (modeLiveForm) modeLiveForm.classList.add('hidden');
            logToTerminal("[MODE] Switched to Package Export Mode (XML/CLI & Terraform Bundle).", 'term-system');
        } else {
            tabLive.classList.add('active');
            tabLive.setAttribute('aria-selected', 'true');
            tabDownload.classList.remove('active');
            tabDownload.setAttribute('aria-selected', 'false');

            if (modeLiveForm) modeLiveForm.classList.remove('hidden');
            if (modeDownloadForm) modeDownloadForm.classList.add('hidden');
            logToTerminal("[MODE] Switched to Direct Live Migration Engine (Target Pre-Flight & Live Push).", 'term-system');
        }
    }

    // =========================================================================
    // 2. Ingestion Method Tabs (Upload File vs Live REST API)
    // =========================================================================
    if (btnIngestFile) {
        btnIngestFile.addEventListener('click', () => {
            activeIngestMethod = 'file';
            btnIngestFile.classList.add('active');
            btnIngestApi.classList.remove('active');
            if (ingestFileContainer) ingestFileContainer.classList.remove('hidden');
            if (ingestApiContainer) ingestApiContainer.classList.add('hidden');
            logToTerminal("[INGEST] Switched to File Upload mode.", 'term-system');
        });
    }

    if (btnIngestApi) {
        btnIngestApi.addEventListener('click', () => {
            activeIngestMethod = 'api';
            btnIngestApi.classList.add('active');
            btnIngestFile.classList.remove('active');
            if (ingestApiContainer) ingestApiContainer.classList.remove('hidden');
            if (ingestFileContainer) ingestFileContainer.classList.add('hidden');

            renderApiCredentialFields(selectedSourceVendor);
            logToTerminal(`[INGEST] Switched to Live REST API Extraction mode for ${VENDOR_CONFIGS[selectedSourceVendor]?.name || selectedSourceVendor}.`, 'term-system');
        });
    }

    // =========================================================================
    // 3. Vendor Selector Dropdowns
    // =========================================================================
    if (sourceVendorSelect) {
        selectedSourceVendor = sourceVendorSelect.value || 'fortigate';
        sourceVendorSelect.addEventListener('change', (e) => {
            selectedSourceVendor = e.target.value;
            const vendorName = sourceVendorSelect.options[sourceVendorSelect.selectedIndex]?.text || selectedSourceVendor;
            logToTerminal(`[VENDOR] Source vendor selected: ${vendorName}`, 'term-system');

            const cfg = VENDOR_CONFIGS[selectedSourceVendor];
            if (cfg) {
                if (dropzoneSubtext) dropzoneSubtext.innerHTML = cfg.dropText;
                if (fileInput) fileInput.accept = cfg.fileAccept;
            }

            // If in API mode, update the dynamic form immediately
            if (activeIngestMethod === 'api') {
                renderApiCredentialFields(selectedSourceVendor);
            }

            // Re-fetch preview if an active file or live session exists
            if (currentFile || currentApiSessionId) {
                fetchMigrationPreview();
            }
        });
    }

    if (targetVendorSelect) {
        selectedTargetVendor = targetVendorSelect.value || 'palo_alto';
        targetVendorSelect.addEventListener('change', (e) => {
            selectedTargetVendor = e.target.value;
            const targetName = targetVendorSelect.options[targetVendorSelect.selectedIndex]?.text || selectedTargetVendor;
            logToTerminal(`[VENDOR] Target platform selected: ${targetName}`, 'term-system');
            updateTargetBundleDescriptions(selectedTargetVendor);
        });
    }

    function updateTargetBundleDescriptions(target) {
        const panDesc = document.getElementById('feature-card-pan-desc');
        const tfDesc = document.getElementById('feature-card-tf-desc');
        const auditDesc = document.getElementById('feature-card-audit-desc');

        if (target === 'fortigate') {
            if (panDesc) panDesc.innerHTML = "Native <code>fortigate_config.conf</code> script for FortiOS CLI execution";
            if (tfDesc) tfDesc.innerHTML = "Production HCL targeting <code>fortinetdev/fortios</code> (<code>main.tf</code>, <code>variables.tf</code>)";
        } else if (target === 'cisco_asa') {
            if (panDesc) panDesc.innerHTML = "Native <code>cisco_asa_config.cfg</code> CLI commands for ASA / Firepower import";
            if (tfDesc) tfDesc.innerHTML = "Production HCL targeting <code>CiscoDevNet/ciscoasa</code> (<code>main.tf</code>, <code>variables.tf</code>)";
        } else if (target === 'checkpoint') {
            if (panDesc) panDesc.innerHTML = "Native <code>checkpoint_mgmt_cli.sh</code> automation script for Check Point MDS";
            if (tfDesc) tfDesc.innerHTML = "Production HCL targeting <code>CheckPointSW/checkpoint</code> (<code>main.tf</code>, <code>variables.tf</code>)";
        } else if (target === 'juniper_srx') {
            if (panDesc) panDesc.innerHTML = "Native <code>junos_srx_config.set</code> batch configuration syntax";
            if (tfDesc) tfDesc.innerHTML = "Production HCL targeting <code>juniper/junos</code> (<code>main.tf</code>, <code>variables.tf</code>)";
        } else {
            if (panDesc) panDesc.innerHTML = "Native <code>palo_alto_config.xml</code> ready for Panorama / Firewall WebGUI import";
            if (tfDesc) tfDesc.innerHTML = "Production HCL targeting <code>PaloAltoNetworks/panos</code> (<code>main.tf</code>, <code>terraform.tfvars</code>)";
        }
    }

    // =========================================================================
    // 4. Dynamic API Credential Form Generator
    // =========================================================================
    function renderApiCredentialFields(vendorId) {
        if (!apiCredentialFields) return;
        const config = VENDOR_CONFIGS[vendorId] || VENDOR_CONFIGS['fortigate'];

        // Build HTML for fields
        let html = '';

        // If vendor supports multiple auth types, render an auth switcher
        if (config.authTypes && config.authTypes.length > 1) {
            html += `
                <div class="form-group col-12">
                    <label>Authentication Method</label>
                    <div class="radio-toggle" id="api-auth-toggle-group">
                        ${config.authTypes.map((at, idx) => `
                            <label class="radio-label">
                                <input type="radio" name="api-auth-type" value="${at.id}" ${idx === 0 ? 'checked' : ''}>
                                <span>${at.label}</span>
                            </label>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        // Render input fields
        config.fields.forEach(field => {
            const colClass = field.col || 'col-6';
            const authFilter = field.authType ? `data-auth-type="${field.authType}"` : '';
            const hideClass = (field.authType && field.authType !== config.authTypes?.[0]?.id) ? 'hidden' : '';

            if (field.type === 'checkbox') {
                html += `
                    <div class="form-group ${colClass} ${hideClass}" ${authFilter}>
                        <label class="checkbox-label">
                            <input type="checkbox" id="${field.id}" ${field.checked ? 'checked' : ''}>
                            <span>${field.label}</span>
                        </label>
                    </div>
                `;
            } else if (field.type === 'password') {
                html += `
                    <div class="form-group ${colClass} ${hideClass}" ${authFilter} id="group-${field.id}">
                        <label for="${field.id}">${field.label} ${field.required ? '<span class="req">*</span>' : ''}</label>
                        <div class="password-wrapper">
                            <input type="password" id="${field.id}" placeholder="${field.placeholder || ''}" ${field.required ? 'required' : ''}>
                            <button type="button" class="btn-toggle-password" data-target="${field.id}" title="Toggle visibility">👁️</button>
                        </div>
                    </div>
                `;
            } else {
                html += `
                    <div class="form-group ${colClass} ${hideClass}" ${authFilter} id="group-${field.id}">
                        <label for="${field.id}">${field.label} ${field.required ? '<span class="req">*</span>' : ''}</label>
                        <input type="${field.type}" id="${field.id}" value="${field.value !== undefined ? field.value : ''}" placeholder="${field.placeholder || ''}" ${field.required ? 'required' : ''}>
                    </div>
                `;
            }
        });

        apiCredentialFields.innerHTML = html;

        // Wire up password toggles inside dynamic fields
        apiCredentialFields.querySelectorAll('.btn-toggle-password').forEach(btn => {
            btn.addEventListener('click', () => {
                const targetId = btn.getAttribute('data-target');
                const input = document.getElementById(targetId);
                if (!input) return;
                if (input.type === 'password') {
                    input.type = 'text';
                    btn.textContent = '🔒';
                } else {
                    input.type = 'password';
                    btn.textContent = '👁️';
                }
            });
        });

        // Wire up auth radio toggle if present
        const authRadios = apiCredentialFields.querySelectorAll('input[name="api-auth-type"]');
        authRadios.forEach(radio => {
            radio.addEventListener('change', (e) => {
                const selectedAuth = e.target.value;
                apiCredentialFields.querySelectorAll('[data-auth-type]').forEach(el => {
                    if (el.getAttribute('data-auth-type') === selectedAuth) {
                        el.classList.remove('hidden');
                    } else {
                        el.classList.add('hidden');
                    }
                });
            });
        });

        // Clear validation errors on typing
        apiCredentialFields.querySelectorAll('input').forEach(inp => {
            inp.addEventListener('input', () => {
                inp.classList.remove('input-invalid');
                const parent = inp.closest('.form-group') || inp.parentElement;
                const err = parent.querySelector('.field-error-text');
                if (err) err.remove();
            });
        });
    }

    // Initial render for default vendor
    renderApiCredentialFields(selectedSourceVendor);

    // =========================================================================
    // 5. Live REST API Ingestion Handler
    // =========================================================================
    if (btnApiExtract) {
        btnApiExtract.addEventListener('click', async () => {
            clearInputErrors();
            hideApiIngestError();
            hideError();

            const hostEl = document.getElementById('api-host');
            const portEl = document.getElementById('api-port');
            const tokenEl = document.getElementById('api-token');
            const userEl = document.getElementById('api-username');
            const passEl = document.getElementById('api-password');
            const vdomEl = document.getElementById('api-vdom');
            const vsysEl = document.getElementById('api-vsys');
            const domainEl = document.getElementById('api-domain');
            const insecureEl = document.getElementById('api-insecure');

            const host = hostEl ? hostEl.value.trim() : '';
            const port = portEl ? parseInt(portEl.value.trim() || '443') : 443;
            const verifySsl = insecureEl ? !insecureEl.checked : true;

            const authTypeRadio = document.querySelector('input[name="api-auth-type"]:checked');
            const authType = authTypeRadio ? authTypeRadio.value : (tokenEl ? 'apikey' : 'userpass');

            // Validation
            if (!host) {
                showInputError('api-host', 'Host or IP address is required.');
                showToast('error', 'Missing Host', 'Please specify a device IP address or hostname.');
                return;
            }

            if (authType === 'apikey' && tokenEl && !tokenEl.value.trim()) {
                showInputError('api-token', 'API Token is required for token authentication.');
                showToast('error', 'Missing API Token', 'Please enter your REST API token.');
                return;
            }

            if (authType === 'userpass') {
                let hasErr = false;
                if (userEl && !userEl.value.trim()) {
                    showInputError('api-username', 'Admin Username is required.');
                    hasErr = true;
                }
                if (passEl && !passEl.value.trim()) {
                    showInputError('api-password', 'Admin Password is required.');
                    hasErr = true;
                }
                if (hasErr) {
                    showToast('error', 'Missing Credentials', 'Please provide admin username and password.');
                    return;
                }
            }

            // Prepare Payload
            const payload = {
                host,
                port,
                verify_ssl: verifySsl
            };

            if (authType === 'apikey' && tokenEl) {
                payload.api_key = tokenEl.value.trim();
            }
            if (userEl && userEl.value.trim()) {
                payload.username = userEl.value.trim();
            }
            if (passEl && passEl.value.trim()) {
                payload.password = passEl.value.trim();
            }
            if (vdomEl) payload.vdom = vdomEl.value.trim() || 'root';
            if (vsysEl) payload.vsys = vsysEl.value.trim() || 'vsys1';
            if (domainEl) payload.domain = domainEl.value.trim();

            btnApiExtract.disabled = true;
            const btnText = btnApiExtract.querySelector('.btn-text');
            const spinner = btnApiExtract.querySelector('.spinner');
            if (btnText) btnText.textContent = `Connecting to ${host}:${port}...`;
            if (spinner) spinner.classList.remove('hidden');
            if (apiIngestSuccess) apiIngestSuccess.classList.add('hidden');

            const vendorName = VENDOR_CONFIGS[selectedSourceVendor]?.name || selectedSourceVendor;
            logToTerminal(`[INGEST] Connecting to ${vendorName} live API (${host}:${port})...`, 'term-system');

            try {
                const endpoint = `/api/ingest/${selectedSourceVendor}`;
                const resp = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const data = await resp.json();
                if (!data.success) {
                    throw new Error(data.error || `Failed to extract configuration from ${vendorName}`);
                }

                currentApiSessionId = data.session_id;
                currentFile = null; // Clear active file

                if (apiHostname) apiHostname.textContent = `${data.hostname} (Live Connected)`;
                if (apiStatsSummary) {
                    apiStatsSummary.textContent = `${data.stats.interfaces || 0} interfaces • ${data.stats.addresses || 0} addresses • ${data.stats.policies || 0} policies • ${data.stats.nat_rules || 0} NAT rules`;
                }
                if (apiIngestSuccess) apiIngestSuccess.classList.remove('hidden');
                hideApiIngestError();

                // Enable Action Buttons
                if (btnGenerateBundle) btnGenerateBundle.disabled = false;
                if (btnPlanDryrun) btnPlanDryrun.disabled = false;

                showToast('success', 'Extraction Successful', `Extracted configuration from ${vendorName} '${data.hostname}'`);
                logToTerminal(`[INGEST] Successfully pulled running configuration from '${data.hostname}' (${data.stats.interfaces || 0} interfaces, ${data.stats.policies || 0} policies). Ready for migration!`, 'term-success');

                // Load Migration Preview & Rule Matrix
                fetchMigrationPreview();

            } catch (err) {
                currentApiSessionId = null;
                if (apiIngestSuccess) apiIngestSuccess.classList.add('hidden');
                if (!currentFile) {
                    if (btnGenerateBundle) btnGenerateBundle.disabled = true;
                    if (btnPlanDryrun) btnPlanDryrun.disabled = true;
                }
                showApiIngestError(err.message, vendorName);
                logToTerminal(`[ERROR] Live API Extraction failed: ${err.message}`, 'term-error');
            } finally {
                btnApiExtract.disabled = false;
                if (btnText) btnText.textContent = "Connect & Pull Running Configuration";
                if (spinner) spinner.classList.add('hidden');
            }
        });
    }

    if (btnClearApiIngest) {
        btnClearApiIngest.addEventListener('click', () => {
            currentApiSessionId = null;
            if (apiIngestSuccess) apiIngestSuccess.classList.add('hidden');
            hideApiIngestError();
            if (!currentFile) {
                if (btnGenerateBundle) btnGenerateBundle.disabled = true;
                if (btnPlanDryrun) btnPlanDryrun.disabled = true;
                if (btnApplyLive) btnApplyLive.disabled = true;
                if (optimizerPanel) optimizerPanel.classList.add('hidden');
            }
            logToTerminal("[INGEST] Live API session cleared.", 'term-system');
        });
    }

    if (btnDismissApiError) {
        btnDismissApiError.addEventListener('click', hideApiIngestError);
    }

    // =========================================================================
    // 6. File Dropzone & Handling
    // =========================================================================
    if (dropzone && fileInput) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(evt => {
            dropzone.addEventListener(evt, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(evt => {
            dropzone.addEventListener(evt, () => dropzone.classList.add('dragover'), false);
        });

        ['dragleave', 'drop'].forEach(evt => {
            dropzone.addEventListener(evt, () => dropzone.classList.remove('dragover'), false);
        });

        dropzone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            if (dt && dt.files && dt.files.length) handleFileSelect(dt.files[0]);
        });

        dropzone.addEventListener('click', (e) => {
            if (e.target.tagName !== 'BUTTON' && !e.target.closest('button')) {
                fileInput.click();
            }
        });

        fileInput.addEventListener('change', function() {
            if (this.files.length) handleFileSelect(this.files[0]);
        });
    }

    function handleFileSelect(file) {
        if (!file) return;
        currentFile = file;
        currentApiSessionId = null;

        if (selectedFilename) selectedFilename.textContent = file.name;
        if (selectedFilesize) selectedFilesize.textContent = formatBytes(file.size);

        if (dropzone) dropzone.classList.add('hidden');
        if (selectedFileCard) selectedFileCard.classList.remove('hidden');
        hideError();

        if (btnGenerateBundle) btnGenerateBundle.disabled = false;
        if (btnPlanDryrun) btnPlanDryrun.disabled = false;
        logToTerminal(`[FILE] Loaded '${file.name}' (${formatBytes(file.size)}). Ready for processing.`, 'term-system');

        fetchMigrationPreview();
    }

    if (btnRemoveFile) {
        btnRemoveFile.addEventListener('click', () => {
            currentFile = null;
            if (fileInput) fileInput.value = '';
            if (selectedFileCard) selectedFileCard.classList.add('hidden');
            if (dropzone) dropzone.classList.remove('hidden');
            if (!currentApiSessionId) {
                if (btnGenerateBundle) btnGenerateBundle.disabled = true;
                if (btnPlanDryrun) btnPlanDryrun.disabled = true;
                if (btnApplyLive) btnApplyLive.disabled = true;
                if (optimizerPanel) optimizerPanel.classList.add('hidden');
            }
            if (planSummaryBadges) planSummaryBadges.classList.add('hidden');
            if (postActionsBar) postActionsBar.classList.add('hidden');
            hideError();
            logToTerminal("[FILE] Configuration file unloaded.", 'term-system');
        });
    }

    // =========================================================================
    // 7. Migration Intelligence Preview
    // =========================================================================
    async function fetchMigrationPreview() {
        if (!currentFile && !currentApiSessionId) return;

        const formData = new FormData();
        if (currentFile) {
            formData.append('file', currentFile);
        } else if (currentApiSessionId) {
            formData.append('session_id', currentApiSessionId);
        }
        formData.append('source_vendor', selectedSourceVendor);

        try {
            const resp = await fetch('/api/preview', {
                method: 'POST',
                body: formData
            });
            const data = await resp.json();
            if (data.success) {
                if (optimizerPanel) optimizerPanel.classList.remove('hidden');
                if (statTotalRules) statTotalRules.textContent = data.stats.policies || 0;
                if (statTotalObjects) statTotalObjects.textContent = (data.stats.addresses || 0) + (data.stats.services || 0);
                if (statUnusedObjects) statUnusedObjects.textContent = (data.optimization.unused_addresses_count || 0) + (data.optimization.unused_services_count || 0);
                if (statShadowedRules) statShadowedRules.textContent = data.optimization.shadowed_rules_count || 0;

                currentPolicies = data.policies || [];
            }
        } catch (err) {
            console.error('Preview extraction error:', err);
        }
    }

    // =========================================================================
    // 8. Mode A: Export Target Migration Bundle (.zip)
    // =========================================================================
    if (btnGenerateBundle) {
        btnGenerateBundle.addEventListener('click', async () => {
            if (!currentFile && !currentApiSessionId) {
                showToast('info', 'No Input', 'Please upload a configuration file or pull from Live REST API first.');
                return;
            }

            btnGenerateBundle.disabled = true;
            const btnText = btnGenerateBundle.querySelector('span:last-child');
            const originalText = btnText ? btnText.textContent : 'Generate Migration Bundle (.zip)';
            if (btnText) btnText.textContent = "Compiling Migration Package...";
            hideError();

            const formData = new FormData();
            if (currentFile) {
                formData.append('file', currentFile);
            } else if (currentApiSessionId) {
                formData.append('session_id', currentApiSessionId);
            }
            formData.append('source_vendor', selectedSourceVendor);
            formData.append('target_vendor', selectedTargetVendor);
            formData.append('optimize', optPruneObjects ? (optPruneObjects.checked ? 'true' : 'false') : 'false');

            logToTerminal(`[EXPORT] Compiling ${selectedSourceVendor} -> ${selectedTargetVendor} migration bundle...`, 'term-system');

            try {
                const resp = await fetch('/api/migrate', {
                    method: 'POST',
                    body: formData
                });

                if (!resp.ok) {
                    const errData = await resp.json().catch(() => ({}));
                    throw new Error(errData.error || 'Failed to generate package');
                }

                const blob = await resp.blob();
                downloadBlob(blob, `migration_${selectedSourceVendor}_to_${selectedTargetVendor}.zip`);
                showToast('success', 'Bundle Generated', `Downloaded migration bundle for ${selectedTargetVendor}`);
                logToTerminal(`[EXPORT] Successfully generated and downloaded bundle 'migration_${selectedSourceVendor}_to_${selectedTargetVendor}.zip'`, 'term-success');

            } catch (err) {
                showError(err.message);
                showToast('error', 'Export Failed', err.message);
                logToTerminal(`[ERROR] Bundle generation failed: ${err.message}`, 'term-error');
            } finally {
                btnGenerateBundle.disabled = false;
                if (btnText) btnText.textContent = originalText;
            }
        });
    }

    // =========================================================================
    // 9. Mode B: Target Authentication Switcher & Diagnostics
    // =========================================================================
    radioAuthTypes.forEach(radio => {
        radio.addEventListener('change', (e) => {
            if (e.target.value === 'apikey') {
                if (authApikeyGroup) authApikeyGroup.classList.remove('hidden');
                if (authUserGroup) authUserGroup.classList.add('hidden');
                if (authPassGroup) authPassGroup.classList.add('hidden');
            } else {
                if (authApikeyGroup) authApikeyGroup.classList.add('hidden');
                if (authUserGroup) authUserGroup.classList.remove('hidden');
                if (authPassGroup) authPassGroup.classList.remove('hidden');
            }
        });
    });

    document.querySelectorAll('.btn-toggle-password').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            const input = document.getElementById(targetId);
            if (!input) return;
            if (input.type === 'password') {
                input.type = 'text';
                btn.textContent = '🔒';
            } else {
                input.type = 'password';
                btn.textContent = '👁️';
            }
        });
    });

    if (btnRunDiagnostics) {
        btnRunDiagnostics.addEventListener('click', async () => {
            const host = panHost ? panHost.value.trim() : '';
            const port = panPort ? parseInt(panPort.value.trim() || '443') : 443;
            const authType = document.querySelector('input[name="auth-type"]:checked')?.value || 'apikey';
            const apiKey = panApikey ? panApikey.value.trim() : '';
            const username = panUser ? panUser.value.trim() : '';
            const password = panPass ? panPass.value.trim() : '';
            const verifySsl = panInsecure ? !panInsecure.checked : true;

            logToTerminal(`[DIAGNOSTICS] Probing environment and target diagnostics (${host}:${port})...`, 'term-system');
            btnRunDiagnostics.disabled = true;
            setDiagLoadingAll();

            try {
                const payload = {
                    host,
                    port,
                    verify_ssl: verifySsl,
                    auto_download_tf: true
                };

                if (authType === 'apikey') {
                    payload.api_key = apiKey;
                } else {
                    payload.username = username;
                    payload.password = password;
                }

                const resp = await fetch('/api/diagnostics', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const data = await resp.json();
                if (!data.success) throw new Error(data.error || 'Diagnostics failed');

                data.results.forEach(res => {
                    updateDiagCard(res.name, res.status, res.message);
                    logToTerminal(`[DIAGNOSTICS] ${res.name.toUpperCase()}: ${res.status.toUpperCase()} - ${res.message}`, res.status === 'ok' ? 'term-success' : res.status === 'error' ? 'term-error' : 'term-system');
                });
                showToast('info', 'Diagnostics Complete', 'Environment and line-of-sight checks finished.');

            } catch (err) {
                showError(`Diagnostics error: ${err.message}`);
                logToTerminal(`[ERROR] Diagnostics failed: ${err.message}`, 'term-error');
            } finally {
                btnRunDiagnostics.disabled = false;
            }
        });
    }

    function setDiagLoadingAll() {
        ['diag-tf-local', 'diag-tf-reg', 'diag-tcp', 'diag-panos'].forEach(id => {
            const card = document.getElementById(id);
            if (card) {
                card.className = 'diag-card running';
                const msg = document.getElementById(`${id}-msg`);
                if (msg) msg.textContent = 'Probing...';
            }
        });
    }

    function updateDiagCard(name, status, msg) {
        let cardId = 'diag-tf-local';
        if (name === 'terraform_cli') cardId = 'diag-tf-local';
        else if (name === 'registry_access') cardId = 'diag-tf-reg';
        else if (name === 'palo_alto_line_of_sight') cardId = 'diag-tcp';
        else if (name === 'palo_alto_auth') cardId = 'diag-panos';

        const card = document.getElementById(cardId);
        const msgEl = document.getElementById(`${cardId}-msg`);

        if (card) {
            const cardClass = status === 'ok' ? 'success' : (status === 'error' ? 'failed' : 'pending');
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
        btnPlanDryrun.addEventListener('click', async () => {
            if (!currentFile && !currentApiSessionId) {
                showToast('error', 'No Configuration', 'Please upload a configuration or extract via API first.');
                return;
            }

            const host = panHost ? panHost.value.trim() : '';
            if (!host) {
                showInputError('pan-host', 'Target Hostname or IP is required for Live Apply.');
                showToast('error', 'Missing Target Host', 'Please specify target firewall management IP.');
                return;
            }

            btnPlanDryrun.disabled = true;
            logToTerminal(`[PREPARE] Initializing deployment sandbox for ${selectedSourceVendor} -> ${selectedTargetVendor}...`, 'term-system');

            const formData = new FormData();
            if (currentFile) {
                formData.append('file', currentFile);
            } else if (currentApiSessionId) {
                formData.append('session_id', currentApiSessionId);
            }

            formData.append('source_vendor', selectedSourceVendor);
            formData.append('target_vendor', selectedTargetVendor);
            formData.append('host', host);
            formData.append('port', panPort ? panPort.value.trim() : '443');
            formData.append('vsys', 'vsys1');
            formData.append('device_group', 'shared');

            const authType = document.querySelector('input[name="auth-type"]:checked')?.value || 'apikey';
            if (authType === 'apikey') {
                formData.append('api_key', panApikey ? panApikey.value.trim() : '');
            } else {
                formData.append('username', panUser ? panUser.value.trim() : '');
                formData.append('password', panPass ? panPass.value.trim() : '');
            }

            try {
                // 1. Prepare Sandbox
                const prepResp = await fetch('/api/terraform/prepare', {
                    method: 'POST',
                    body: formData
                });
                const prepData = await prepResp.json();
                if (!prepData.success) throw new Error(prepData.error || 'Preparation failed');

                currentSessionId = prepData.session_id;
                logToTerminal(`[PREPARE] Sandbox ${currentSessionId} ready. Running Terraform Init & Plan...`, 'term-system');

                // 2. Run Terraform Plan
                const planResp = await fetch('/api/terraform/plan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: currentSessionId })
                });

                const planData = await planResp.json();
                if (!planData.success) {
                    if (planData.init_log) logToTerminal(planData.init_log, 'term-log');
                    if (planData.plan_log) logToTerminal(planData.plan_log, 'term-log');
                    throw new Error(planData.error || 'Terraform plan failed');
                }

                if (planData.init_log) logToTerminal(planData.init_log, 'term-log');
                if (planData.plan_log) logToTerminal(planData.plan_log, 'term-log');

                const summary = planData.summary || { add: 0, change: 0, destroy: 0 };
                if (badgeAdd) badgeAdd.textContent = `+${summary.add} add`;
                if (badgeChange) badgeChange.textContent = `~${summary.change} change`;
                if (badgeDestroy) badgeDestroy.textContent = `-${summary.destroy} destroy`;
                if (planSummaryBadges) planSummaryBadges.classList.remove('hidden');

                if (planStatusMsg) planStatusMsg.textContent = `Plan verified (+${summary.add}, ~${summary.change}, -${summary.destroy}). Ready for Live Push.`;
                if (btnApplyLive) btnApplyLive.disabled = false;
                if (btnRollback) btnRollback.disabled = false;

                showToast('success', 'Plan Ready', `Dry-run plan computed (+${summary.add}, ~${summary.change}, -${summary.destroy}).`);
                logToTerminal(`[PLAN] Plan complete: +${summary.add} to add, ~${summary.change} to change, -${summary.destroy} to destroy. Ready for Live Apply.`, 'term-success');

            } catch (err) {
                showError(`Plan error: ${err.message}`);
                logToTerminal(`[ERROR] Plan failed: ${err.message}`, 'term-error');
                showToast('error', 'Plan Error', err.message);
            } finally {
                btnPlanDryrun.disabled = false;
            }
        });
    }

    // =========================================================================
    // 11. Mode B: Step 2 - Live Apply (`terraform apply` via SSE)
    // =========================================================================
    if (btnApplyLive) {
        btnApplyLive.addEventListener('click', () => {
            if (!currentSessionId) {
                showToast('error', 'No Active Plan', 'Please execute dry-run plan before applying changes.');
                return;
            }

            const confirmApply = confirm("Are you sure you want to commit this configuration to the live firewall?");
            if (!confirmApply) return;

            btnApplyLive.disabled = true;
            if (btnPlanDryrun) btnPlanDryrun.disabled = true;
            logToTerminal("[APPLY] Commencing live Server-Sent Events (SSE) streaming...", 'term-system');

            const evtSource = new EventSource(`/api/terraform/apply/stream?session_id=${currentSessionId}`);

            evtSource.onmessage = (e) => {
                try {
                    const data = JSON.parse(e.data);
                    if (data.event === 'log') {
                        logToTerminal(data.line, 'term-log');
                    } else if (data.event === 'status') {
                        logToTerminal(`[STATUS] ${data.message}`, 'term-system');
                    } else if (data.event === 'complete') {
                        evtSource.close();
                        if (data.success) {
                            logToTerminal(`[SUCCESS] ${data.message}`, 'term-success');
                            if (postActionsBar) postActionsBar.classList.remove('hidden');
                            if (applyStatusMsg) applyStatusMsg.textContent = "Deployment committed successfully.";
                            showToast('success', 'Apply Complete', 'All rules committed to target firewall.');
                        } else {
                            logToTerminal(`[FAILED] ${data.message}`, 'term-error');
                            showError(data.message);
                        }
                        btnApplyLive.disabled = false;
                        if (btnPlanDryrun) btnPlanDryrun.disabled = false;
                    } else if (data.event === 'error') {
                        evtSource.close();
                        logToTerminal(`[ERROR] ${data.message}`, 'term-error');
                        showError(data.message);
                        btnApplyLive.disabled = false;
                        if (btnPlanDryrun) btnPlanDryrun.disabled = false;
                    }
                } catch (err) {
                    console.error("SSE parse error:", err);
                }
            };

            evtSource.onerror = () => {
                evtSource.close();
                logToTerminal("[ERROR] Live deployment event stream disconnected.", 'term-error');
                btnApplyLive.disabled = false;
                if (btnPlanDryrun) btnPlanDryrun.disabled = false;
            };
        });
    }

    // =========================================================================
    // 12. Mode B: Step 3 - Emergency Rollback / Destroy
    // =========================================================================
    if (btnRollback) {
        btnRollback.addEventListener('click', () => {
            if (!currentSessionId) return;

            const confirmDestroy = confirm("WARNING: This will DESTROY and remove all provisioned resources from the firewall. Proceed with rollback?");
            if (!confirmDestroy) return;

            btnRollback.disabled = true;
            btnApplyLive.disabled = true;
            logToTerminal("[ROLLBACK] Starting live terraform destroy streaming...", 'term-warning');

            const evtSource = new EventSource(`/api/terraform/destroy/stream?session_id=${currentSessionId}`);

            evtSource.onmessage = (e) => {
                try {
                    const data = JSON.parse(e.data);
                    if (data.event === 'log') {
                        logToTerminal(data.line, 'term-log');
                    } else if (data.event === 'status') {
                        logToTerminal(`[STATUS] ${data.message}`, 'term-system');
                    } else if (data.event === 'complete') {
                        evtSource.close();
                        logToTerminal(`[ROLLBACK COMPLETE] ${data.message}`, 'term-warning');
                        if (rollbackStatusMsg) rollbackStatusMsg.textContent = "Rollback finished. Resources removed.";
                        showToast('info', 'Rollback Finished', 'All provisioned resources were removed.');
                        btnRollback.disabled = false;
                        btnApplyLive.disabled = false;
                    } else if (data.event === 'error') {
                        evtSource.close();
                        logToTerminal(`[ERROR] ${data.message}`, 'term-error');
                        btnRollback.disabled = false;
                        btnApplyLive.disabled = false;
                    }
                } catch (err) {
                    console.error("SSE rollback parse error:", err);
                }
            };

            evtSource.onerror = () => {
                evtSource.close();
                logToTerminal("[ERROR] Rollback stream disconnected.", 'term-error');
                btnRollback.disabled = false;
                btnApplyLive.disabled = false;
            };
        });
    }

    // =========================================================================
    // 13. Terminal Helpers (Clear, Copy, Log)
    // =========================================================================
    if (btnClearTerm) {
        btnClearTerm.addEventListener('click', () => {
            if (terminalStreamBody) {
                terminalStreamBody.innerHTML = '<div class="term-line term-system">[SYSTEM] Terminal logs cleared. Ready for operations.</div>';
            }
        });
    }

    if (btnCopyTerm) {
        btnCopyTerm.addEventListener('click', () => {
            if (!terminalStreamBody) return;
            const text = terminalStreamBody.innerText;
            navigator.clipboard.writeText(text).then(() => {
                showToast('info', 'Copied', 'Terminal log copied to clipboard');
            }).catch(err => {
                console.error('Clipboard copy error:', err);
            });
        });
    }

    function logToTerminal(text, className = 'term-log') {
        if (!terminalStreamBody) return;
        const line = document.createElement('div');
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
        btnDownloadState.addEventListener('click', async () => {
            if (!currentSessionId) return;
            try {
                const resp = await fetch(`/api/download/state?session_id=${currentSessionId}`);
                if (!resp.ok) throw new Error('Failed to download state file');
                const blob = await resp.blob();
                await downloadBlob(blob, `terraform_${currentSessionId}.tfstate`);
            } catch (err) {
                showToast('error', 'Download Failed', err.message);
            }
        });
    }

    if (btnDownloadAudit) {
        btnDownloadAudit.addEventListener('click', async () => {
            if (!currentSessionId) return;
            try {
                const resp = await fetch(`/api/download/package?session_id=${currentSessionId}`);
                if (!resp.ok) throw new Error('Failed to download package');
                const blob = await resp.blob();
                await downloadBlob(blob, `terraform_package_${currentSessionId}.zip`);
            } catch (err) {
                showToast('error', 'Download Failed', err.message);
            }
        });
    }

    // =========================================================================
    // 15. Feedback, Errors & Toast System
    // =========================================================================
    function clearInputErrors() {
        document.querySelectorAll('.input-invalid').forEach(el => el.classList.remove('input-invalid'));
        document.querySelectorAll('.field-error-text').forEach(el => el.remove());
    }

    function showInputError(elementId, message) {
        const el = document.getElementById(elementId);
        if (!el) return;
        el.classList.add('input-invalid');

        const parent = el.closest('.form-group') || el.parentElement;
        const existing = parent.querySelector('.field-error-text');
        if (existing) existing.remove();

        const err = document.createElement('div');
        err.className = 'field-error-text';
        err.innerHTML = `<span>⚠️</span> <span>${message}</span>`;

        if (el.closest('.password-wrapper')) {
            el.closest('.password-wrapper').insertAdjacentElement('afterend', err);
        } else {
            el.insertAdjacentElement('afterend', err);
        }
        el.focus();
    }

    function formatApiErrorMessage(errMessage, vendorName = "Firewall") {
        const msg = (errMessage || '').toLowerCase();

        if (msg.includes('401') || msg.includes('403') || msg.includes('authentication failed') || msg.includes('login failed') || msg.includes('unauthorized') || msg.includes('forbidden')) {
            return {
                title: `${vendorName} Authentication Failed`,
                detail: errMessage || "Invalid API Token or Admin Credentials.",
                hint: `💡 <strong>Troubleshooting:</strong> Verify your REST API token or admin credentials. Ensure the user profile has configuration read permissions.`
            };
        }
        if (msg.includes('ssl') || msg.includes('certificate') || msg.includes('cert') || msg.includes('tlsv1')) {
            return {
                title: "TLS / SSL Certificate Verification Error",
                detail: errMessage,
                hint: `💡 <strong>Troubleshooting:</strong> If this firewall uses a self-signed HTTPS certificate, check <em>'Allow Self-Signed TLS Certificates'</em>.`
            };
        }
        if (msg.includes('connection refused') || msg.includes('timed out') || msg.includes('timeout') || msg.includes('failed to reach') || msg.includes('name or service not known') || msg.includes('gaierror')) {
            return {
                title: `${vendorName} Host Unreachable`,
                detail: errMessage,
                hint: `💡 <strong>Troubleshooting:</strong> Check the host IP address and HTTPS port. Ensure line-of-sight and that management API access is enabled on the interface.`
            };
        }
        return {
            title: `${vendorName} Connection Error`,
            detail: errMessage || "An unexpected error occurred while communicating with the device API.",
            hint: `💡 <strong>Troubleshooting:</strong> Check device connection parameters and network routing.`
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
                apiErrorHint.classList.remove('hidden');
            } else {
                apiErrorHint.classList.add('hidden');
            }
        }
        apiIngestError.classList.remove('hidden');
        showToast('error', parsed.title, parsed.detail);
    }

    function hideApiIngestError() {
        if (apiIngestError) apiIngestError.classList.add('hidden');
    }

    function showToast(type, title, msg, duration = 5000) {
        if (!toastContainer) return;
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;

        const icons = {
            error: '⚠️',
            success: '✓',
            info: 'ℹ️'
        };

        toast.innerHTML = `
            <div class="toast-icon">${icons[type] || 'ℹ️'}</div>
            <div class="toast-content" style="flex: 1;">
                <div class="toast-title" style="font-weight: 600; font-size: 0.88rem; color: var(--text-heading);">${title}</div>
                <div class="toast-msg" style="font-size: 0.8rem; color: var(--text-muted);">${msg}</div>
            </div>
            <button class="toast-close" type="button" aria-label="Close">✕</button>
        `;

        const removeToast = () => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            toast.style.transition = 'all 0.25s ease';
            setTimeout(() => toast.remove(), 250);
        };

        const closeBtn = toast.querySelector('.toast-close');
        if (closeBtn) closeBtn.addEventListener('click', removeToast);

        setTimeout(removeToast, duration);
        toastContainer.appendChild(toast);
    }

    function showError(msg) {
        if (errorBanner) {
            errorBanner.textContent = msg;
            errorBanner.classList.remove('hidden');
        }
    }

    function hideError() {
        if (errorBanner) {
            errorBanner.textContent = '';
            errorBanner.classList.add('hidden');
        }
    }

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    async function downloadBlob(blob, filename) {
        // 1. Check if running inside desktop app (pywebview)
        if (window.pywebview && window.pywebview.api && typeof window.pywebview.api.save_file_dialog === 'function') {
            try {
                const base64Data = await new Promise((resolve, reject) => {
                    const reader = new FileReader();
                    reader.onloadend = () => {
                        const res = reader.result;
                        const base64 = res.substring(res.indexOf(',') + 1);
                        resolve(base64);
                    };
                    reader.onerror = reject;
                    reader.readAsDataURL(blob);
                });

                const res = await window.pywebview.api.save_file_dialog(filename, base64Data);
                if (res && res.success) {
                    showToast('success', 'File Saved', `Saved successfully to ${res.path}`);
                    logToTerminal(`[SAVED] File saved successfully to: ${res.path}`, 'term-success');
                } else if (res && res.cancelled) {
                    logToTerminal(`[CANCELLED] File save cancelled by user.`, 'term-info');
                } else if (res && res.error) {
                    showToast('error', 'Save Failed', res.error);
                    logToTerminal(`[ERROR] Failed to save file: ${res.error}`, 'term-error');
                }
                return;
            } catch (err) {
                console.error('Desktop save dialog failed, falling back to browser download', err);
            }
        }

        // 2. Standard Web Browser download fallback
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }
});
