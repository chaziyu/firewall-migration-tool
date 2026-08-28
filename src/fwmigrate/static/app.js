document.addEventListener('DOMContentLoaded', () => {
    // =========================================================================
    // Application State
    // =========================================================================
    let currentFile = null;
    let currentSessionId = null;
    let selectedSourceVendor = 'fortigate';
    let selectedTargetVendor = 'palo_alto';
    let activeMode = 'extract'; // 'download', 'live', or 'extract'
    let currentPolicies = [];

    // Vendor metadata specifications for dynamic API credential forms & guides
    const VENDOR_CONFIGS = {
        fortigate: {
            name: "Fortinet FortiGate",
            icon: "🛡️",
            desc: "Directly connects over HTTPS to extract interfaces, policies, addresses, VIPs, and services in real-time.",
            fileAccept: ".conf,.cfg,.txt",
            dropText: "Supports FortiOS <code>.conf</code>, <code>.cfg</code>, or <code>.txt</code> backup files",
        },
        palo_alto: {
            name: "Palo Alto Networks",
            icon: "🔥",
            desc: "Connects to PAN-OS XML API to retrieve active candidate/running configurations and security rulebases.",
            fileAccept: ".xml,.txt,.conf",
            dropText: "Supports Palo Alto Networks PAN-OS <code>.xml</code> or <code>.txt</code> configuration exports",
        },
        cisco_asa: {
            name: "Cisco ASA / FTD",
            icon: "🌐",
            desc: "Authenticates with Cisco FMC REST API / ASA to pull network objects, ACL policies, and NAT definitions.",
            fileAccept: ".cfg,.txt,.conf",
            dropText: "Supports Cisco ASA / Firepower <code>.cfg</code> or <code>.txt</code> configuration files",
        },
        checkpoint: {
            name: "Check Point",
            icon: "🔒",
            desc: "Queries Check Point R80/R81 SmartCenter Web API to extract network objects, rulebases, and NAT tables.",
            fileAccept: ".json,.txt",
            dropText: "Supports Check Point R80/R81 <code>.json</code> database dumps or export files",
        },
        juniper_srx: {
            name: "Juniper SRX",
            icon: "🌲",
            desc: "Connects via NETCONF (Port 830) to retrieve JunOS security zones, address books, and policy sets.",
            fileAccept: ".set,.conf,.txt",
            dropText: "Supports JunOS SRX <code>.set</code>, <code>.conf</code>, or <code>.txt</code> files",
        }
    };

    // =========================================================================
    // DOM Elements Cache
    // =========================================================================
    // Mode Switcher Tabs
    const tabDownload = document.getElementById('tab-download');
    const tabLive = document.getElementById('tab-live');
    const tabExtract = document.getElementById('tab-extract');
    const modeDownloadForm = document.getElementById('mode-download-form');
    const modeLiveForm = document.getElementById('mode-live-form');
    const modeExtractForm = document.getElementById('mode-extract-form');

    // Ingestion Method Tabs

    // Vendor Selection Dropdowns
    const sourceVendorSelect = document.getElementById('source-vendor-select');
    const targetVendorSelect = document.getElementById('target-vendor-select');
    const targetVendorGroup = document.getElementById('target-vendor-group');
    const vendorSelectorGrid = document.getElementById('vendor-selector-grid');

    // File Ingest Dropzone
    const dropzone = document.getElementById('file-dropzone');
    const fileInput = document.getElementById('file-input');
    const dropzoneSubtext = document.getElementById('dropzone-subtext');
    const selectedFileCard = document.getElementById('selected-file-card');
    const selectedFilename = document.getElementById('selected-filename');
    const selectedFilesize = document.getElementById('selected-filesize');
    const btnRemoveFile = document.getElementById('btn-remove-file');

    // Optimizer Panel Stats
    const optimizerPanel = document.getElementById('optimizer-panel');
    const optPruneObjects = document.getElementById('opt-prune-objects');
    const statTotalRules = document.getElementById('stat-total-rules');
    const statTotalObjects = document.getElementById('stat-total-objects');
    const statUnusedObjects = document.getElementById('stat-unused-objects');
    const statShadowedRules = document.getElementById('stat-shadowed-rules');

    // Mode A Components
    const btnGenerateBundle = document.getElementById('btn-generate-bundle');
    const btnExtractExcel = document.getElementById('btn-extract-excel');

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
    if (tabExtract) {
        tabExtract.addEventListener('click', () => switchMode('extract'));
    }

    function switchMode(mode) {
        activeMode = mode;
        [
            [tabDownload, 'download'],
            [tabLive, 'live'],
            [tabExtract, 'extract']
        ].forEach(([tab, tabMode]) => {
            if (!tab) return;
            const selected = mode === tabMode;
            tab.classList.toggle('active', selected);
            tab.setAttribute('aria-selected', selected ? 'true' : 'false');
        });

        if (modeDownloadForm) modeDownloadForm.classList.toggle('hidden', mode !== 'download');
        if (modeLiveForm) modeLiveForm.classList.toggle('hidden', mode !== 'live');
        if (modeExtractForm) modeExtractForm.classList.toggle('hidden', mode !== 'extract');
        if (targetVendorGroup) targetVendorGroup.classList.toggle('hidden', mode === 'extract');
        if (vendorSelectorGrid) vendorSelectorGrid.classList.toggle('extract-mode', mode === 'extract');

        if (mode === 'download') {
            logToTerminal("[MODE] Switched to Package Export Mode (XML/CLI & Terraform Bundle).", 'term-system');
        } else if (mode === 'live') {
            logToTerminal("[MODE] Switched to Direct Live Migration Engine (Target Pre-Flight & Live Push).", 'term-system');
        } else {
            logToTerminal("[MODE] Switched to Vendor-Neutral Excel Extraction.", 'term-system');
        }
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


            if (currentFile) {
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
        

        if (selectedFilename) selectedFilename.textContent = file.name;
        if (selectedFilesize) selectedFilesize.textContent = formatBytes(file.size);

        if (dropzone) dropzone.classList.add('hidden');
        if (selectedFileCard) selectedFileCard.classList.remove('hidden');
        hideError();

        if (btnGenerateBundle) btnGenerateBundle.disabled = false;
        if (btnExtractExcel) btnExtractExcel.disabled = false;
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
            if (true) {
                if (btnGenerateBundle) btnGenerateBundle.disabled = true;
                if (btnExtractExcel) btnExtractExcel.disabled = true;
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
        if (!currentFile) return;

        const formData = new FormData();
        if (currentFile) {
            formData.append('file', currentFile);
        
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
            if (!currentFile) {
                showToast('info', 'No Input', 'Please upload a configuration file first.');
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
    // 8b. Vendor-neutral Excel source inventory
    // =========================================================================
    if (btnExtractExcel) {
        btnExtractExcel.addEventListener('click', async () => {
            if (!currentFile) {
                showToast('info', 'No Input', 'Please upload a configuration file first.');
                return;
            }

            btnExtractExcel.disabled = true;
            const btnText = btnExtractExcel.querySelector('span:last-child');
            const originalText = btnText ? btnText.textContent : 'Download Source Inventory (.xlsx)';
            if (btnText) btnText.textContent = 'Building Source Inventory...';
            hideError();

            const formData = new FormData();
            if (currentFile) {
                formData.append('file', currentFile);
            
            formData.append('source_vendor', selectedSourceVendor);

            try {
                const resp = await fetch('/api/extract/excel', { method: 'POST', body: formData });
                if (!resp.ok) {
                    const errData = await resp.json().catch(() => ({}));
                    throw new Error(errData.error || 'Failed to generate Excel inventory');
                }
                const blob = await resp.blob();
                await downloadBlob(blob, `firewall_inventory_${selectedSourceVendor}.xlsx`);
                showToast('success', 'Inventory Generated', 'Downloaded the pre-optimization source inventory.');
            } catch (err) {
                showError(err.message);
                showToast('error', 'Excel Export Failed', err.message);
            } finally {
                btnExtractExcel.disabled = false;
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
            if (!currentFile) {
                showToast('error', 'No Configuration', 'Please upload a configuration file first.');
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
