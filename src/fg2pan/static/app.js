document.addEventListener('DOMContentLoaded', () => {
    // State
    let currentFile = null;
    let currentApiSessionId = null;
    let currentSessionId = null;
    let selectedSourceVendor = 'fortigate';
    let selectedTargetVendor = 'palo_alto';

    // Elements - Vendor Pills
    const sourceVendorPills = document.querySelectorAll('#source-vendor-pills .vendor-pill');
    const targetVendorPills = document.querySelectorAll('#target-vendor-pills .vendor-pill');
    const dropzoneSub = document.getElementById('dropzone-sub');

    sourceVendorPills.forEach(pill => {
        pill.addEventListener('click', () => {
            sourceVendorPills.forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            selectedSourceVendor = pill.getAttribute('data-source');
            logToTerminal(`[VENDOR] Selected source vendor: ${pill.textContent.trim()}`, 'term-system');

            if (selectedSourceVendor === 'cisco_asa') {
                if (dropzoneSub) dropzoneSub.innerHTML = 'Supports Cisco ASA / Firepower <code>.cfg</code> or <code>.txt</code> files';
                if (fileInput) fileInput.accept = '.cfg,.txt,.conf';
            } else if (selectedSourceVendor === 'checkpoint') {
                if (dropzoneSub) dropzoneSub.innerHTML = 'Supports Check Point R80/R81 <code>.json</code> database dumps';
                if (fileInput) fileInput.accept = '.json,.txt';
            } else if (selectedSourceVendor === 'juniper_srx') {
                if (dropzoneSub) dropzoneSub.innerHTML = 'Supports JunOS SRX <code>.set</code> or <code>.conf</code> files';
                if (fileInput) fileInput.accept = '.set,.txt,.conf';
            } else {
                if (dropzoneSub) dropzoneSub.innerHTML = 'Supports FortiOS <code>.conf</code> or <code>.txt</code> backup files';
                if (fileInput) fileInput.accept = '.conf,.txt,.cfg';
            }

            if (currentFile || currentApiSessionId) {
                fetchMigrationPreview();
            }
        });
    });

    targetVendorPills.forEach(pill => {
        pill.addEventListener('click', () => {
            targetVendorPills.forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            selectedTargetVendor = pill.getAttribute('data-target');
            logToTerminal(`[VENDOR] Selected target platform: ${pill.textContent.trim()}`, 'term-system');
        });
    });

    // Elements - Optimizer & Rule Matrix
    const optimizerSection = document.getElementById('optimizer-section');
    const chkAutoOptimize = document.getElementById('chkAutoOptimize');
    const btnTogglePreview = document.getElementById('btnTogglePreview');
    const ruleMatrixContainer = document.getElementById('rule-matrix-container');
    const ruleMatrixTbody = document.getElementById('rule-matrix-tbody');

    if (btnTogglePreview) {
        btnTogglePreview.addEventListener('click', () => {
            if (ruleMatrixContainer) {
                ruleMatrixContainer.classList.toggle('hidden');
                btnTogglePreview.querySelector('span').textContent = ruleMatrixContainer.classList.contains('hidden') ? '👁️ View Rule Matrix' : '✕ Hide Rule Matrix';
            }
        });
    }

    // Elements - File Ingestion & API Ingestion Switch
    const btnIngestFile = document.getElementById('btn-ingest-file');
    const btnIngestApi = document.getElementById('btn-ingest-api');
    const ingestFileContainer = document.getElementById('ingest-file-container');
    const ingestApiContainer = document.getElementById('ingest-api-container');

    // Elements - File Ingestion
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('fileInput');
    const selectedFileDiv = document.getElementById('selected-file');
    const filenameSpan = document.getElementById('filename');
    const fileSizeSpan = document.getElementById('file-size');
    const removeFileBtn = document.getElementById('removeFile');
    const errorBanner = document.getElementById('error-message');

    // Elements - Live FortiGate API Ingestion Form
    const radioFgAuthMethods = document.querySelectorAll('input[name="fgAuthMethod"]');
    const fgGroupApiKey = document.getElementById('fg-group-apikey');
    const fgGroupUserPass = document.getElementById('fg-group-userpass');
    const btnFetchFortiGateApi = document.getElementById('btnFetchFortiGateApi');
    const apiIngestSuccess = document.getElementById('api-ingest-success');
    const apiHostnameSpan = document.getElementById('api-hostname');
    const apiStatsSummarySpan = document.getElementById('api-stats-summary');
    const clearApiIngestBtn = document.getElementById('clearApiIngest');
    const apiIngestError = document.getElementById('api-ingest-error');
    const apiErrorTitle = document.getElementById('api-error-title');
    const apiErrorDetail = document.getElementById('api-error-detail');
    const apiErrorHint = document.getElementById('api-error-hint');
    const dismissApiErrorBtn = document.getElementById('dismissApiError');
    const toastContainer = document.getElementById('toast-container');

    // Elements - Mode Tabs
    const tabDownload = document.getElementById('tab-download');
    const tabLive = document.getElementById('tab-live');
    const panelDownload = document.getElementById('panel-download');
    const panelLive = document.getElementById('panel-live');

    // Elements - Mode A
    const submitDownloadBtn = document.getElementById('submitDownloadBtn');

    // Elements - Mode B (Target Palo Alto Form & Diagnostics)
    const btnRunDiagnostics = document.getElementById('btnRunDiagnostics');
    const radioAuthMethods = document.querySelectorAll('input[name="authMethod"]');
    const groupApiKey = document.getElementById('group-apikey');
    const groupUserPass = document.getElementById('group-userpass');
    const togglePasswordBtns = document.querySelectorAll('.btn-toggle-password');

    // Elements - Mode B (Stepper & Actions)
    const btnPrepare = document.getElementById('btnPrepare');
    const btnPlan = document.getElementById('btnPlan');
    const btnApply = document.getElementById('btnApply');
    const planBadges = document.getElementById('plan-badges');
    const badgeAdd = document.getElementById('badge-add');
    const badgeChange = document.getElementById('badge-change');
    const badgeDestroy = document.getElementById('badge-destroy');

    // Elements - Terminal
    const terminalBody = document.getElementById('terminal-body');
    const chkAutoScroll = document.getElementById('chkAutoScroll');
    const btnClearLogs = document.getElementById('btnClearLogs');

    // Elements - Post Actions
    const postActionsBar = document.getElementById('post-actions');
    const btnDownloadState = document.getElementById('btnDownloadState');
    const btnDownloadLivePackage = document.getElementById('btnDownloadLivePackage');

    // -------------------------------------------------------------------------
    // 1. Ingestion Method Tabs (File vs Live REST API)
    // -------------------------------------------------------------------------
    btnIngestFile.addEventListener('click', () => {
        btnIngestFile.classList.add('active');
        btnIngestApi.classList.remove('active');
        ingestFileContainer.classList.remove('hidden');
        ingestApiContainer.classList.add('hidden');
    });

    btnIngestApi.addEventListener('click', () => {
        btnIngestApi.classList.add('active');
        btnIngestFile.classList.remove('active');
        ingestApiContainer.classList.remove('hidden');
        ingestFileContainer.classList.add('hidden');
    });

    // FortiGate Auth Radio Switch
    radioFgAuthMethods.forEach(radio => {
        radio.addEventListener('change', (e) => {
            if (e.target.value === 'apikey') {
                fgGroupApiKey.classList.remove('hidden');
                fgGroupUserPass.classList.add('hidden');
            } else {
                fgGroupApiKey.classList.add('hidden');
                fgGroupUserPass.classList.remove('hidden');
            }
        });
    });

    // Clear input validation errors on typing
    ['fgHost', 'fgPort', 'fgApiKey', 'fgUsername', 'fgPassword', 'fgVdom'].forEach(id => {
        const inputEl = document.getElementById(id);
        if (inputEl) {
            inputEl.addEventListener('input', () => {
                inputEl.classList.remove('input-invalid');
                const parent = inputEl.closest('.form-group') || inputEl.parentElement;
                const err = parent.querySelector('.field-error-text');
                if (err) err.remove();
            });
        }
    });

    if (dismissApiErrorBtn) {
        dismissApiErrorBtn.addEventListener('click', hideApiIngestError);
    }

    // FortiGate Live REST API Ingest Button
    btnFetchFortiGateApi.addEventListener('click', async () => {
        clearInputErrors();
        hideApiIngestError();
        hideError();

        const host = document.getElementById('fgHost').value.trim();
        const port = parseInt(document.getElementById('fgPort').value.trim() || '443');
        const authMethod = document.querySelector('input[name="fgAuthMethod"]:checked').value;
        const apiKey = document.getElementById('fgApiKey').value.trim();
        const username = document.getElementById('fgUsername').value.trim();
        const password = document.getElementById('fgPassword').value.trim();
        const vdom = document.getElementById('fgVdom').value.trim() || 'root';
        const verifySsl = document.getElementById('fgVerifySsl').checked;

        // Client-side Input Validations
        if (!host) {
            showInputError('fgHost', 'FortiGate Hostname or IP is required.');
            showToast('error', 'Missing Host', 'Please enter a valid FortiGate IP address or hostname.');
            return;
        }

        if (authMethod === 'apikey' && !apiKey) {
            showInputError('fgApiKey', 'API Token is required for REST API Token authentication.');
            showToast('error', 'Missing API Token', 'Please enter your FortiOS REST API token.');
            return;
        }

        if (authMethod === 'userpass') {
            let hasError = false;
            if (!username) {
                showInputError('fgUsername', 'Admin Username is required.');
                hasError = true;
            }
            if (!password) {
                showInputError('fgPassword', 'Admin Password is required.');
                hasError = true;
            }
            if (hasError) {
                showToast('error', 'Missing Credentials', 'Please enter both Admin username and password.');
                return;
            }
        }

        btnFetchFortiGateApi.disabled = true;
        const btnText = btnFetchFortiGateApi.querySelector('.btn-text');
        const spinner = btnFetchFortiGateApi.querySelector('.spinner');
        btnText.textContent = `Connecting to ${host}:${port}...`;
        spinner.classList.remove('hidden');
        apiIngestSuccess.classList.add('hidden');

        logToTerminal(`[INGEST] Initiating live REST API extraction from FortiGate (${host}:${port}, VDOM: ${vdom})...`, 'term-system');

        try {
            const payload = {
                host,
                port,
                vdom,
                verify_ssl: verifySsl
            };

            if (authMethod === 'apikey') {
                payload.api_key = apiKey;
            } else {
                payload.username = username;
                payload.password = password;
            }

            const resp = await fetch('/api/ingest/fortigate-api', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await resp.json();
            if (!data.success) throw new Error(data.error || 'Failed to pull configuration from FortiGate API');

            currentApiSessionId = data.session_id;
            currentFile = null; // Clear file if live API is used

            apiHostnameSpan.textContent = `${data.hostname} (Live FortiGate Connected)`;
            apiStatsSummarySpan.textContent = `${data.stats.interfaces} interfaces • ${data.stats.addresses} addresses • ${data.stats.policies} policies • ${data.stats.nat_rules} NAT rules`;
            apiIngestSuccess.classList.remove('hidden');
            hideApiIngestError();

            submitDownloadBtn.disabled = false;
            btnPrepare.disabled = false;

            showToast('success', 'Extraction Successful', `Extracted configuration from FortiGate '${data.hostname}'`);
            logToTerminal(`[INGEST] Successfully pulled configuration from FortiGate '${data.hostname}' (${data.stats.interfaces} interfaces, ${data.stats.policies} policies). Ready for migration!`, 'term-success');

        } catch (err) {
            currentApiSessionId = null;
            apiIngestSuccess.classList.add('hidden');
            if (!currentFile) {
                submitDownloadBtn.disabled = true;
                btnPrepare.disabled = true;
            }
            showApiIngestError(err.message);
            showError(`FortiGate Connection Error: ${err.message}`);
            logToTerminal(`[ERROR] FortiGate API Extraction failed: ${err.message}`, 'term-error');
        } finally {
            btnFetchFortiGateApi.disabled = false;
            btnText.textContent = "⚡ Pull Configuration from Live FortiGate";
            spinner.classList.add('hidden');
        }
    });

    clearApiIngestBtn.addEventListener('click', () => {
        currentApiSessionId = null;
        apiIngestSuccess.classList.add('hidden');
        hideApiIngestError();
        if (!currentFile) {
            submitDownloadBtn.disabled = true;
            btnPrepare.disabled = true;
            btnPlan.disabled = true;
            btnApply.disabled = true;
        }
        logToTerminal("[INGEST] Live FortiGate configuration cleared.", 'term-system');
    });

    // -------------------------------------------------------------------------
    // 2. Mode Tab Switching
    // -------------------------------------------------------------------------
    tabDownload.addEventListener('click', () => switchTab('download'));
    tabLive.addEventListener('click', () => switchTab('live'));

    function switchTab(mode) {
        if (mode === 'download') {
            tabDownload.classList.add('active');
            tabLive.classList.remove('active');
            panelDownload.classList.remove('hidden');
            panelLive.classList.add('hidden');
        } else {
            tabLive.classList.add('active');
            tabDownload.classList.remove('active');
            panelLive.classList.remove('hidden');
            panelDownload.classList.add('hidden');
        }
    }

    // -------------------------------------------------------------------------
    // 3. Drag & Drop File Handling
    // -------------------------------------------------------------------------
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

    function handleFileSelect(file) {
        if (!file) return;
        const lowerName = file.name.toLowerCase();
        if (!lowerName.endsWith('.conf') && !lowerName.endsWith('.txt') && !lowerName.endsWith('.cfg')) {
            // Warn but still allow processing if user uploaded a text configuration with different extension
            logToTerminal(`[WARNING] Uploaded file '${file.name}' does not have a standard .conf/.txt extension, attempting parse.`, 'term-log');
        }

        currentFile = file;
        currentApiSessionId = null;
        filenameSpan.textContent = file.name;
        fileSizeSpan.textContent = formatBytes(file.size);

        dropzone.classList.add('hidden');
        selectedFileDiv.classList.remove('hidden');
        hideError();

        submitDownloadBtn.disabled = false;
        btnPrepare.disabled = false;
        logToTerminal(`[FILE] Loaded '${file.name}' (${formatBytes(file.size)}). Ready for processing.`, 'term-system');

        // Trigger Configuration Intelligence & Rule Optimizer Preview
        fetchMigrationPreview();
    }

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
                if (optimizerSection) optimizerSection.classList.remove('hidden');
                document.getElementById('stat-total-policies').textContent = data.stats.policies || 0;
                document.getElementById('stat-total-addresses').textContent = data.stats.addresses || 0;
                document.getElementById('stat-unused-addresses').textContent = data.optimization.unused_addresses_count || 0;
                document.getElementById('stat-unused-services').textContent = data.optimization.unused_services_count || 0;
                document.getElementById('stat-shadowed-rules').textContent = data.optimization.shadowed_rules_count || 0;

                // Render Rule Matrix
                if (ruleMatrixTbody && data.policies) {
                    ruleMatrixTbody.innerHTML = '';
                    data.policies.forEach(p => {
                        const tr = document.createElement('tr');
                        const actClass = p.action === 'allow' ? 'action-permit' : 'action-deny';
                        tr.innerHTML = `
                            <td>${p.index}</td>
                            <td><strong>${escapeHtml(p.id)}</strong></td>
                            <td>${escapeHtml((p.from_zone || []).join(', '))}</td>
                            <td>${escapeHtml((p.to_zone || []).join(', '))}</td>
                            <td>${escapeHtml((p.source || []).join(', '))}</td>
                            <td>${escapeHtml((p.destination || []).join(', '))}</td>
                            <td>${escapeHtml((p.service || []).join(', '))}</td>
                            <td class="${actClass}">${p.action.toUpperCase()}</td>
                        `;
                        ruleMatrixTbody.appendChild(tr);
                    });
                }
            }
        } catch (err) {
            console.error('Preview error:', err);
        }
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    removeFileBtn.addEventListener('click', () => {
        currentFile = null;
        fileInput.value = '';
        selectedFileDiv.classList.add('hidden');
        dropzone.classList.remove('hidden');
        if (optimizerSection) optimizerSection.classList.add('hidden');
        if (!currentApiSessionId) {
            submitDownloadBtn.disabled = true;
            btnPrepare.disabled = true;
            btnPlan.disabled = true;
            btnApply.disabled = true;
        }
        planBadges.classList.add('hidden');
        postActionsBar.classList.add('hidden');
        hideError();
        logToTerminal("[FILE] Configuration file unloaded.", 'term-system');
    });

    // -------------------------------------------------------------------------
    // 4. Form Interactions (Target Palo Alto)
    // -------------------------------------------------------------------------
    radioAuthMethods.forEach(radio => {
        radio.addEventListener('change', (e) => {
            if (e.target.value === 'apikey') {
                groupApiKey.classList.remove('hidden');
                groupUserPass.classList.add('hidden');
            } else {
                groupApiKey.classList.add('hidden');
                groupUserPass.classList.remove('hidden');
            }
        });
    });

    togglePasswordBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            const input = document.getElementById(targetId);
            if (input.type === 'password') {
                input.type = 'text';
                btn.textContent = '🔒';
            } else {
                input.type = 'password';
                btn.textContent = '👁️';
            }
        });
    });

    // -------------------------------------------------------------------------
    // 5. Pre-Flight Diagnostics
    // -------------------------------------------------------------------------
    btnRunDiagnostics.addEventListener('click', async () => {
        const host = document.getElementById('panHost').value.trim();
        const port = parseInt(document.getElementById('panPort').value.trim() || '443');
        const authMethod = document.querySelector('input[name="authMethod"]:checked').value;
        const apiKey = document.getElementById('panApiKey').value.trim();
        const username = document.getElementById('panUsername').value.trim();
        const password = document.getElementById('panPassword').value.trim();
        const verifySsl = document.getElementById('panVerifySsl').checked;

        logToTerminal(`[DIAGNOSTICS] Probing diagnostics for ${host}:${port}...`, 'term-system');
        btnRunDiagnostics.disabled = true;
        setDiagLoadingAll();

        try {
            const payload = {
                host,
                port,
                verify_ssl: verifySsl,
                auto_download_tf: true
            };

            if (authMethod === 'apikey') {
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

        } catch (err) {
            showError(`Diagnostics error: ${err.message}`);
            logToTerminal(`[ERROR] Diagnostics failed: ${err.message}`, 'term-error');
        } finally {
            btnRunDiagnostics.disabled = false;
        }
    });

    function setDiagLoadingAll() {
        ['terraform', 'registry', 'line-of-sight', 'auth'].forEach(name => {
            const card = document.getElementById(`diag-${name}`);
            if (card) {
                card.className = 'diag-card pending';
                card.querySelector('.diag-msg').textContent = 'Probing...';
            }
        });
    }

    function updateDiagCard(name, status, msg) {
        let cardId = `diag-${name}`;
        if (name === 'terraform_cli') cardId = 'diag-terraform';
        if (name === 'registry_access') cardId = 'diag-registry';
        if (name === 'palo_alto_line_of_sight') cardId = 'diag-line-of-sight';
        if (name === 'palo_alto_auth') cardId = 'diag-auth';

        const card = document.getElementById(cardId);
        if (card) {
            card.className = `diag-card ${status}`;
            card.querySelector('.diag-msg').textContent = msg;
        }
    }

    // -------------------------------------------------------------------------
    // 6. Mode A: Download Package (.zip)
    // -------------------------------------------------------------------------
    submitDownloadBtn.addEventListener('click', async () => {
        if (!currentFile && !currentApiSessionId) return;

        submitDownloadBtn.disabled = true;
        const btnText = submitDownloadBtn.querySelector('.btn-text');
        const spinner = submitDownloadBtn.querySelector('.spinner');
        btnText.textContent = "Compiling Migration Package...";
        spinner.classList.remove('hidden');
        hideError();

        const formData = new FormData();
        if (currentFile) {
            formData.append('file', currentFile);
        } else if (currentApiSessionId) {
            formData.append('session_id', currentApiSessionId);
        }
        formData.append('source_vendor', selectedSourceVendor);
        formData.append('target_vendor', selectedTargetVendor);
        formData.append('optimize', chkAutoOptimize ? (chkAutoOptimize.checked ? 'true' : 'false') : 'false');

        try {
            const resp = await fetch('/api/migrate', {
                method: 'POST',
                body: formData
            });

            if (!resp.ok) {
                const errData = await resp.json();
                throw new Error(errData.error || 'Failed to generate package');
            }

            const blob = await resp.blob();
            downloadBlob(blob, `migration_${selectedSourceVendor}_to_${selectedTargetVendor}.zip`);

        } catch (err) {
            showError(err.message);
        } finally {
            submitDownloadBtn.disabled = false;
            btnText.textContent = "Generate & Download Package (.zip)";
            spinner.classList.add('hidden');
        }
    });

    // -------------------------------------------------------------------------
    // 7. Mode B: Step 1 - Prepare Configuration
    // -------------------------------------------------------------------------
    btnPrepare.addEventListener('click', async () => {
        if (!currentFile && !currentApiSessionId) return;

        btnPrepare.disabled = true;
        logToTerminal(`[PREPARE] Parsing ${selectedSourceVendor} configuration and constructing IR for ${selectedTargetVendor}...`, 'term-system');

        const formData = new FormData();
        if (currentFile) {
            formData.append('file', currentFile);
        } else if (currentApiSessionId) {
            formData.append('session_id', currentApiSessionId);
        }

        formData.append('source_vendor', selectedSourceVendor);
        formData.append('target_vendor', selectedTargetVendor);
        formData.append('host', document.getElementById('panHost').value.trim());
        formData.append('port', document.getElementById('panPort').value.trim());
        formData.append('vsys', document.getElementById('panVsys').value.trim());
        formData.append('device_group', document.getElementById('panDeviceGroup').value.trim());

        const authMethod = document.querySelector('input[name="authMethod"]:checked').value;
        if (authMethod === 'apikey') {
            formData.append('api_key', document.getElementById('panApiKey').value.trim());
        } else {
            formData.append('username', document.getElementById('panUsername').value.trim());
            formData.append('password', document.getElementById('panPassword').value.trim());
        }

        try {
            const resp = await fetch('/api/terraform/prepare', {
                method: 'POST',
                body: formData
            });

            const data = await resp.json();
            if (!data.success) throw new Error(data.error || 'Preparation failed');

            currentSessionId = data.session_id;
            logToTerminal(`[PREPARE] Session ${currentSessionId} initialized with ${data.stats.addresses} addresses, ${data.stats.policies} policies, ${data.stats.nat_rules} NAT rules.`, 'term-success');

            btnPlan.disabled = false;
            btnPrepare.classList.replace('btn-secondary', 'btn-outline');
            document.getElementById('prepare-status-text').textContent = `Session ${currentSessionId} ready with generated HCL.`;

        } catch (err) {
            showError(`Prepare error: ${err.message}`);
            logToTerminal(`[ERROR] Prepare failed: ${err.message}`, 'term-error');
        } finally {
            btnPrepare.disabled = false;
        }
    });

    // -------------------------------------------------------------------------
    // 8. Mode B: Step 2 - Dry-Run Plan (`terraform plan`)
    // -------------------------------------------------------------------------
    btnPlan.addEventListener('click', async () => {
        if (!currentSessionId) return;

        btnPlan.disabled = true;
        logToTerminal("[PLAN] Initializing Terraform and executing dry-run plan...", 'term-system');

        try {
            const resp = await fetch('/api/terraform/plan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: currentSessionId })
            });

            const data = await resp.json();
            if (!data.success) {
                if (data.init_log) logToTerminal(data.init_log, 'term-log');
                if (data.plan_log) logToTerminal(data.plan_log, 'term-log');
                throw new Error(data.error || 'Plan failed');
            }

            if (data.init_log) logToTerminal(data.init_log, 'term-log');
            if (data.plan_log) logToTerminal(data.plan_log, 'term-log');

            const summary = data.summary || { add: 0, change: 0, destroy: 0 };
            badgeAdd.textContent = `+ ${summary.add} to add`;
            badgeChange.textContent = `~ ${summary.change} to change`;
            badgeDestroy.textContent = `- ${summary.destroy} to destroy`;
            planBadges.classList.remove('hidden');

            logToTerminal(`[PLAN] Plan succeeded: +${summary.add} to add, ~${summary.change} to change, -${summary.destroy} to destroy. Ready for Live Push.`, 'term-success');

            btnApply.disabled = false;
            document.getElementById('plan-status-text').textContent = "Plan verified. Review changes and click Live Push.";

        } catch (err) {
            showError(`Plan error: ${err.message}`);
            logToTerminal(`[ERROR] Plan failed: ${err.message}`, 'term-error');
        } finally {
            btnPlan.disabled = false;
        }
    });

    // -------------------------------------------------------------------------
    // 9. Mode B: Step 3 - Live Apply (`terraform apply` via SSE)
    // -------------------------------------------------------------------------
    btnApply.addEventListener('click', () => {
        if (!currentSessionId) return;

        const confirmApply = confirm("Are you sure you want to apply this configuration to the live Palo Alto firewall?");
        if (!confirmApply) return;

        btnApply.disabled = true;
        btnPlan.disabled = true;
        logToTerminal("[APPLY] Starting live SSE deployment stream...", 'term-system');

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
                        postActionsBar.classList.remove('hidden');
                        document.getElementById('apply-status-text').textContent = "Deployment completed successfully.";
                    } else {
                        logToTerminal(`[FAILED] ${data.message}`, 'term-error');
                        showError(data.message);
                    }
                    btnApply.disabled = false;
                    btnPlan.disabled = false;
                } else if (data.event === 'error') {
                    evtSource.close();
                    logToTerminal(`[ERROR] ${data.message}`, 'term-error');
                    showError(data.message);
                    btnApply.disabled = false;
                    btnPlan.disabled = false;
                }
            } catch (err) {
                console.error("Error parsing SSE data:", err);
            }
        };

        evtSource.onerror = () => {
            evtSource.close();
            logToTerminal("[ERROR] Connection to live deployment stream lost.", 'term-error');
            btnApply.disabled = false;
            btnPlan.disabled = false;
        };
    });

    // -------------------------------------------------------------------------
    // 10. Post Actions (State & Package Download)
    // -------------------------------------------------------------------------
    btnDownloadState.addEventListener('click', () => {
        if (!currentSessionId) return;
        window.location.href = `/api/download/state?session_id=${currentSessionId}`;
    });

    btnDownloadLivePackage.addEventListener('click', () => {
        if (!currentSessionId) return;
        window.location.href = `/api/download/package?session_id=${currentSessionId}`;
    });

    // -------------------------------------------------------------------------
    // 11. Terminal Helpers
    // -------------------------------------------------------------------------
    btnClearLogs.addEventListener('click', () => {
        terminalBody.innerHTML = '';
        logToTerminal("[SYSTEM] Terminal cleared.", 'term-system');
    });

    function logToTerminal(text, className = 'term-log') {
        const line = document.createElement('div');
        line.className = `term-line ${className}`;
        line.textContent = text;
        terminalBody.appendChild(line);

        if (chkAutoScroll.checked) {
            terminalBody.scrollTop = terminalBody.scrollHeight;
        }
    }

    // -------------------------------------------------------------------------
    // 12. Utilities & Feedback System
    // -------------------------------------------------------------------------
    function clearInputErrors() {
        document.querySelectorAll('.input-invalid').forEach(el => el.classList.remove('input-invalid'));
        document.querySelectorAll('.field-error-text').forEach(el => el.remove());
    }

    function showInputError(elementId, message) {
        const el = document.getElementById(elementId);
        if (!el) return;
        el.classList.add('input-invalid');

        const parent = el.closest('.form-group') || el.parentElement;
        const existingError = parent.querySelector('.field-error-text');
        if (existingError) existingError.remove();

        const errEl = document.createElement('div');
        errEl.className = 'field-error-text';
        errEl.innerHTML = `<span>⚠️</span> <span>${message}</span>`;

        if (el.closest('.password-wrapper')) {
            el.closest('.password-wrapper').insertAdjacentElement('afterend', errEl);
        } else {
            el.insertAdjacentElement('afterend', errEl);
        }
        el.focus();
    }

    function formatApiErrorMessage(errMessage) {
        const msg = (errMessage || '').toLowerCase();

        if (msg.includes('401') || msg.includes('403') || msg.includes('authentication failed') || msg.includes('login failed') || msg.includes('unauthorized') || msg.includes('forbidden')) {
            return {
                title: "FortiGate Authentication Failed",
                detail: errMessage || "Invalid API Token or Admin Credentials.",
                hint: "💡 <strong>Troubleshooting:</strong> Verify your REST API Token or Username/Password. Ensure the FortiOS administrator profile has CMDB Read permissions."
            };
        }
        if (msg.includes('ssl') || msg.includes('certificate') || msg.includes('cert') || msg.includes('tlsv1')) {
            return {
                title: "SSL Certificate Validation Error",
                detail: errMessage,
                hint: "💡 <strong>Troubleshooting:</strong> If your FortiGate uses a self-signed HTTPS certificate, uncheck <em>'Strict SSL Validation'</em> and try again."
            };
        }
        if (msg.includes('connection refused') || msg.includes('timed out') || msg.includes('timeout') || msg.includes('failed to reach') || msg.includes('max retries') || msg.includes('name or service not known') || msg.includes('gaierror') || msg.includes('failed to establish')) {
            return {
                title: "FortiGate Host Unreachable",
                detail: errMessage,
                hint: "💡 <strong>Troubleshooting:</strong> Check the Hostname / IP and HTTPS port (default: 443). Ensure network connectivity and that HTTPS management access is enabled on the FortiGate interface."
            };
        }
        if (msg.includes('vdom') || msg.includes('404')) {
            return {
                title: "Resource or VDOM Not Found",
                detail: errMessage,
                hint: "💡 <strong>Troubleshooting:</strong> Check that the specified Virtual Domain (VDOM) exists on this FortiGate."
            };
        }
        return {
            title: "FortiGate Live Ingest Failed",
            detail: errMessage || "An unexpected error occurred while communicating with the FortiGate REST API.",
            hint: "💡 <strong>Troubleshooting:</strong> Review the FortiGate parameters and verify REST API access."
        };
    }

    function showApiIngestError(errMessage) {
        if (!apiIngestError) return;
        const parsed = formatApiErrorMessage(errMessage);
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
        if (apiIngestError) {
            apiIngestError.classList.add('hidden');
        }
    }

    function showToast(type, title, msg, duration = 6500) {
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
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                <div class="toast-msg">${msg}</div>
            </div>
            <button class="toast-close" type="button" aria-label="Close">✕</button>
        `;

        const removeToast = () => {
            toast.classList.add('toast-hiding');
            setTimeout(() => toast.remove(), 250);
        };

        const closeBtn = toast.querySelector('.toast-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', removeToast);
        }

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
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function downloadBlob(blob, filename) {
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
});
