document.addEventListener('DOMContentLoaded', () => {
    const ingestionMethodRadios = document.querySelectorAll('input[name="ingestion-method"]');
    const fileMethodRadio = document.querySelector('input[name="ingestion-method"][value="file"]');
    const liveMethodRadio = document.querySelector('input[name="ingestion-method"][value="live"]');
    const ingestFileContainer = document.getElementById('ingest-file-container');
    const ingestLiveContainer = document.getElementById('ingest-live-container');
    const inputMethodHelp = document.getElementById('input-method-help');
    const sourceVendorSelect = document.getElementById('source-vendor-select');
    const fileInput = document.getElementById('file-input');
    const selectedFileCard = document.getElementById('selected-file-card');
    const btnRemoveFile = document.getElementById('btn-remove-file');
    const btnExtractExcel = document.getElementById('btn-extract-excel');
    const extractSourceDesc = document.getElementById('extract-source-desc');

    const liveHost = document.getElementById('live-host');
    const livePort = document.getElementById('live-port');
    const liveUsername = document.getElementById('live-username');
    const livePassword = document.getElementById('live-password');
    const liveVerifyHostKey = document.getElementById('live-verify-host-key');
    const btnToggleLivePassword = document.querySelector('.btn-toggle-live-password');
    const btnLiveTest = document.getElementById('btn-live-test');
    const btnLivePull = document.getElementById('btn-live-pull');
    const liveConnectionStatus = document.getElementById('live-connection-status');
    const liveExportStatus = document.getElementById('live-export-status');
    const liveCollectionPanel = document.getElementById('live-collection-panel');
    const liveMetaComplete = document.getElementById('live-meta-complete');
    const liveMetaHostname = document.getElementById('live-meta-hostname');
    const liveMetaVersion = document.getElementById('live-meta-version');
    const liveMetaSize = document.getElementById('live-meta-size');
    const liveMetaTime = document.getElementById('live-meta-time');
    const liveMetaHash = document.getElementById('live-meta-hash');
    const liveMetaCommands = document.getElementById('live-meta-commands');
    const liveMetaWarnings = document.getElementById('live-meta-warnings');

    if (btnToggleLivePassword) btnToggleLivePassword.classList.add('btn-toggle-password');

    let ingestionMethod = 'file';
    let activeMode = document.querySelector('.tab-btn.active')?.dataset.tab || 'extract';
    let liveCollectionId = null;
    let liveCollectionComplete = false;

    function setStatus(element, kind, text) {
        if (!element) return;
        element.textContent = text;
        if (kind === 'success') element.style.color = 'var(--success)';
        else if (kind === 'error') element.style.color = 'var(--danger)';
        else if (kind === 'warning') element.style.color = 'var(--warning)';
        else element.style.color = 'var(--text-muted)';
    }

    function updateHelpText() {
        if (!inputMethodHelp) return;
        if (activeMode !== 'extract') {
            inputMethodHelp.textContent = 'Live Firewall input is currently available only in Extract Data to Excel. Config file input is used for conversion and live deployment.';
        } else if (ingestionMethod === 'live') {
            inputMethodHelp.textContent = 'Live Firewall currently supports FortiGate source inventory extraction over SSH. The source vendor is locked to FortiGate.';
        } else {
            inputMethodHelp.textContent = 'Upload a configuration backup file, or pull a FortiGate source configuration over SSH for Excel extraction.';
        }
    }

    function updateExtractDescription() {
        if (!extractSourceDesc) return;
        if (ingestionMethod === 'live') {
            extractSourceDesc.textContent = 'Download the parsed source IR from the preserved live FortiGate snapshot as a vendor-neutral Excel workbook. No target conversion or optimizer changes are applied.';
        } else {
            extractSourceDesc.textContent = 'Download the parsed source IR as a vendor-neutral Excel workbook. No target platform or optimizer changes are applied.';
        }
    }

    function clearUploadedFile() {
        const hasSelectedCard = selectedFileCard && !selectedFileCard.classList.contains('hidden');
        const hasInputFile = fileInput && fileInput.files && fileInput.files.length > 0;
        if ((hasSelectedCard || hasInputFile) && btnRemoveFile) {
            btnRemoveFile.click();
        } else if (fileInput) {
            fileInput.value = '';
        }
    }

    function resetLiveCollection() {
        liveCollectionId = null;
        liveCollectionComplete = false;
        if (liveCollectionPanel) liveCollectionPanel.classList.add('hidden');
        if (liveMetaComplete) {
            liveMetaComplete.textContent = 'NOT COLLECTED';
            liveMetaComplete.style.color = 'var(--text-muted)';
        }
        [
            liveMetaHostname,
            liveMetaVersion,
            liveMetaSize,
            liveMetaTime,
            liveMetaHash,
            liveMetaCommands,
            liveMetaWarnings,
        ].forEach((element) => {
            if (element) element.value = '';
        });
        setStatus(liveExportStatus, 'muted', 'Pull a complete source snapshot to enable Excel extraction.');
        updateActionState();
    }

    function updateActionState() {
        if (!btnExtractExcel) return;
        if (ingestionMethod === 'live') {
            btnExtractExcel.disabled = !(liveCollectionId && liveCollectionComplete);
        } else if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
            // The primary app.js enables this again when a file is selected.
            btnExtractExcel.disabled = true;
        }
    }

    function setIngestionMethod(method) {
        if (method === 'live' && activeMode !== 'extract') {
            method = 'file';
        }

        ingestionMethod = method;
        if (fileMethodRadio) fileMethodRadio.checked = method === 'file';
        if (liveMethodRadio) liveMethodRadio.checked = method === 'live';
        if (ingestFileContainer) ingestFileContainer.classList.toggle('hidden', method !== 'file');
        if (ingestLiveContainer) ingestLiveContainer.classList.toggle('hidden', method !== 'live');

        if (method === 'live') {
            clearUploadedFile();
            resetLiveCollection();
            if (sourceVendorSelect) {
                if (sourceVendorSelect.value !== 'fortigate') {
                    sourceVendorSelect.value = 'fortigate';
                    sourceVendorSelect.dispatchEvent(new Event('change', { bubbles: true }));
                }
                sourceVendorSelect.disabled = true;
            }
        } else {
            if (sourceVendorSelect) sourceVendorSelect.disabled = false;
            resetLiveCollection();
        }

        updateHelpText();
        updateExtractDescription();
        updateActionState();
    }

    ingestionMethodRadios.forEach((radio) => {
        radio.addEventListener('change', (event) => {
            if (!event.target.checked) return;
            setIngestionMethod(event.target.value);
        });
    });

    document.querySelectorAll('.tab-btn[data-tab]').forEach((tab) => {
        tab.addEventListener('click', () => {
            activeMode = tab.dataset.tab || 'extract';
            if (liveMethodRadio) {
                liveMethodRadio.disabled = activeMode !== 'extract';
                liveMethodRadio.title = activeMode === 'extract'
                    ? ''
                    : 'Live Firewall input is available only for Excel extraction.';
            }
            if (activeMode !== 'extract' && ingestionMethod === 'live') {
                setIngestionMethod('file');
            } else {
                updateHelpText();
            }
        });
    });

    if (btnToggleLivePassword && livePassword) {
        btnToggleLivePassword.addEventListener('click', () => {
            if (livePassword.type === 'password') {
                livePassword.type = 'text';
                btnToggleLivePassword.textContent = '🔒';
            } else {
                livePassword.type = 'password';
                btnToggleLivePassword.textContent = '👁️';
            }
        });
    }

    function credentials() {
        return {
            host: liveHost ? liveHost.value.trim() : '',
            port: Number(livePort?.value || 22),
            username: liveUsername ? liveUsername.value.trim() : '',
            password: livePassword ? livePassword.value : '',
            verify_host_key: Boolean(liveVerifyHostKey?.checked),
        };
    }

    function validateCredentials(payload) {
        if (!payload.host || !payload.username || !payload.password) {
            throw new Error('FortiGate host, username, and password are required.');
        }
        if (!Number.isInteger(payload.port) || payload.port < 1 || payload.port > 65535) {
            throw new Error('SSH port must be between 1 and 65535.');
        }
    }

    async function postJson(url, body) {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const contentType = response.headers.get('content-type') || '';
        const data = contentType.includes('application/json')
            ? await response.json()
            : null;
        return { response, data };
    }

    function setBusy(button, busy, busyText) {
        if (!button) return;
        const label = button.querySelector('span:last-child');
        if (!label) return;
        if (!button.dataset.originalText) button.dataset.originalText = label.textContent;
        button.disabled = busy;
        label.textContent = busy ? busyText : button.dataset.originalText;
    }

    function renderCollection(data) {
        if (liveCollectionPanel) liveCollectionPanel.classList.remove('hidden');
        if (liveMetaComplete) {
            liveMetaComplete.textContent = data.complete ? 'COMPLETE' : 'INCOMPLETE';
            liveMetaComplete.style.color = data.complete ? 'var(--success)' : 'var(--danger)';
        }
        if (liveMetaHostname) liveMetaHostname.value = data.hostname || 'Unknown';
        if (liveMetaVersion) liveMetaVersion.value = data.software_version || 'Unknown';
        if (liveMetaSize) liveMetaSize.value = `${Number(data.raw_config_bytes || 0).toLocaleString()} bytes`;
        if (liveMetaTime) liveMetaTime.value = data.collected_at || '';
        if (liveMetaHash) liveMetaHash.value = data.sha256 || '';
        if (liveMetaCommands) liveMetaCommands.value = (data.commands_executed || []).join(', ') || 'None';
        if (liveMetaWarnings) liveMetaWarnings.value = (data.warnings || []).join('; ') || 'None';
    }

    if (btnLiveTest) {
        btnLiveTest.addEventListener('click', async () => {
            setBusy(btnLiveTest, true, 'Testing...');
            setStatus(liveConnectionStatus, 'muted', 'Testing SSH connection...');
            try {
                const payload = credentials();
                validateCredentials(payload);
                const { response, data } = await postJson('/api/source/fortigate/test', payload);
                if (!response.ok || !data?.success) {
                    throw new Error(data?.error || data?.message || `HTTP ${response.status}`);
                }
                const hostname = data.hostname ? ` — ${data.hostname}` : '';
                const version = data.software_version ? ` (${data.software_version})` : '';
                setStatus(liveConnectionStatus, 'success', `Connection successful${hostname}${version}`);
            } catch (error) {
                setStatus(liveConnectionStatus, 'error', `Connection failed: ${error.message}`);
            } finally {
                setBusy(btnLiveTest, false, 'Testing...');
            }
        });
    }

    if (btnLivePull) {
        btnLivePull.addEventListener('click', async () => {
            resetLiveCollection();
            setBusy(btnLivePull, true, 'Pulling...');
            setStatus(liveExportStatus, 'muted', 'Collecting the source configuration...');
            try {
                const payload = credentials();
                validateCredentials(payload);
                const { response, data } = await postJson('/api/source/fortigate/pull', payload);
                if (!response.ok || !data?.success) {
                    const details = [
                        data?.error,
                        ...(data?.errors || []),
                        ...(data?.warnings || []),
                    ].filter(Boolean).join('\n');
                    throw new Error(details || `HTTP ${response.status}`);
                }

                liveCollectionId = data.collection_id || null;
                liveCollectionComplete = Boolean(data.complete && liveCollectionId);
                renderCollection(data);
                updateActionState();

                if (!liveCollectionComplete) {
                    throw new Error('FortiGate configuration collection was incomplete.');
                }
                setStatus(liveExportStatus, 'success', 'Complete source snapshot is preserved and ready for Excel extraction.');
            } catch (error) {
                liveCollectionId = null;
                liveCollectionComplete = false;
                updateActionState();
                setStatus(liveExportStatus, 'error', `Collection failed: ${error.message}`);
            } finally {
                setBusy(btnLivePull, false, 'Pulling...');
            }
        });
    }

    async function downloadBlob(blob, filename) {
        if (window.pywebview && window.pywebview.api && typeof window.pywebview.api.save_file_dialog === 'function') {
            const base64Data = await new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onloadend = () => {
                    const result = String(reader.result || '');
                    resolve(result.substring(result.indexOf(',') + 1));
                };
                reader.onerror = reject;
                reader.readAsDataURL(blob);
            });
            const result = await window.pywebview.api.save_file_dialog(filename, base64Data);
            if (result?.cancelled) return false;
            if (!result?.success) throw new Error(result?.error || 'Desktop file save failed.');
            return true;
        }

        const url = window.URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.style.display = 'none';
        anchor.href = url;
        anchor.download = filename;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        window.URL.revokeObjectURL(url);
        return true;
    }

    if (btnExtractExcel) {
        btnExtractExcel.addEventListener('click', async (event) => {
            if (ingestionMethod !== 'live') return;

            // Intercept the existing file-based Excel handler only for live input.
            event.preventDefault();
            event.stopImmediatePropagation();

            if (!liveCollectionId || !liveCollectionComplete) {
                setStatus(liveExportStatus, 'warning', 'Pull a complete source snapshot before downloading the inventory.');
                return;
            }

            setBusy(btnExtractExcel, true, 'Building Source Inventory...');
            setStatus(liveExportStatus, 'muted', 'Parsing the preserved live snapshot and generating Excel...');
            try {
                const response = await fetch('/api/source/fortigate/extract/excel', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ collection_id: liveCollectionId }),
                });
                if (!response.ok) {
                    const data = await response.json().catch(() => ({}));
                    throw new Error(data.error || `HTTP ${response.status}`);
                }

                const blob = await response.blob();
                const disposition = response.headers.get('content-disposition') || '';
                const filenameMatch = disposition.match(/filename="?([^";]+)"?/i);
                const filename = filenameMatch ? filenameMatch[1] : 'firewall_inventory_fortigate.xlsx';
                const saved = await downloadBlob(blob, filename);
                setStatus(
                    liveExportStatus,
                    saved ? 'success' : 'muted',
                    saved
                        ? 'Source inventory generated from the preserved live snapshot.'
                        : 'File save was cancelled.'
                );
            } catch (error) {
                setStatus(liveExportStatus, 'error', `Excel generation failed: ${error.message}`);
            } finally {
                setBusy(btnExtractExcel, false, 'Building Source Inventory...');
                updateActionState();
            }
        }, true);
    }

    if (liveMethodRadio) liveMethodRadio.disabled = activeMode !== 'extract';
    setIngestionMethod('file');
});