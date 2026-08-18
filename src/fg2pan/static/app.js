document.addEventListener('DOMContentLoaded', () => {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('fileInput');
    const selectedFileDiv = document.getElementById('selected-file');
    const filenameSpan = document.getElementById('filename');
    const removeFileBtn = document.getElementById('removeFile');
    const submitBtn = document.getElementById('submitBtn');
    const submitText = submitBtn.querySelector('span');
    const spinner = submitBtn.querySelector('.spinner');
    const errorMsg = document.getElementById('error-message');

    let currentFile = null;

    // Drag and Drop Handlers
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, () => dropzone.classList.add('dragover'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, () => dropzone.classList.remove('dragover'), false);
    });

    dropzone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length) handleFile(files[0]);
    });

    // File Input Handler (Click to browse)
    fileInput.addEventListener('change', function() {
        if (this.files.length) handleFile(this.files[0]);
    });

    // Handle File Selection
    function handleFile(file) {
        if (!file.name.endsWith('.conf') && !file.name.endsWith('.txt')) {
            showError("Please upload a valid FortiGate .conf or .txt file.");
            return;
        }
        
        currentFile = file;
        filenameSpan.textContent = file.name;
        dropzone.classList.add('hidden');
        selectedFileDiv.classList.remove('hidden');
        submitBtn.disabled = false;
        errorMsg.classList.add('hidden');
    }

    // Remove File Handler
    removeFileBtn.addEventListener('click', () => {
        currentFile = null;
        fileInput.value = '';
        selectedFileDiv.classList.add('hidden');
        dropzone.classList.remove('hidden');
        submitBtn.disabled = true;
        errorMsg.classList.add('hidden');
    });

    // Submit Migration
    submitBtn.addEventListener('click', async () => {
        if (!currentFile) return;

        // UI Loading State
        submitBtn.disabled = true;
        submitText.textContent = "Processing Migration...";
        spinner.classList.remove('hidden');
        errorMsg.classList.add('hidden');

        const formData = new FormData();
        formData.append('file', currentFile);

        try {
            const response = await fetch('/api/migrate', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Migration failed. Please check the file format.');
            }

            // Handle file download
            const blob = await response.blob();
            const downloadUrl = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = downloadUrl;
            
            // Extract filename from Content-Disposition header if possible
            const disposition = response.headers.get('Content-Disposition');
            let filename = 'migration_results.zip';
            if (disposition && disposition.indexOf('attachment') !== -1) {
                const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
                const matches = filenameRegex.exec(disposition);
                if (matches != null && matches[1]) { 
                    filename = matches[1].replace(/['"]/g, '');
                }
            }
            
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(downloadUrl);
            a.remove();

        } catch (error) {
            showError(error.message);
        } finally {
            // Reset UI Loading State
            submitBtn.disabled = false;
            submitText.textContent = "Start Migration";
            spinner.classList.add('hidden');
        }
    });

    function showError(message) {
        errorMsg.textContent = message;
        errorMsg.classList.remove('hidden');
    }
});
