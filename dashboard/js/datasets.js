const API_BASE = '/api';

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

let selectedDatasets = new Set();

function updateDatasetActions() {
    const actionsDiv = document.getElementById('dataset-actions');
    actionsDiv.style.display = selectedDatasets.size > 0 ? 'block' : 'none';
}

function toggleDatasetSelection(id, checked) {
    if (checked) {
        selectedDatasets.add(id);
    } else {
        selectedDatasets.delete(id);
    }
    updateSelectAllCheckbox();
    updateDatasetActions();
}

function updateSelectAllCheckbox() {
    const selectAllCheckbox = document.getElementById('select-all-datasets');
    const checkboxes = document.querySelectorAll('.dataset-checkbox');
    const checkedBoxes = document.querySelectorAll('.dataset-checkbox:checked');
    selectAllCheckbox.checked = checkboxes.length > 0 && checkedBoxes.length === checkboxes.length;
    selectAllCheckbox.indeterminate = checkedBoxes.length > 0 && checkedBoxes.length < checkboxes.length;
}

function deleteSelectedDatasets() {
    const selectedIds = Array.from(selectedDatasets);
    if (selectedIds.length === 0) return;

    showConfirm(
        'Delete Selected Datasets',
        `Are you sure you want to delete ${selectedIds.length} dataset(s)? This action cannot be undone.`,
        async () => {
            try {
                const deletePromises = selectedIds.map(id =>
                    apiFetch(`${API_BASE}/datasets/${id}`, { method: 'DELETE' })
                );
                await Promise.all(deletePromises);
                loadDatasets();
            } catch (e) {
                console.error('Delete selected datasets error:', e);
                showModal('Delete Failed', 'An error occurred while deleting the datasets', 'error');
            }
        }
    );
}

function mergeSelectedDatasets() {
    const selectedIds = Array.from(selectedDatasets);
    if (selectedIds.length < 2) {
        showModal('Merge Datasets', 'Please select at least 2 datasets to merge.', 'error');
        return;
    }

    showPrompt(
        'Merge Datasets',
        'Enter a name for the merged dataset:',
        'merged_' + new Date().toISOString().slice(0, 10).replace(/-/g, ''),
        (name) => {
            if (!name || name.trim() === '') {
                return;
            }

            showConfirm(
                'Merge Selected Datasets',
                `Are you sure you want to merge ${selectedIds.length} datasets into "${name.trim()}"?`,
                async () => {
                    try {
                        const res = await apiFetch(`${API_BASE}/datasets/merge`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ ids: selectedIds, name: name.trim() })
                        });
                        if (!res.ok) {
                            const err = await res.json().catch(() => ({}));
                            showModal('Merge Failed', err.error || 'Failed to merge datasets', 'error');
                            return;
                        }
                        loadDatasets();
                    } catch (e) {
                        console.error('Merge datasets error:', e);
                        showModal('Merge Failed', 'An error occurred while merging the datasets', 'error');
                    }
                }
            );
        }
    );
}

async function loadDatasets() {
    try {
        const res = await apiFetch(`${API_BASE}/datasets`);
        if (!res.ok) {
            console.error('Failed to load datasets:', res.status, res.statusText);
            return;
        }
        const data = await res.json();
        const items = (data.items || []).slice().sort((a, b) => {
            const aTime = Date.parse(a.created_at || a.createdAt || '') || 0;
            const bTime = Date.parse(b.created_at || b.createdAt || '') || 0;
            return bTime - aTime;
        });
        renderDatasets(items);
        updateSelectAllCheckbox();
        updateDatasetActions();
    } catch (e) {
        console.error('Error loading datasets:', e);
    }
}

async function loadDatasetSources() {
    try {
        const res = await apiFetch(`${API_BASE}/datasets/sources`);
        const data = await res.json();
        renderSources(data.sources || []);
    } catch (e) {
        console.error('Error loading dataset sources:', e);
    }
}

const activeBalanceTimers = {};

function renderDatasets(items) {
    const tbody = document.getElementById('datasets-list');
    if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--fg-muted);padding:20px;">No datasets yet.</td></tr>';
        return;
    }
    tbody.innerHTML = items.map(d => `
        <tr>
            <td><input type="checkbox" class="dataset-checkbox" data-id="${d._id}" style="margin-right: 8px;">${d.name || '—'}</td>
            <td>${d.type || '—'}</td>
            <td>${d.samples || 0}</td>
            <td>${d.attack_pct || 0}%</td>
            <td>${d.created_at ? new Date(d.created_at).toLocaleDateString() : '—'}</td>
            <td>
                <button class="btn btn-sm process-dataset-btn" data-id="${d._id}" data-name="${escapeHtml(d.name || '')}">
                    <svg class="process-circle" viewBox="0 0 20 20" width="14" height="14">
                        <circle cx="10" cy="10" r="8" fill="none" stroke="var(--border)" stroke-width="2.5"/>
                        <circle class="process-fill" cx="10" cy="10" r="8" fill="none" stroke="#ff570a" stroke-width="2.5" stroke-dasharray="50.27" stroke-dashoffset="50.27" stroke-linecap="round" transform="rotate(-90 10 10)"/>
                    </svg>
                    Process
                </button>
            </td>
            <td><button class="btn btn-sm btn-danger delete-dataset-btn" data-id="${d._id}">Delete</button></td>
        </tr>
    `).join('');

    document.querySelectorAll('.delete-dataset-btn').forEach(btn => {
        btn.addEventListener('click', () => deleteDataset(btn.dataset.id));
    });

    document.querySelectorAll('.dataset-checkbox').forEach(cb => {
        cb.addEventListener('change', () => {
            toggleDatasetSelection(cb.dataset.id, cb.checked);
        });
    });

    document.querySelectorAll('.process-dataset-btn').forEach(btn => {
        btn.addEventListener('click', () => processDataset(btn));
    });

    items.forEach(d => {
        if (d.name) checkActiveBalanceJob(d.name);
    });
}

async function checkActiveBalanceJob(name) {
    try {
        const res = await apiFetch(`${API_BASE}/training/datasets/${encodeURIComponent(name)}/balance/status`);
        if (!res.ok) {
            return;
        }
        const job = await res.json();
        if (!job || job.status === 'idle' || !job.needed) return;

        const btn = Array.from(document.querySelectorAll('.process-dataset-btn')).find(b => b.dataset.name === name);
        if (!btn) { return; }
        const fill = btn.querySelector('.process-fill');
        if (!fill) { return; }

        const pct = Math.min(1, job.collected / job.needed);
        fill.style.strokeDashoffset = String(50.27 * (1 - pct));

        if (job.status === 'done' || job.status === 'error' || job.status === 'partial') {
            return;
        }

        if (job.status === 'running' || job.status === 'collecting') {
            btn.disabled = true;
            btn.classList.add('is-processing');
            fill.classList.add('processing');
            resumeBalancePolling(name, btn, fill, job);
        }
    } catch (e) {
    }
}

function resumeBalancePolling(name, btn, fill, job) {
    if (activeBalanceTimers[name]) clearInterval(activeBalanceTimers[name]);
    let resolved = false;
    const pollStatus = function () {
        apiFetch(`${API_BASE}/training/datasets/${encodeURIComponent(name)}/balance/status`)
            .then(res => res.ok ? res.json() : null)
            .then(j => {
                if (j) {
                    const pct = Math.min(1, j.collected / j.needed);
                    fill.style.strokeDashoffset = String(50.27 * (1 - pct));
                    if ((j.status === 'done' || j.status === 'error' || j.status === 'partial') && !resolved) {
                        resolved = true;
                        clearInterval(activeBalanceTimers[name]);
                        delete activeBalanceTimers[name];
                        btn.disabled = false;
                        btn.classList.remove('is-processing');
                        fill.classList.remove('processing');
                        fill.style.strokeDashoffset = '50.27';
                        if (j.status === 'done') {
                            const totalSamples = j.samples || (j.attack_count + j.benign_count);
                            showModal('Dataset Balanced',
                                totalSamples + ' total samples (' + j.attack_count + ' attacks + ' + j.benign_count + ' benign, ' + j.attack_pct + '% attacks)',
                                'info');
                            loadDatasets();
                        } else if (j.status === 'partial') {
                            const totalSamples = j.samples || (j.attack_count + j.benign_count);
                            showModal('Partially Balanced',
                                'Collected ' + j.benign_count + ' of ' + j.needed + ' benign samples.\n'
                                + totalSamples + ' total (' + j.attack_count + ' attacks + ' + j.benign_count + ' benign, ' + j.attack_pct + '% attacks).\n\n'
                                + 'Generate more benign traffic and try again.',
                                'info');
                        } else {
                            let msg = j.message || 'Failed to balance dataset';
                            let title = 'Balance Failed';
                            if (msg === 'no benign traffic available' || msg === 'caddy access log not found') {
                                title = 'No Benign Traffic Available';
                                msg = 'Not enough benign requests found in the access logs. Browse the application normally and try again.';
                            } else if (msg === 'dataset already at or above 60% attacks') {
                                title = 'Dataset Already Balanced';
                                msg = 'This dataset already has 60% or more attack samples. No benign blending needed.';
                            }
                            showModal(title, msg, 'error');
                        }
                    }
                }
            })
            .catch(() => {});
    };
    activeBalanceTimers[name] = setInterval(pollStatus, 1000);
    pollStatus();
}

function renderSources(sources) {
    const container = document.querySelector('.source-list');
    if (!container) {
        return;
    }
    const icons = {
        sqli: 'sqli',
        xss: 'xss',
        cmdi: 'cmdi',
        lfi: 'cmdi',
        rfi: 'cmdi',
        normal: 'normal'
    };

    container.innerHTML = sources.map(s => {
        const iconClass = icons[s.key] || 'normal';
        const attackPct = s.attackPct || s.attack_pct || 0;
        return `
            <div class="source-item">
                <div class="source-icon ${iconClass}">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                    </svg>
                </div>
                <div class="source-info">
                    <div class="source-name">${s.name}</div>
                    <div class="source-meta">${s.samples.toLocaleString()} samples • ${attackPct}% attack</div>
                </div>

            </div>
        `;
    }).join('');
}

async function generateDataset() {
    const attackType = document.getElementById('attack-type').value;
    const sampleCount = parseInt(document.getElementById('sample-count').value) || 1000;

    const btn = document.querySelector('.btn-primary');
    btn.textContent = 'Generating...';
    btn.disabled = true;

    try {
        const res = await apiFetch(`${API_BASE}/datasets/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                attack_type: attackType,
                sample_count: sampleCount
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            showModal('Generation Failed', err.error || 'Failed to generate dataset', 'error');
            btn.textContent = 'Generate';
            btn.disabled = false;
            return;
        }

        btn.textContent = 'Exporting...';
        await apiFetch(`${API_BASE}/training/datasets/export`, {
            method: 'POST'
        }).catch(() => {});

        btn.textContent = 'Generated!';
        setTimeout(() => {
            btn.textContent = 'Generate';
            btn.disabled = false;
        }, 2000);

        loadDatasets();
    } catch (e) {
        console.error('Generate dataset error:', e);
        btn.textContent = 'Generate';
        btn.disabled = false;
    }
}

async function deleteDataset(id) {
    showConfirm(
        'Delete Dataset',
        'Are you sure you want to delete this dataset? This action cannot be undone.',
        async () => {
            try {
                const res = await apiFetch(`${API_BASE}/datasets/${id}`, {
                    method: 'DELETE'
                });
                if (!res.ok) {
                    const err = await res.json().catch(() => ({}));
                    showModal('Delete Failed', err.error || 'Failed to delete dataset', 'error');
                    return;
                }
                loadDatasets();
            } catch (e) {
                console.error('Delete dataset error:', e);
                showModal('Delete Failed', 'An error occurred while deleting the dataset', 'error');
            }
        }
    );
}

function processDataset(btn) {
    const fill = btn.querySelector('.process-fill');
    if (!fill || fill.classList.contains('processing')) return;

    const name = btn.dataset.name;
    if (!name) return;

    btn.disabled = true;
    btn.classList.add('is-processing');
    fill.classList.add('processing');
    fill.style.strokeDashoffset = '0';

    let pollTimer = null;
    let resolved = false;
    const updateProgress = function (job) {
        if (!job || !job.needed) return;
        const pct = Math.min(1, job.collected / job.needed);
        fill.style.strokeDashoffset = String(50.27 * (1 - pct));
    };

    const finish = function () {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = null;
        if (activeBalanceTimers[name]) { clearInterval(activeBalanceTimers[name]); delete activeBalanceTimers[name]; }
        btn.disabled = false;
        btn.classList.remove('is-processing');
        fill.classList.remove('processing');
        fill.style.strokeDashoffset = '50.27';
    };

    const pollStatus = function () {
        apiFetch(`${API_BASE}/training/datasets/${encodeURIComponent(name)}/balance/status`)
            .then(res => res.ok ? res.json() : null)
            .then(job => {
                if (job) {
                    updateProgress(job);
                    if ((job.status === 'done' || job.status === 'error' || job.status === 'partial') && !resolved) {
                        resolved = true;
                        if (job.status === 'done') {
                            const totalSamples = job.samples || (job.attack_count + job.benign_count);
                            showModal('Dataset Balanced',
                                totalSamples + ' total samples (' + job.attack_count + ' attacks + ' + job.benign_count + ' benign, ' + job.attack_pct + '% attacks)',
                                'info');
                            loadDatasets();
                        } else if (job.status === 'partial') {
                            const totalSamples = job.samples || (job.attack_count + job.benign_count);
                            showModal('Partially Balanced',
                                'Collected ' + job.benign_count + ' of ' + job.needed + ' benign samples.\n'
                                + totalSamples + ' total (' + job.attack_count + ' attacks + ' + job.benign_count + ' benign, ' + job.attack_pct + '% attacks).\n\n'
                                + 'Generate more benign traffic and try again.',
                                'info');
                        } else {
                            let msg = job.message || 'Failed to balance dataset';
                            let title = 'Balance Failed';
                            if (msg === 'no benign traffic available' || msg === 'caddy access log not found') {
                                title = 'No Benign Traffic Available';
                                msg = 'Not enough benign requests found in the access logs. Browse the application normally and try again.';
                            } else if (msg === 'dataset already at or above 60% attacks') {
                                title = 'Dataset Already Balanced';
                                msg = 'This dataset already has 60% or more attack samples. No benign blending needed.';
                            }
                            showModal(title, msg, 'error');
                        }
                        finish();
                    }
                }
            })
            .catch(() => {});
    };

    apiFetch(`${API_BASE}/training/datasets/${encodeURIComponent(name)}/balance`, {
        method: 'POST'
    }).then(function (res) {
        if (!res.ok) {
            return res.json().then(function (data) {
                throw new Error(data.detail || 'HTTP ' + res.status);
            });
        }
        return res.json();
    }).then(function (data) {
        if (data && data.status === 'balanced') {
            resolved = true;
            const totalSamples = data.samples || (data.attack_count + data.benign_count);
            showModal('Dataset Balanced',
                totalSamples + ' total samples (' + data.attack_count + ' attacks + ' + data.benign_count + ' benign, ' + data.attack_pct + '% attacks)',
                'info');
            loadDatasets();
            finish();
        }
    }).catch(function (err) {
        if (!resolved) {
            let msg = err.message || 'Failed to balance dataset';
            let title = 'Balance Failed';
            if (msg.includes('not found') || msg.includes('404')) {
                title = 'Dataset Not Found';
                msg = 'The dataset file could not be found. Make sure the dataset exists on disk.';
            }
            showModal(title, msg, 'error');
            finish();
        }
    });

    pollTimer = setInterval(pollStatus, 1000);
    pollStatus();
}

const generateDatasetBtn = document.getElementById('generate-dataset-btn');
if (generateDatasetBtn) {
    generateDatasetBtn.addEventListener('click', generateDataset);
}

document.getElementById('select-all-datasets').addEventListener('change', function() {
    const checked = this.checked;
    document.querySelectorAll('.dataset-checkbox').forEach(cb => {
        cb.checked = checked;
        toggleDatasetSelection(cb.dataset.id, checked);
    });
});

const deleteSelectedBtn = document.getElementById('delete-selected-btn');
if (deleteSelectedBtn) {
    deleteSelectedBtn.addEventListener('click', deleteSelectedDatasets);
}

const mergeSelectedBtn = document.getElementById('merge-selected-btn');
if (mergeSelectedBtn) {
    mergeSelectedBtn.addEventListener('click', mergeSelectedDatasets);
}

(async () => {
    await requireAuth();
    await loadDatasets();
})();
