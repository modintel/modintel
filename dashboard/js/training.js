const API_BASE = '/api';
let trainingPollInterval = null;
let selectedTrainingVersions = new Set();
let allTrainingHistory = [];

function normalizeHistory(data) {
    const items = Array.isArray(data) ? data : (data && data.items ? data.items : []);
    return items.map((item) => {
        const safe = item && typeof item === 'object' ? item : {};
        const targetLayer = safe.model_family === 'miss' ? 'layer2'
            : safe.target_layer || safe.targetLayer || 'layer1';
        return { ...safe, target_layer: targetLayer };
    });
}

function formatPct(value) {
    const num = Number(value);
    if (!Number.isFinite(num)) return '—';
    return num.toFixed(2) + '%';
}

function formatDate(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toLocaleDateString();
}

async function loadDatasets() {
    var select = document.getElementById('train-dataset');
    try {
        var res = await apiFetch(API_BASE + '/datasets');
        var data = await res.json();
        var items = data.items || [];
        select.innerHTML = '';
        if (items.length === 0) {
            select.innerHTML = '<option value="">No datasets found</option>';
            return;
        }
        items.forEach(function (ds) {
            var opt = document.createElement('option');
            opt.value = ds.name;
            opt.textContent = ds.name + (ds.type ? ' (' + ds.type + ')' : '');
            select.appendChild(opt);
        });
    } catch (e) {
        select.innerHTML = '<option value="">Failed to load datasets</option>';
    }
}

async function loadTrainingStatus() {
    try {
        const res = await apiFetch(`${API_BASE}/training/status`);
        const data = await res.json();
        if (data.training_active) {
            const btn = document.getElementById('train-model-btn');
            btn.textContent = 'Training...';
            btn.disabled = true;
            if (!trainingPollInterval) {
                pollTrainingJob();
            }
        }
    } catch (e) {
        console.error('Error loading training status:', e);
    }
}

async function loadTrainingHistory() {
    try {
        const res = await apiFetch(`${API_BASE}/training/history`);
        const data = await res.json();
        allTrainingHistory = normalizeHistory(data);

        const activeBtn = document.querySelector('.panel-right-header .view-btn.active');
        const view = activeBtn ? activeBtn.dataset.view : 'layer1';

        let filtered = allTrainingHistory;
        if (view === 'layer1') {
            filtered = allTrainingHistory.filter(item => item.target_layer === 'layer1');
        } else if (view === 'layer2') {
            filtered = allTrainingHistory.filter(item => item.target_layer === 'layer2');
        }

        renderHistory(filtered);
        if (filtered.length > 0) {
            updateEvalMetrics(filtered[0]);
        }
        updateActiveStatus();
    } catch (e) {
        console.error('Error loading training history:', e);
    }
}

function updateActiveStatus() {
    const container = document.getElementById('active-status');
    if (!container) return;

    const layer1 = allTrainingHistory.find(item => item.active && item.target_layer === 'layer1');
    const layer2 = allTrainingHistory.find(item => item.active && item.target_layer === 'layer2');

    const fmt = (v) => v != null ? Number(v).toFixed(1) + '%' : '—';

    container.innerHTML = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;">
            <div class="metric" style="padding:6px;">
                <div class="metric-label">Layer 1</div>
                <div class="metric-value" style="font-size:0.9rem;">${layer1 ? layer1.version : '—'}</div>
                <div style="font-size:0.65rem;color:var(--fg-muted);margin-top:6px;">
                    ${layer1 ? `P:${fmt(layer1.precision)} | R:${fmt(layer1.recall)} | F1:${fmt(layer1.f1_score)}` : 'No active model'}
                </div>
            </div>
            <div class="metric" style="padding:6px;">
                <div class="metric-label">Layer 2</div>
                <div class="metric-value" style="font-size:0.9rem;">${layer2 ? layer2.version : '—'}</div>
                <div style="font-size:0.65rem;color:var(--fg-muted);margin-top:6px;">
                    ${layer2 ? `P:${fmt(layer2.precision)} | R:${fmt(layer2.recall)} | F1:${fmt(layer2.f1_score)}` : 'No active model'}
                </div>
            </div>
        </div>
    `;
}

function getCurrentView() {
    const activeBtn = document.querySelector('.panel-right-header .view-btn.active');
    return activeBtn ? activeBtn.dataset.view : 'layer1';
}

function renderHistory(items) {
    const tbody = document.getElementById('training-history');
    const view = getCurrentView();
    const isLayer1 = view === 'layer1';
    if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;color:var(--fg-muted);padding:20px;">No training history yet.</td></tr>';
        updateTrainingActions();
        return;
    }
    tbody.innerHTML = items.map(item => {
        const isMiss = (item.model_family === 'miss');
        const composite = isMiss && item.composite_score != null ? (item.composite_score * 100).toFixed(2) + '%' : '—';
        return `
        <tr>
            <td style="white-space: nowrap;"><input type="checkbox" class="training-checkbox" data-version="${item.version}" style="margin-right: 8px;" ${item.active || isLayer1 ? 'disabled' : ''}>${item.version}</td>
            <td style="max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${item.model_type}</td>
            <td style="max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${item.dataset}</td>
            <td style="white-space: nowrap;">${formatPct(item.precision)}</td>
            <td style="white-space: nowrap;">${formatPct(item.recall)}</td>
            <td style="color:var(--accent); white-space: nowrap;">${formatPct(item.fpr)}</td>
            <td style="white-space: nowrap;">${isMiss ? composite : formatPct(item.f1_score)}</td>
            <td style="white-space: nowrap;">${formatDate(item.trained_at)}</td>
            <td style="white-space: nowrap;">
                ${item.active
                    ? '<span class="badge-active">Active</span>'
                    : `<button class="btn btn-sm deploy-btn" data-version="${item.version}">Deploy</button>`}
            </td>
            <td style="white-space: nowrap;">
                ${!item.active && !isLayer1
                    ? `<button class="btn btn-sm btn-danger delete-model-btn" data-version="${item.version}">Delete</button>`
                    : `<button class="btn btn-sm btn-danger" disabled style="opacity:0.35;cursor:not-allowed;">Delete</button>`}
            </td>
        </tr>`;
    }).join('');

    document.querySelectorAll('.deploy-btn').forEach(btn => {
        btn.addEventListener('click', () => deployModel(btn.dataset.version));
    });

    document.querySelectorAll('.delete-model-btn').forEach(btn => {
        btn.addEventListener('click', () => deleteModel(btn.dataset.version));
    });

    updateSelectAllTraining();
    updateTrainingActions();
}

function toggleTrainingSelection(version, checked) {
    if (checked) {
        selectedTrainingVersions.add(version);
    } else {
        selectedTrainingVersions.delete(version);
    }
    updateSelectAllTraining();
    updateTrainingActions();
}

function updateSelectAllTraining() {
    const selectAll = document.getElementById('select-all-training');
    const allCheckboxes = document.querySelectorAll('.training-checkbox');
    const selectableCheckboxes = Array.from(allCheckboxes).filter(cb => {
        const row = cb.closest('tr');
        return row && !row.querySelector('.badge-active');
    });
    const checkedBoxes = selectableCheckboxes.filter(cb => cb.checked);
    selectAll.checked = selectableCheckboxes.length > 0 && checkedBoxes.length === selectableCheckboxes.length;
    selectAll.indeterminate = checkedBoxes.length > 0 && checkedBoxes.length < selectableCheckboxes.length;
}

function updateTrainingActions() {
    const actions = document.getElementById('training-actions');
    const isLayer1 = getCurrentView() === 'layer1';
    if (isLayer1) {
        actions.style.display = 'none';
        return;
    }
    actions.style.display = selectedTrainingVersions.size > 0 ? 'block' : 'none';
}

async function deleteSelectedTraining() {
    const versions = Array.from(selectedTrainingVersions);
    if (versions.length === 0) return;

    showConfirm(
        'Delete Models',
        `Are you sure you want to delete ${versions.length} selected model(s)? This will remove their files from disk.`,
        async () => {
            const errors = [];
            for (const version of versions) {
                try {
                    const res = await apiFetch(`${API_BASE}/training/history/${version}`, {
                        method: 'DELETE'
                    });
                    if (!res.ok) {
                        const err = await res.json().catch(() => ({}));
                        errors.push(`${version}: ${err.detail || 'Failed'}`);
                    }
                } catch (e) {
                    errors.push(`${version}: ${e.message}`);
                }
            }
            selectedTrainingVersions.clear();
            loadTrainingStatus();
            loadTrainingHistory();
            if (errors.length > 0) {
                showModal('Delete Results', errors.join('\n'), 'warning');
            }
        }
    );
}

async function pollTrainingJob() {
    try {
        const statusRes = await fetch(`${API_BASE}/training/status`, {
            headers: authHeaders(),
            credentials: 'same-origin'
        });
        const statusData = await statusRes.json();

        if (!statusData.training_active) {
            clearInterval(trainingPollInterval);
            trainingPollInterval = null;
            const btn = document.getElementById('train-model-btn');
            btn.textContent = 'Training Complete';
            btn.disabled = false;
            setTimeout(() => { btn.textContent = 'Start Training'; }, 2000);
            loadTrainingStatus();
            loadTrainingHistory();
        }
    } catch (e) {
        clearInterval(trainingPollInterval);
        trainingPollInterval = null;
    }
}

function authHeaders() {
    return {};
}

async function trainModel() {
    if (document.getElementById('train-model-btn').disabled) return;

    const dataset = document.getElementById('train-dataset').value;

    const btn = document.getElementById('train-model-btn');
    btn.textContent = 'Starting...';
    btn.disabled = true;

    try {
        const res = await apiFetch(`${API_BASE}/training/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dataset })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            showModal('Training Failed', err.detail || err.error || 'An error occurred', 'error');
            btn.textContent = 'Start Training';
            btn.disabled = false;
            return;
        }

        btn.textContent = 'Training...';

        trainingPollInterval = setInterval(pollTrainingJob, 5000);
        loadTrainingStatus();
    } catch (e) {
        console.error('Training error:', e);
        btn.textContent = 'Start Training';
        btn.disabled = false;
    }
}

function updateEvalMetrics(item) {
    const metrics = document.getElementById('eval-metrics');
    const isMiss = item && (item.model_family === 'miss');
    if (!item) {
        metrics.innerHTML = `
            <div class="metric"><div class="metric-label">Precision</div><div class="metric-value">—</div></div>
            <div class="metric"><div class="metric-label">Recall</div><div class="metric-value">—</div></div>
            <div class="metric"><div class="metric-label">FPR</div><div class="metric-value" style="color:var(--accent);">—</div></div>
            <div class="metric"><div class="metric-label">F1</div><div class="metric-value">—</div></div>
        `;
        return;
    }

    const composite = isMiss && item.composite_score != null ? (item.composite_score * 100).toFixed(2) + '%' : '—';
    const samples = isMiss && item.samples ? item.samples.toLocaleString() : '—';
    const attBen = isMiss && item.attacks != null && item.benign != null
        ? `${item.attacks.toLocaleString()} / ${item.benign.toLocaleString()}`
        : '—';

    const core = `
        <div class="metric">
            <div class="metric-label">Precision</div>
            <div class="metric-value">${formatPct(item.precision)}</div>
        </div>
        <div class="metric">
            <div class="metric-label">Recall</div>
            <div class="metric-value">${formatPct(item.recall)}</div>
        </div>
        <div class="metric">
            <div class="metric-label">FPR</div>
            <div class="metric-value" style="color:var(--accent);">${formatPct(item.fpr)}</div>
        </div>
        <div class="metric">
            <div class="metric-label">F1</div>
            <div class="metric-value">${formatPct(item.f1_score)}</div>
        </div>
    `;

    const extra = isMiss ? `
        <div class="metric">
            <div class="metric-label">AUROC</div>
            <div class="metric-value">${formatPct(item.auroc)}</div>
        </div>
        <div class="metric">
            <div class="metric-label">Composite</div>
            <div class="metric-value">${composite}</div>
        </div>
        <div class="metric">
            <div class="metric-label">Samples</div>
            <div class="metric-value">${samples}</div>
        </div>
        <div class="metric">
            <div class="metric-label">Attack/Benign</div>
            <div class="metric-value">${attBen}</div>
        </div>
    ` : '';

    metrics.innerHTML = core + extra;
}

async function deployModel(version) {
    showConfirm(
        'Switch Model',
        `Are you sure you want to activate model ${version}? This will switch the active model and restart the inference engine.`,
        async () => {
            try {
                const endpoint = version.startsWith('miss_')
                    ? `/training/miss/${version}/activate`
                    : `/training/${version}/activate`;
                const res = await apiFetch(`${API_BASE}${endpoint}`, {
                    method: 'POST'
                });
                if (!res.ok) {
                    const err = await res.json().catch(() => ({}));
                    showModal('Deploy Failed', err.detail || 'Failed to deploy model', 'error');
                    return;
                }
                loadTrainingStatus();
                loadTrainingHistory();
            } catch (e) {
                console.error('Deploy error:', e);
            }
        }
    );
}

async function deleteModel(version) {
    showConfirm(
        'Delete Model',
        `Are you sure you want to delete model ${version}? This will also remove its files from disk.`,
        async () => {
            try {
                const res = await apiFetch(`${API_BASE}/training/history/${version}`, {
                    method: 'DELETE'
                });
                if (!res.ok) {
                    const err = await res.json().catch(() => ({}));
                    showModal('Delete Failed', err.detail || 'Failed to delete model', 'error');
                    return;
                }
                loadTrainingStatus();
                loadTrainingHistory();
            } catch (e) {
                console.error('Delete error:', e);
                showModal('Delete Failed', 'An error occurred while deleting the model', 'error');
            }
        }
    );
}

let missTrainingPollInterval = null;

async function loadMissTrainingStatus() {
    try {
        const res = await apiFetch(`${API_BASE}/training/miss/status`);
        const data = await res.json();
        if (data.training_active) {
            const btn = document.getElementById('miss-train-btn');
            if (btn) {
                btn.textContent = 'Training...';
                btn.disabled = true;
            }
            if (!missTrainingPollInterval) {
                missTrainingPollInterval = setInterval(pollMissTrainingJob, 5000);
            }
        }
    } catch (e) {
        console.error('Error loading miss training status:', e);
    }
}

async function pollMissTrainingJob() {
    try {
        const res = await apiFetch(`${API_BASE}/training/miss/status`);
        const data = await res.json();
        if (!data.training_active) {
            clearInterval(missTrainingPollInterval);
            missTrainingPollInterval = null;
            const btn = document.getElementById('miss-train-btn');
            if (btn) {
                btn.textContent = 'Miss Training Complete';
                btn.disabled = false;
                setTimeout(() => { btn.textContent = 'Start Miss Training'; }, 3000);
            }
            loadTrainingHistory();
        }
    } catch (e) {
        clearInterval(missTrainingPollInterval);
        missTrainingPollInterval = null;
    }
}

async function startMissTraining() {
    const btn = document.getElementById('miss-train-btn');
    if (!btn || btn.disabled) return;

    btn.textContent = 'Starting...';
    btn.disabled = true;

    try {
        const res = await apiFetch(`${API_BASE}/training/miss/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source: 'mongo' })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            showModal('Miss Training Failed', err.detail || err.error || 'An error occurred', 'error');
            btn.textContent = 'Start Miss Training';
            btn.disabled = false;
            return;
        }

        btn.textContent = 'Training...';
        missTrainingPollInterval = setInterval(pollMissTrainingJob, 5000);
    } catch (e) {
        console.error('Miss training error:', e);
        btn.textContent = 'Start Miss Training';
        btn.disabled = false;
    }
}

const trainModelBtn = document.getElementById('train-model-btn');
if (trainModelBtn) {
    trainModelBtn.addEventListener('click', trainModel);
}

const missTrainBtn = document.getElementById('miss-train-btn');
if (missTrainBtn) {
    missTrainBtn.addEventListener('click', startMissTraining);
}

document.getElementById('select-all-training').addEventListener('change', function() {
    const checked = this.checked;
    document.querySelectorAll('.training-checkbox').forEach(cb => {
        const row = cb.closest('tr');
        if (row && row.querySelector('.badge-active')) {
            return;
        }
        cb.checked = checked;
        toggleTrainingSelection(cb.dataset.version, checked);
    });
});

document.getElementById('delete-selected-training-btn').addEventListener('click', deleteSelectedTraining);

function updateTrainingSections() {
    // Both sections always visible — Layer 1 model is final, only Layer 2 (miss) training is active
}

function initViewToggle() {
    document.querySelectorAll('.panel-right-header .view-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.panel-right-header .view-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            updateTrainingSections();
            loadTrainingHistory();
        });
    });
}
initViewToggle();

(async () => {
    await requireAuth();
    updateTrainingSections();
    await loadDatasets();
    await loadTrainingStatus();
    await loadMissTrainingStatus();
    await loadTrainingHistory();
})();
