const API_BASE = '/api';
let trainingPollInterval = null;

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

document.getElementById('val-split').addEventListener('input', function() {
    document.getElementById('val-split-val').textContent = this.value + '%';
});

document.getElementById('hp-toggle-check').addEventListener('change', function() {
    document.getElementById('hp-advanced').style.display = this.checked ? 'block' : 'none';
});

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
        renderHistory(data.items || []);
        if (data.items && data.items.length > 0) {
            updateEvalMetrics(data.items[0]);
        }
    } catch (e) {
        console.error('Error loading training history:', e);
    }
}

function renderHistory(items) {
    const tbody = document.getElementById('training-history');
    if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--fg-muted);padding:20px;">No training history yet.</td></tr>';
        return;
    }
    tbody.innerHTML = items.map(item => `
        <tr>
            <td>${item.version}</td>
            <td>${item.model_type}</td>
            <td>${item.dataset}</td>
            <td>${item.precision}%</td>
            <td>${item.recall}%</td>
            <td style="color:var(--accent);">${item.fpr}%</td>
            <td>${new Date(item.trained_at).toLocaleDateString()}</td>
            <td>
                ${item.active
                    ? '<span class="badge-active">Active</span>'
                    : `<button class="btn btn-sm deploy-btn" data-version="${item.version}">Deploy</button>`}
            </td>
            <td>
                ${!item.active
                    ? `<button class="btn btn-sm btn-danger delete-model-btn" data-version="${item.version}">Delete</button>`
                    : ''}
            </td>
        </tr>
    `).join('');

    document.querySelectorAll('.deploy-btn').forEach(btn => {
        btn.addEventListener('click', () => deployModel(btn.dataset.version));
    });

    document.querySelectorAll('.delete-model-btn').forEach(btn => {
        btn.addEventListener('click', () => deleteModel(btn.dataset.version));
    });
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
    const modelType = document.getElementById('model-type').value;
    const valSplit = parseInt(document.getElementById('val-split').value);

    const btn = document.getElementById('train-model-btn');
    btn.textContent = 'Starting...';
    btn.disabled = true;

    try {
        const res = await apiFetch(`${API_BASE}/training/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                dataset,
                model_type: modelType,
                val_split: valSplit
            })
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            showModal('Training Failed', err.detail || err.error || 'An error occurred', 'error');
            btn.textContent = 'Start Training';
            btn.disabled = false;
            return;
        }

        const result = await res.json();
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
    if (!item) {
        metrics.innerHTML = `
            <div class="metric"><div class="metric-label">Precision</div><div class="metric-value">—</div></div>
            <div class="metric"><div class="metric-label">Recall</div><div class="metric-value">—</div></div>
            <div class="metric"><div class="metric-label">FPR</div><div class="metric-value" style="color:var(--accent);">—</div></div>
            <div class="metric"><div class="metric-label">F1</div><div class="metric-value">—</div></div>
        `;
        return;
    }

    metrics.innerHTML = `
        <div class="metric">
            <div class="metric-label">Precision</div>
            <div class="metric-value">${item.precision}%</div>
        </div>
        <div class="metric">
            <div class="metric-label">Recall</div>
            <div class="metric-value">${item.recall}%</div>
        </div>
        <div class="metric">
            <div class="metric-label">FPR</div>
            <div class="metric-value" style="color:var(--accent);">${item.fpr}%</div>
        </div>
        <div class="metric">
            <div class="metric-label">F1</div>
            <div class="metric-value">${item.f1_score}%</div>
        </div>
    `;
}

async function deployModel(version) {
    try {
        const res = await apiFetch(`${API_BASE}/training/${version}/activate`, {
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

const trainModelBtn = document.getElementById('train-model-btn');
if (trainModelBtn) {
    trainModelBtn.addEventListener('click', trainModel);
}

loadDatasets();
loadTrainingStatus();
loadTrainingHistory();