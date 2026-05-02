const API_BASE = '/api';

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

function handleSelectAllChange() {
    const selectAllCheckbox = document.getElementById('select-all-datasets');
    const checkboxes = document.querySelectorAll('.dataset-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = selectAllCheckbox.checked;
        toggleDatasetSelection(cb.dataset.id, selectAllCheckbox.checked);
    });
}

function deleteSelectedDatasets() {
    const selectedIds = Array.from(selectedDatasets);
    if (selectedIds.length === 0) return;

    showConfirm(
        'Delete Selected Datasets',
        `Are you sure you want to delete ${selectedIds.length} dataset(s)? This action cannot be undone.`,
        async () => {
            try {
                // Delete each selected dataset
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
        renderDatasets(data.items || []);
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

function renderDatasets(items) {
    const tbody = document.getElementById('datasets-list');
    if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--fg-muted);padding:20px;">No datasets yet.</td></tr>';
        return;
    }
    tbody.innerHTML = items.map(d => `
        <tr>
            <td><input type="checkbox" class="dataset-checkbox" data-id="${d._id}" style="margin-right: 8px;">${d.name || '—'}</td>
            <td>${d.type || '—'}</td>
            <td>${d.samples || 0}</td>
            <td>${d.attack_pct || 0}%</td>
            <td>${d.created_at || '—'}</td>
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
}

function renderSources(sources) {
    const container = document.querySelector('.source-list');
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
                <div class="source-actions">
                    <button class="btn btn-sm">View</button>
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

const generateDatasetBtn = document.getElementById('generate-dataset-btn');
if (generateDatasetBtn) {
    generateDatasetBtn.addEventListener('click', generateDataset);
}

(async () => {
    await requireAuth();
    await loadDatasets();
    loadDatasetSources();

    const selectAllCheckbox = document.getElementById('select-all-datasets');
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', handleSelectAllChange);
    }

    const deleteSelectedBtn = document.getElementById('delete-selected-btn');
    if (deleteSelectedBtn) {
        deleteSelectedBtn.addEventListener('click', deleteSelectedDatasets);
    }

    const mergeSelectedBtn = document.getElementById('merge-selected-btn');
    if (mergeSelectedBtn) {
        mergeSelectedBtn.addEventListener('click', mergeSelectedDatasets);
    }
})();