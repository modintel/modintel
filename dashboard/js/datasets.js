const API_BASE = '/api';

async function loadDatasets() {
    try {
        const res = await apiFetch(`${API_BASE}/datasets`);
        const data = await res.json();
        renderDatasets(data.items || []);
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
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--fg-muted);padding:20px;">No datasets yet.</td></tr>';
        return;
    }
    tbody.innerHTML = items.map(d => `
        <tr>
            <td>${d.name || '—'}</td>
            <td>${d.type || '—'}</td>
            <td>${d.samples || 0}</td>
            <td>${d.attack_pct || 0}%</td>
            <td>${d.created_at || '—'}</td>
        </tr>
    `).join('');
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
            alert(err.error || 'Failed to generate dataset');
            btn.textContent = 'Generate';
            btn.disabled = false;
            return;
        }

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

const generateDatasetBtn = document.getElementById('generate-dataset-btn');
if (generateDatasetBtn) {
    generateDatasetBtn.addEventListener('click', generateDataset);
}

loadDatasets();
loadDatasetSources();