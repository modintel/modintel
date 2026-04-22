const API_BASE = '/api';
let currentGraphRange = 'day';
let currentView = 'waf';
const MAX_VISIBLE_RULES = 5;

function formatRules(rules) {
    if (!rules || rules.length === 0) return '-';

    const visibleRules = rules.slice(0, MAX_VISIBLE_RULES);
    const hiddenCount = rules.length - MAX_VISIBLE_RULES;

    let html = visibleRules.map(r => `<a href="/rules?rule=${r}" class="rule-code">${r}</a>`).join(' ');

    if (hiddenCount > 0) {
        html += ` <span class="rules-more" data-hidden="${rules.slice(MAX_VISIBLE_RULES).join(',')}">+${hiddenCount} more</span>`;
    }

    return html;
}

function expandRules(element) {
    const hiddenRules = element.dataset.hidden.split(',');
    const links = hiddenRules.map(r => `<a href="/rules?rule=${r}" class="rule-code">${r}</a>`).join(' ');
    const parent = element.parentElement;
    parent.innerHTML = parent.innerHTML.replace(element.outerHTML, links);
}

document.addEventListener('click', (e) => {
    if (e.target.classList.contains('rules-more')) {
        expandRules(e.target);
    }
});

async function updateStats() {
    try {
        const res = await apiFetch(`${API_BASE}/stats`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        document.getElementById('stat-total').textContent = data.total_alerts || 0;
        document.getElementById('stat-ai-count').textContent = data.ai_enriched_count || 0;
        document.getElementById('stat-misses').textContent = data.ml_miss_count || 0;

        const priorityEl = document.getElementById('stat-priority');
        if (data.latest_priority && data.latest_priority !== '-') {
            priorityEl.textContent = data.latest_priority;
            priorityEl.className = 'stat-value priority-' + data.latest_priority.toLowerCase();
        } else {
            priorityEl.textContent = '-';
            priorityEl.className = 'stat-value';
        }
    } catch (e) { }
}

async function updateLogs() {
    try {
        const sourceParam = currentView === 'miss' ? 'source=ml_miss_detector' : '';
        const res = await apiFetch(`${API_BASE}/logs${sourceParam ? '?' + sourceParam : ''}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (!data.alerts) {
            return;
        }
        const tbody = document.getElementById('logs-body');
        tbody.innerHTML = '';
        const maxRows = 500;
        data.alerts.slice(0, maxRows).forEach((alert, i) => {
            const row = document.createElement('tr');
            let ts = alert.timestamp || '-';
            if (ts.includes('/')) {
                ts = ts.split('/').join('-').replace(' ', 'T') + 'Z';
            }
            const source = alert.source || 'coraza';
            const isMiss = source === 'ml_miss_detector';
            const rules = formatRules(alert.triggered_rules);

            const aiScoreVal = alert.ai_score;
            const aiScore = aiScoreVal !== null && aiScoreVal !== undefined
                ? `<span class="ai-score">${(aiScoreVal * 100).toFixed(1)}%</span>`
                : '-';
            const aiPriority = alert.ai_priority
                ? `<span class="priority-${alert.ai_priority.toLowerCase()}">${alert.ai_priority}</span>`
                : '-';
            const aiConf = alert.ai_confidence !== null && alert.ai_confidence !== undefined
                ? `${alert.ai_confidence.toFixed(0)}%`
                : '-';

            const scoreDisplay = isMiss && aiScoreVal !== null && aiScoreVal !== undefined
                ? `<span class="miss-score">${(aiScoreVal * 100).toFixed(1)}%</span>`
                : `<span class="anomaly-badge">${alert.anomaly_score}</span>`;

            row.innerHTML = `
                <td style="color:var(--fg-muted);">${new Date(ts).toLocaleTimeString()}</td>
                <td>${alert.client_ip}</td>
                <td style="font-family:monospace;font-size:0.75rem;">${alert.uri}</td>
                <td style="text-align: center;">${scoreDisplay}</td>
                <td style="text-align: center;">${rules}</td>
                <td style="text-align: center;">${aiScore}</td>
                <td style="text-align: center;">${aiConf}</td>
                <td style="text-align: center;">${aiPriority}</td>
            `;
            tbody.appendChild(row);
        });
        if (streamSearchQuery) applyStreamSearch();
    } catch (e) {
        console.error('Error in updateLogs:', e);
    }
}
setInterval(() => { updateStats(); updateLogs(); }, 2000);
updateStats();
updateLogs();

async function clearLogs() {
    try {
        const res = await apiFetch(`${API_BASE}/logs`, { method: 'DELETE' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        updateStats();
        updateLogs();
    } catch (e) {
        console.error('Error clearing logs:', e);
    }
}

function showClearModal() {
    document.getElementById('clear-modal').classList.add('open');
}

function hideClearModal() {
    document.getElementById('clear-modal').classList.remove('open');
}

function confirmClearLogs() {
    hideClearModal();
    clearLogs();
}

let streamSearchQuery = '';

function handleStreamSearch(query) {
    streamSearchQuery = query.toLowerCase().trim();
    applyStreamSearch();
}

function applyStreamSearch() {
    const rows = document.querySelectorAll('#logs-body tr');
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(streamSearchQuery) ? '' : 'none';
    });
}

function handleSync() {
    const btn = document.getElementById('sync-btn');
    const icon = document.getElementById('sync-icon');
    btn.classList.add('syncing');
    updateStats();
    updateLogs();
    updateGraph(currentGraphRange);
    setTimeout(() => {
        btn.classList.remove('syncing');
    }, 1000);
}

const syncBtn = document.getElementById('sync-btn');
if (syncBtn) {
    syncBtn.addEventListener('click', handleSync);
}

const refreshBtn = document.getElementById('refresh-btn');
if (refreshBtn) {
    refreshBtn.addEventListener('click', () => window.location.reload());
}

const clearLogsBtn = document.getElementById('clear-logs-btn');
if (clearLogsBtn) {
    clearLogsBtn.addEventListener('click', showClearModal);
}

const clearCancelBtn = document.getElementById('clear-modal-cancel');
if (clearCancelBtn) {
    clearCancelBtn.addEventListener('click', hideClearModal);
}

const clearConfirmBtn = document.getElementById('clear-modal-confirm');
if (clearConfirmBtn) {
    clearConfirmBtn.addEventListener('click', confirmClearLogs);
}

const streamSearchInput = document.getElementById('stream-search');
if (streamSearchInput) {
    streamSearchInput.addEventListener('input', (e) => handleStreamSearch(e.target.value));
}

function generateGraphPoints(data) {
    const max = Math.max(...data, 1);
    const width = 300;
    const height = 100;
    const padding = 5;
    const step = (width - padding * 2) / (data.length - 1);

    const points = data.map((val, i) => {
        const x = padding + i * step;
        const y = height - padding - (val / max) * (height - padding * 2);
        return `${x},${y}`;
    }).join(' ');

    const areaPoints = `${padding},${height - padding} ` + points + ` ${width - padding},${height - padding} Z`;

    return { points, areaPoints };
}

function updateGraphVisual(range, data) {
    const { points, areaPoints } = generateGraphPoints(data);

    document.getElementById('chart-line').setAttribute('points', points);
    document.getElementById('chart-area').setAttribute('d', 'M' + areaPoints);

    document.querySelectorAll('.graph-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.range === range);
    });
}

function renderGraphLabels(range, labels) {
    const labelsEl = document.getElementById('graph-labels');
    if (!labelsEl) return;

    labelsEl.innerHTML = '';
    if (!Array.isArray(labels) || labels.length === 0) {
        labelsEl.innerHTML = '<span>-</span><span>-</span><span>-</span>';
        return;
    }

    let indices;
    if (range === 'day') {
        indices = [0, 24, 48, 72, labels.length - 1];
    } else if (range === 'week') {
        indices = [0, 21, 42, 63, labels.length - 1];
    } else {
        indices = [0, 30, 60, 90, labels.length - 1];
    }

    const unique = [...new Set(indices.filter(i => i >= 0 && i < labels.length))];
    unique.forEach(i => {
        const span = document.createElement('span');
        span.textContent = labels[i];
        labelsEl.appendChild(span);
    });
}

async function updateGraph(range) {
    currentGraphRange = range;
    try {
        const res = await apiFetch(`${API_BASE}/trend?range=${range}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const values = Array.isArray(data.values) && data.values.length > 0 ? data.values : new Array(96).fill(0);
        updateGraphVisual(range, values);
        renderGraphLabels(range, data.labels);
    } catch (e) {
        console.error('Error fetching trend data:', e);
        updateGraphVisual(range, new Array(96).fill(0));
        renderGraphLabels(range, []);
    }
}

document.querySelectorAll('.graph-btn').forEach(btn => {
    btn.addEventListener('click', () => updateGraph(btn.dataset.range));
});

updateGraph('day');

document.querySelectorAll('.view-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentView = btn.dataset.view;
        updateLogs();
    });
});

