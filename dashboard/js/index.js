const API_BASE = '/api';
let currentGraphRange = localStorage.getItem('indexGraphRange') || 'day';
let currentView = localStorage.getItem('indexView') || 'waf';
const MAX_VISIBLE_RULES = 5;
let logsCursor = null;
let logsHasMore = true;
let logsLoading = false;
let lastAlertCount = 0;
const priorityFilters = {
    p1: localStorage.getItem('indexPriority_p1') !== 'false',
    p2: localStorage.getItem('indexPriority_p2') !== 'false',
    p3: localStorage.getItem('indexPriority_p3') !== 'false',
};

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
        const total = data.total_alerts || 0;
        document.getElementById('stat-total').textContent = total;
        document.getElementById('stat-ai-count').textContent = data.coraza_count || 0;
        document.getElementById('stat-misses').textContent = data.ml_miss_count || 0;

        const priorityEl = document.getElementById('stat-priority');
        if (data.latest_priority && data.latest_priority !== '-') {
            priorityEl.textContent = data.latest_priority;
            priorityEl.className = 'stat-value priority-' + data.latest_priority.toLowerCase();
        } else {
            priorityEl.textContent = '-';
            priorityEl.className = 'stat-value';
        }
        return total;
    } catch (e) { 
        return 0;
    }
}

async function updateLogs(append = false) {
    if (logsLoading) return;
    logsLoading = true;

    try {
        let url = logsCursor
            ? `${API_BASE}/logs?cursor=${logsCursor}&limit=50`
            : `${API_BASE}/logs?limit=50`;

        if (currentView === 'miss') {
            url += '&source=ml_miss_detector';
        }

        const activePriorities = Object.keys(priorityFilters).filter(p => priorityFilters[p]);
        if (activePriorities.length > 0 && activePriorities.length < 3) {
            url += '&priority=' + activePriorities.map(p => p.toUpperCase()).join(',');
        }

        const res = await apiFetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        if (!data.data) {
            logsLoading = false;
            return;
        }

        const tbody = document.getElementById('logs-body');
        if (!append) {
            tbody.innerHTML = '';
            logsCursor = null;
        }

        data.data.forEach((alert, i) => {
            const row = document.createElement('tr');
            if (alert.alert_key) row.dataset.alertKey = alert.alert_key;
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
                ? `<span class="ai-score">*${(aiScoreVal * 100).toFixed(1)}%</span>`
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

        logsCursor = data.next_cursor || null;
        logsHasMore = !!data.next_cursor;
        
        const loadMoreBtn = document.getElementById('load-more-logs');
        if (loadMoreBtn) {
            loadMoreBtn.style.display = logsHasMore ? 'block' : 'none';
            loadMoreBtn.disabled = false;
            loadMoreBtn.textContent = 'Load More';
        }

        if (streamSearchQuery) applyStreamSearch();
    } catch (e) {
        console.error('Error in updateLogs:', e);
    } finally {
        logsLoading = false;
    }
}

async function loadMoreLogs() {
    if (!logsHasMore || logsLoading) return;

    const loadMoreBtn = document.getElementById('load-more-logs');
    if (loadMoreBtn) {
        loadMoreBtn.disabled = true;
        loadMoreBtn.textContent = 'Loading...';
    }

    await updateLogs(true);
}

let isInitialLoad = true;
let sseClient = null;
let pollingInterval = null;

function startSSE() {
    if (sseClient) sseClient.close();

    const indicator = SSE_createIndicator('connection-indicator');
    sseClient = new SSEClient('/api/events/stream', {
        onAlert: function (alert) {
            if (isInitialLoad) return;
            prependAlertRow(alert);
        },
        onAlertUpdate: function (update) {
            updateAlertRow(update);
        },
        onStats: function (stats) {
            updateStatCards(stats);
            lastAlertCount = stats.total_alerts || 0;
        },
        onConnect: function () {
            if (sseClient && sseClient.fallbackActive) {
                stopPolling();
                sseClient.fallbackActive = false;
            }
        },
        onFallback: function () {
            startPolling();
        }
    });
    if (indicator) sseClient.indicator = indicator;
    sseClient.connect();
}

function stopSSE() {
    if (sseClient) {
        sseClient.close();
        sseClient = null;
    }
}

function startPolling() {
    if (pollingInterval) return;
    pollingInterval = setInterval(async () => {
        const currentTotal = await updateStats();
        if (currentTotal > lastAlertCount) {
            lastAlertCount = currentTotal;
            if (!isInitialLoad) {
                await updateLogsNewOnly();
            }
        }
    }, 2000);
}

function stopPolling() {
    if (pollingInterval) {
        clearInterval(pollingInterval);
        pollingInterval = null;
    }
}

function updateStatCards(stats) {
    document.getElementById('stat-total').textContent = stats.total_alerts || 0;
    document.getElementById('stat-ai-count').textContent = stats.coraza_count || 0;
    document.getElementById('stat-misses').textContent = stats.ml_miss_count || 0;

    const priorityEl = document.getElementById('stat-priority');
    if (stats.latest_priority && stats.latest_priority !== '-') {
        priorityEl.textContent = stats.latest_priority;
        priorityEl.className = 'stat-value priority-' + stats.latest_priority.toLowerCase();
    } else {
        priorityEl.textContent = '-';
        priorityEl.className = 'stat-value';
    }
}

function prependAlertRow(alert) {
    const tbody = document.getElementById('logs-body');
    const firstRow = tbody.querySelector('tr');
    const firstAlertTs = firstRow ? firstRow.querySelector('td')?.textContent : null;

    let ts = alert.timestamp || '-';
    if (ts.includes('-') || ts.includes('Z')) {
        ts = ts;
    } else if (ts.includes('/')) {
        ts = ts.split('/').join('-').replace(' ', 'T') + 'Z';
    }
    const tsFormatted = new Date(ts).toLocaleTimeString();

    if (firstAlertTs && tsFormatted <= firstAlertTs) return;

    const source = alert.source || 'coraza';
    const isMiss = source === 'ml_miss_detector';
    const rules = formatRules(alert.triggered_rules);
    const aiScoreVal = alert.ai_score;
    const aiScore = aiScoreVal !== null && aiScoreVal !== undefined
        ? '<span class="ai-score">' + (aiScoreVal * 100).toFixed(1) + '%</span>' : '-';
    const aiPriority = alert.ai_priority
        ? '<span class="priority-' + alert.ai_priority.toLowerCase() + '">' + alert.ai_priority + '</span>' : '-';
    const aiConf = alert.ai_confidence !== null && alert.ai_confidence !== undefined
        ? alert.ai_confidence.toFixed(0) + '%' : '-';
    const scoreDisplay = isMiss && aiScoreVal !== null && aiScoreVal !== undefined
        ? '<span class="ai-score">*' + (aiScoreVal * 100).toFixed(1) + '%</span>'
        : '<span class="anomaly-badge">' + alert.anomaly_score + '</span>';

    const row = document.createElement('tr');
    if (alert.alert_key) row.dataset.alertKey = alert.alert_key;
    row.innerHTML = '<td style="color:var(--fg-muted);">' + tsFormatted + '</td>' +
        '<td>' + alert.client_ip + '</td>' +
        '<td style="font-family:monospace;font-size:0.75rem;">' + alert.uri + '</td>' +
        '<td style="text-align: center;">' + scoreDisplay + '</td>' +
        '<td style="text-align: center;">' + rules + '</td>' +
        '<td style="text-align: center;">' + aiScore + '</td>' +
        '<td style="text-align: center;">' + aiConf + '</td>' +
        '<td style="text-align: center;">' + aiPriority + '</td>';
    tbody.insertBefore(row, firstRow);

    applyStreamSearch();
}

function updateAlertRow(update) {
    if (!update.alert_key) return;
    var row = document.querySelector('#logs-body tr[data-alert-key="' + update.alert_key.replace(/"/g, '') + '"]');
    if (!row) return;
    var cells = row.querySelectorAll('td');
    if (cells.length < 8) return;

    var scoreVal = update.ai_score;
    var confVal = update.ai_confidence;
    var prioVal = update.ai_priority;

    cells[5].innerHTML = scoreVal !== null && scoreVal !== undefined
        ? '<span class="ai-score">' + (scoreVal * 100).toFixed(1) + '%</span>' : '-';

    cells[6].textContent = confVal !== null && confVal !== undefined
        ? confVal.toFixed(0) + '%' : '-';

    cells[7].innerHTML = prioVal
        ? '<span class="priority-' + prioVal.toLowerCase() + '">' + prioVal + '</span>' : '-';
}

updateStats().then(total => { lastAlertCount = total; });
updateLogs().then(() => { isInitialLoad = false; startSSE(); });

async function updateLogsNewOnly() {
    try {
        const url = `${API_BASE}/logs?limit=10`;
        if (currentView === 'miss') {
            url += '&source=ml_miss_detector';
        }
        const activePriorities = Object.keys(priorityFilters).filter(p => priorityFilters[p]);
        if (activePriorities.length > 0 && activePriorities.length < 3) {
            url += '&priority=' + activePriorities.map(p => p.toUpperCase()).join(',');
        }

        const res = await apiFetch(url);
        if (!res.ok) return;
        const data = await res.json();
        if (!data.data || data.data.length === 0) return;

        const tbody = document.getElementById('logs-body');
        const firstRow = tbody.querySelector('tr');
        const firstAlertTs = firstRow ? firstRow.querySelector('td')?.textContent : null;

        data.data.reverse().forEach((alert, i) => {
            const ts = alert.timestamp || '-';
            if (ts.includes('/')) {
                ts = ts.split('/').join('-').replace(' ', 'T') + 'Z';
            }
            const tsFormatted = new Date(ts).toLocaleTimeString();

            if (firstAlertTs && tsFormatted <= firstAlertTs) return;

            const source = alert.source || 'coraza';
            const isMiss = source === 'ml_miss_detector';
            const rules = formatRules(alert.triggered_rules);
            const aiScoreVal = alert.ai_score;
            const aiScore = aiScoreVal !== null && aiScoreVal !== undefined
                ? `<span class="ai-score">${(aiScoreVal * 100).toFixed(1)}%</span>` : '-';
            const aiPriority = alert.ai_priority
                ? `<span class="priority-${alert.ai_priority.toLowerCase()}">${alert.ai_priority}</span>` : '-';
            const aiConf = alert.ai_confidence !== null && alert.ai_confidence !== undefined
                ? `${alert.ai_confidence.toFixed(0)}%` : '-';
            const scoreDisplay = isMiss && aiScoreVal !== null && aiScoreVal !== undefined
                ? `<span class="ai-score">*${(aiScoreVal * 100).toFixed(1)}%</span>`
                : `<span class="anomaly-badge">${alert.anomaly_score}</span>`;

            const row = document.createElement('tr');
            if (alert.alert_key) row.dataset.alertKey = alert.alert_key;
            row.innerHTML = `
                <td style="color:var(--fg-muted);">${tsFormatted}</td>
                <td>${alert.client_ip}</td>
                <td style="font-family:monospace;font-size:0.75rem;">${alert.uri}</td>
                <td style="text-align: center;">${scoreDisplay}</td>
                <td style="text-align: center;">${rules}</td>
                <td style="text-align: center;">${aiScore}</td>
                <td style="text-align: center;">${aiConf}</td>
                <td style="text-align: center;">${aiPriority}</td>
            `;
            tbody.insertBefore(row, firstRow);
        });

        applyStreamSearch();
    } catch (e) {
        console.error('Error in updateLogsNewOnly:', e);
    }
}

async function clearLogs() {
    try {
        const res = await apiFetch(`${API_BASE}/logs`, { method: 'DELETE' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        logsCursor = null;
        logsHasMore = true;
        lastAlertCount = 0;
        await updateStats();
        await updateLogs();
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
        const priorityCell = row.querySelector('td:last-child');
        const priorityMatch = priorityCell ? priorityCell.textContent.match(/P[123]/i) : null;
        const p = priorityMatch ? priorityMatch[0].toLowerCase() : null;
        const priorityVisible = p ? priorityFilters[p] : true;
        const searchVisible = streamSearchQuery === '' || text.includes(streamSearchQuery);
        row.style.display = searchVisible && priorityVisible ? '' : 'none';
    });
}

const syncBtn = document.getElementById('sync-btn');
if (syncBtn) {
    syncBtn.addEventListener('click', () => {
        window.location.href = '/review';
    });
}

const lockBtn = document.getElementById('lock-btn');
if (lockBtn) {
    lockBtn.addEventListener('click', () => {
        window.logout();
    });
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

const loadMoreLogsBtn = document.getElementById('load-more-logs');
if (loadMoreLogsBtn) {
    loadMoreLogsBtn.addEventListener('click', loadMoreLogs);
}

const streamSearchInput = document.getElementById('stream-search');
const searchWrap = document.querySelector('.search-wrap');
if (searchWrap && streamSearchInput) {
    searchWrap.addEventListener('click', (e) => {
        if (!searchWrap.classList.contains('expanded')) {
            searchWrap.classList.add('expanded');
            streamSearchInput.focus();
        }
    });
    streamSearchInput.addEventListener('blur', () => {
        if (streamSearchInput.value.trim() === '') {
            searchWrap.classList.remove('expanded');
            streamSearchQuery = '';
            applyStreamSearch();
        }
    });
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
    localStorage.setItem('indexGraphRange', range);
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

(function restoreIndexFilters() {
    document.querySelectorAll('.graph-btn').forEach(function (btn) {
        btn.classList.toggle('active', btn.dataset.range === currentGraphRange);
    });
    document.querySelectorAll('.view-btn').forEach(function (btn) {
        btn.classList.toggle('active', btn.dataset.view === currentView);
    });
    document.querySelectorAll('.priority-btn').forEach(function (btn) {
        btn.classList.toggle('active', priorityFilters[btn.dataset.priority]);
    });
})();

updateGraph(currentGraphRange);

document.querySelectorAll('.view-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentView = btn.dataset.view;
        localStorage.setItem('indexView', currentView);
        logsCursor = null;
        updateLogs();
    });
});

document.querySelectorAll('.priority-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        btn.classList.toggle('active');
        priorityFilters[btn.dataset.priority] = btn.classList.contains('active');
        localStorage.setItem('indexPriority_' + btn.dataset.priority, btn.classList.contains('active'));
        logsCursor = null;
        updateLogs();
    });
});

function applyPriorityFilter() {
    const rows = document.querySelectorAll('#logs-body tr');
    rows.forEach(row => {
        const priorityCell = row.querySelector('td:last-child');
        if (!priorityCell) return;
        const priorityMatch = priorityCell.textContent.match(/P[123]/i);
        if (!priorityMatch) return;
        const p = priorityMatch[0].toLowerCase();
        row.style.display = priorityFilters[p] ? '' : 'none';
    });
}

