const API_BASE = '/api';
let currentStatus = localStorage.getItem('reviewFilter_status') || 'generated';
let currentPriority = localStorage.getItem('reviewFilter_priority') || '';
let currentSource = localStorage.getItem('reviewFilter_source') || '';
let nextCursor = '';
let hasMore = false;
let isLoading = false;
const alertBodies = {};

function getAlertId(alert) {
    if (!alert) return '';
    if (typeof alert._id === 'string') return alert._id;
    if (alert._id && alert._id.$oid) return alert._id.$oid;
    if (alert.id && typeof alert.id === 'string') return alert.id;
    if (alert.id && alert.id.$oid) return alert.id.$oid;
    return String(alert._id || alert.id || '');
}

function formatTimestamp(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    return d.toLocaleString([], { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function formatBodyHtml(body) {
    if (!body) return '';
    try {
        var parsed = JSON.parse(body);
        return '<pre class="body-json">' + escapeHtml(JSON.stringify(parsed, null, 2)) + '</pre>';
    } catch (e) {
        return '<pre class="body-text">' + escapeHtml(body) + '</pre>';
    }
}

async function loadReviewStats() {
    try {
        const [generated, reviewed, tp, fp] = await Promise.all([
            apiFetch(`${API_BASE}/alerts/review?status=generated&limit=1`),
            apiFetch(`${API_BASE}/alerts/review?status=reviewed&limit=1`),
            apiFetch(`${API_BASE}/alerts/review?status=reviewed&limit=1&human_label=true_positive`),
            apiFetch(`${API_BASE}/alerts/review?status=reviewed&limit=1&human_label=false_positive`),
        ]);
        document.getElementById('stat-reviewed').textContent = (await reviewed.json()).total || 0;
        document.getElementById('stat-pending').textContent = (await generated.json()).total || 0;
        document.getElementById('stat-tp').textContent = (await tp.json()).total || 0;
        document.getElementById('stat-fp').textContent = (await fp.json()).total || 0;
    } catch (e) {
        console.error('Error loading review stats:', e);
    }
}

async function loadReviewAlerts(reset) {
    if (isLoading) return;
    isLoading = true;

    if (reset) {
        nextCursor = '';
        document.getElementById('review-body').innerHTML = '';
    }

    const params = new URLSearchParams();
    params.set('status', currentStatus);
    params.set('limit', '50');
    if (currentPriority) params.set('priority', currentPriority);
    if (currentSource) params.set('source', currentSource);
    if (nextCursor) params.set('cursor', nextCursor);

    try {
        const res = await apiFetch(`${API_BASE}/alerts/review?${params.toString()}`);
        const data = await res.json();

        nextCursor = data.next_cursor || '';
        hasMore = data.has_more || false;

        const loadMoreBtn = document.getElementById('load-more-review');
        loadMoreBtn.style.display = hasMore ? 'inline-block' : 'none';

        renderAlerts(data.items || []);
    } catch (e) {
        console.error('Error loading review alerts:', e);
    } finally {
        isLoading = false;
    }
}

function renderAlerts(items) {
    const tbody = document.getElementById('review-body');
    if (!items.length && tbody.children.length === 0) {
        tbody.innerHTML = '<tr><td colspan="10" style="color: var(--fg-muted); text-align: center; padding: 32px;">No alerts to review.</td></tr>';
        return;
    }

    items.forEach(alert => {
        const id = getAlertId(alert);
        const tr = document.createElement('tr');
        tr.id = `review-row-${id}`;
        if (alert.status === 'reviewed') {
            tr.classList.add(alert.human_label === 'true_positive' ? 'review-row-tp' : 'review-row-fp');
        }

        const aiScore = alert.ai_score != null ? (alert.ai_score * 100).toFixed(1) + '%' : '—';
        const label = alert.human_label === 'true_positive' ? 'TP' :
                     alert.human_label === 'false_positive' ? 'FP' : '—';

        if (alert.body) alertBodies[id] = alert.body;

        tr.innerHTML = `
            <td style="font-size: 0.6875rem;">${formatTimestamp(alert.timestamp)}</td>
            <td>${escapeHtml(alert.method || '—')}</td>
            <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(alert.uri || '')}">${escapeHtml(alert.uri || '—')}</td>
            <td class="body-cell">
                ${alert.body ? `<button class="btn btn-sm btn-body" data-id="${id}" title="Toggle request body">View</button>` : '—'}
            </td>
            <td>${aiScore}</td>
            <td>${escapeHtml(alert.ai_priority || '—')}</td>
            <td>${alert.source === 'ml_miss_detector' ? 'L2' : 'L1'}</td>
            <td>${alert.status === 'generated' ? 'Pending' : alert.status === 'reviewed' ? 'Reviewed' : alert.status || '—'}</td>
            <td>${label}</td>
            <td class="action-cell">
                ${alert.status === 'generated'
                    ? `<button class="btn btn-true btn-sm btn-tp" data-id="${id}" title="True Positive">
                         <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M14 9V5a3 3 0 00-3-3l-4 9v11h11.28a2 2 0 002-1.7l1.38-9a2 2 0 00-2-2.3zM7 22H4a2 2 0 01-2-2v-7a2 2 0 012-2h3"/></svg>
                       </button>
                       <button class="btn btn-false btn-sm btn-fp" data-id="${id}" title="False Positive">
                         <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M10 15v4a3 3 0 003 3l4-9V2H5.72a2 2 0 00-2 1.7l-1.38 9a2 2 0 002 2.3zm7-13h2.67A2.31 2.31 0 0122 4v7a2.31 2.31 0 01-2.33 2H17"/></svg>
                       </button>`
                    : `<span style="font-size: 0.7rem; color: var(--fg-muted);">${label}</span>
                       <button class="btn btn-undo btn-sm" data-id="${id}" title="Undo Review">
                         <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/></svg>
                       </button>`}
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function submitReview(id, humanLabel) {
    try {
        const res = await apiFetch(`${API_BASE}/alerts/${id}/review`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ human_label: humanLabel }),
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            showModal('Error', err.error || 'Failed to submit review', 'error');
            return;
        }

        loadReviewStats();
        delete alertBodies[id];

        if (humanLabel === '') {
            var expandRow = document.getElementById('body-expand-' + id);
            if (expandRow) expandRow.remove();
            const row = document.getElementById(`review-row-${id}`);
            if (row) {
                row.remove();
                if (currentStatus === 'reviewed') return;
                if (document.getElementById('review-body').children.length < 10 && hasMore) {
                    loadReviewAlerts(false);
                }
            }
            return;
        }

        var expandRow = document.getElementById('body-expand-' + id);
        if (expandRow) expandRow.remove();

        const row = document.getElementById(`review-row-${id}`);
        if (row) {
            row.classList.add('reviewed');
            setTimeout(() => {
                row.remove();
                if (document.getElementById('review-body').children.length < 10 && hasMore) {
                    loadReviewAlerts(false);
                }
            }, 1000);
        }
    } catch (e) {
        console.error('Error submitting review:', e);
    }
}

function toggleBodyRow(id) {
    var row = document.getElementById('review-row-' + id);
    if (!row) return;
    var expandId = 'body-expand-' + id;
    var existing = document.getElementById(expandId);
    if (existing) {
        existing.remove();
        var btn = row.querySelector('.btn-body');
        if (btn) btn.textContent = 'View';
        return;
    }
    var body = alertBodies[id];
    if (!body) return;
    var expandRow = document.createElement('tr');
    expandRow.id = expandId;
    expandRow.className = 'body-expand-row';
    expandRow.innerHTML = '<td colspan="10"><div class="body-expand-content">' + formatBodyHtml(body) + '</div></td>';
    row.insertAdjacentElement('afterend', expandRow);
    var btn = row.querySelector('.btn-body');
    if (btn) btn.textContent = 'Hide';
}

document.getElementById('load-more-review').addEventListener('click', () => loadReviewAlerts(false));

document.getElementById('review-body').addEventListener('click', (e) => {
    const btn = e.target.closest('.btn-tp, .btn-fp, .btn-undo, .btn-body');
    if (!btn) return;
    const id = btn.dataset.id;
    if (btn.classList.contains('btn-body')) {
        toggleBodyRow(id);
        return;
    }
    if (btn.classList.contains('btn-undo')) {
        showConfirm('Undo Review', 'Remove the review label and return this alert to the pending queue?', () => submitReview(id, ''));
        return;
    }
    const label = btn.classList.contains('btn-tp') ? 'true_positive' : 'false_positive';
    submitReview(id, label);
});

document.querySelectorAll('.filter-row button').forEach(btn => {
    btn.addEventListener('click', () => {
        const filterGroup = btn.dataset.filter;
        document.querySelectorAll(`.filter-row button[data-filter="${filterGroup}"]`).forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        if (filterGroup === 'status') { currentStatus = btn.dataset.value; localStorage.setItem('reviewFilter_status', btn.dataset.value); }
        if (filterGroup === 'priority') { currentPriority = btn.dataset.value; localStorage.setItem('reviewFilter_priority', btn.dataset.value); }
        if (filterGroup === 'source') { currentSource = btn.dataset.value; localStorage.setItem('reviewFilter_source', btn.dataset.value); }

        loadReviewAlerts(true);
    });
});

loadReviewStats();
loadReviewAlerts(true);

(function restoreFilters() {
    var filters = {
        status: currentStatus,
        priority: currentPriority,
        source: currentSource,
    };
    Object.keys(filters).forEach(function (group) {
        var val = filters[group];
        if (val === undefined) return;
        document.querySelectorAll('.filter-row button[data-filter="' + group + '"]').forEach(function (btn) {
            btn.classList.toggle('active', btn.dataset.value === val);
        });
    });
})();

const cutBtn = document.getElementById('cut-dataset-btn');
const cutModal = document.getElementById('cut-modal');
if (cutBtn && cutModal) {
    cutBtn.addEventListener('click', () => {
        cutModal.classList.add('open');
    });

    document.getElementById('cut-modal-cancel').addEventListener('click', () => {
        cutModal.classList.remove('open');
    });
    cutModal.querySelector('.modal-backdrop').addEventListener('click', () => {
        cutModal.classList.remove('open');
    });

    document.getElementById('cut-modal-confirm').addEventListener('click', async () => {
            const name = document.getElementById('cut-dataset-name').value.trim() || 'reviewed_export';
            cutModal.classList.remove('open');

            try {
                const res = await apiFetch(`${API_BASE}/training/datasets/cut`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name }),
                });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                showModal('Export Failed', err.detail || 'Failed to export dataset', 'error');
                return;
            }
            const data = await res.json();
            showModal('Dataset Created', `${data.samples} alerts exported (${data.true_positives} TP, ${data.false_positives} FP)`, 'info');
            loadReviewStats();
        } catch (e) {
            showModal('Error', 'Failed to export dataset', 'error');
        }
    });
}

const lockBtn = document.getElementById('lock-btn');
if (lockBtn) {
    lockBtn.addEventListener('click', () => {
        window.logout();
    });
}

const syncBtn = document.getElementById('sync-btn');
if (syncBtn) {
    syncBtn.addEventListener('click', () => {
        window.location.href = '/events';
    });
}