let currentOffset = 0;
const pageLimit = 50;

async function loadAuditLogs() {
    const tbody = document.getElementById('audit-logs-list');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--fg-muted);padding:20px;">Loading...</td></tr>';

    try {
        const params = new URLSearchParams();
        const userFilter = document.getElementById('filter-user')?.value;
        const actionFilter = document.getElementById('filter-action')?.value;
        const resourceFilter = document.getElementById('filter-resource')?.value;
        const startFilter = document.getElementById('filter-start')?.value;
        const endFilter = document.getElementById('filter-end')?.value;

        if (userFilter) params.append('user', userFilter);
        if (actionFilter) params.append('action', actionFilter);
        if (resourceFilter) params.append('resource_type', resourceFilter);
        if (startFilter) params.append('start', startFilter);
        if (endFilter) params.append('end', endFilter);

        params.append('offset', currentOffset);
        params.append('limit', pageLimit);

        const url = `/api/admin/audit-logs?${params.toString()}`;
        const response = await apiFetch(url);
        const data = await response.json();

        if (!data.logs || data.logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--fg-muted);padding:20px;">No audit logs found</td></tr>';
            updatePagination(0, 0, 0);
            return;
        }

        tbody.innerHTML = data.logs.map(log => `
            <tr>
                <td>${new Date(log.timestamp).toLocaleString()}</td>
                <td>${log.user_email || log.user_id || '-'}</td>
                <td>${log.action}</td>
                <td>${log.details ? JSON.stringify(log.details).substring(0, 50) + (JSON.stringify(log.details).length > 50 ? '...' : '') : '-'}</td>
                <td>${log.resource_type || '-'}</td>
                <td>${log.ip_address || '-'}</td>
                <td><span class="tag ${log.outcome === 'success' ? 'success' : 'failure'}">${log.outcome}</span></td>
            </tr>
        `).join('');

        updatePagination(data.total || 0, currentOffset, pageLimit);
    } catch (err) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--fg-muted);padding:20px;">Failed to load audit logs</td></tr>';
    }
}

function updatePagination(total, offset, limit) {
    const pagination = document.getElementById('pagination-controls');
    if (!pagination) return;

    const currentPage = Math.floor(offset / limit) + 1;
    const totalPages = Math.ceil(total / limit);

    if (total <= limit) {
        pagination.innerHTML = '';
        return;
    }

    pagination.innerHTML = `
        <div class="pagination" style="display:flex;align-items:center;justify-content:center;gap:10px;padding:15px;">
            <button class="btn btn-secondary" data-page="${currentPage - 1}" ${currentPage <= 1 ? 'disabled' : ''}>Previous</button>
            <span style="color:#f97316;font-size:0.875rem;">Page ${currentPage} of ${totalPages} (${total})</span>
            <button class="btn btn-secondary" data-page="${currentPage + 1}" ${currentPage >= totalPages ? 'disabled' : ''}>Next</button>
        </div>
    `;
}

function goToPage(page) {
    if (page < 1) return;
    currentOffset = (page - 1) * pageLimit;
    loadAuditLogs();
}

document.addEventListener('click', (e) => {
    const btn = e.target.closest('#pagination-controls .btn-secondary[data-page]');
    if (btn && !btn.disabled) {
        goToPage(parseInt(btn.dataset.page));
    }
});

window.addEventListener('load', () => {
    const applyBtn = document.getElementById('apply-filters');
    if (applyBtn) {
        applyBtn.addEventListener('click', () => {
            currentOffset = 0;
            loadAuditLogs();
        });
    }
});

document.addEventListener('DOMContentLoaded', () => {
    requireAuth();
    loadAuditLogs();

    document.getElementById('export-csv')?.addEventListener('click', () => {
        window.location.href = '/api/admin/audit-logs/export?' + new URLSearchParams({
            action: document.getElementById('filter-action')?.value,
            resource_type: document.getElementById('filter-resource')?.value
        });
    });
});