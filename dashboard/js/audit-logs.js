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

        const detailsFallback = {
            auth_login: '{"user":"logged in"}',
            auth_logout: '{"user":"logged out"}',
            auth_refresh: '{"user":"token refreshed"}',
            profile_update: '{"user":"updated profile"}',
            session_revoke: '{"session":"revoked"}',
            session_revoke_all: '{"sessions":"all revoked"}',
            user_create: '{"user":"created"}',
            user_invite: '{"user":"invited"}',
            user_update: '{"user":"updated"}',
            user_deactivate: '{"user":"deactivated"}',
            alert_review: '{"alert":"reviewed"}',
            alert_review_undo: '{"alert":"review undone"}',
            rule_enable: '{"rule":"enabled"}',
            rule_disable: '{"rule":"disabled"}',
            rule_toggle: '{"rule":"toggled"}',
            waf_paranoia_update: '{"waf":"paranoia updated"}',
            waf_restart: '{"waf":"restarted"}',
            logs_clear: '{"logs":"cleared"}',
            dataset_generate: '{"dataset":"generated"}',
            dataset_merge: '{"dataset":"merged"}',
            dataset_delete: '{"dataset":"deleted"}',
            dataset_cut: '{"dataset":"cut"}',
            dataset_export: '{"dataset":"exported"}',
            training_start: '{"training":"started"}',
            training_activate: '{"training":"activated"}',
            training_delete_version: '{"training":"version deleted"}',
            model_activate: '{"model":"activated"}',
            storage_clear: '{"storage":"cleared"}',
        };
        const resourceFallback = {
            auth_login: 'access',
            auth_logout: 'access',
            auth_refresh: 'access',
            profile_update: 'user',
            session_revoke: 'session',
            session_revoke_all: 'session',
            user_create: 'user',
            user_invite: 'user',
            user_update: 'user',
            user_deactivate: 'user',
            alert_review: 'alert',
            alert_review_undo: 'alert',
            rule_enable: 'rule',
            rule_disable: 'rule',
            rule_toggle: 'rule',
            waf_paranoia_update: 'system',
            waf_restart: 'system',
            logs_clear: 'system',
            dataset_generate: 'dataset',
            dataset_merge: 'dataset',
            dataset_delete: 'dataset',
            dataset_cut: 'dataset',
            dataset_export: 'dataset',
            training_start: 'training',
            training_activate: 'training',
            training_delete_version: 'training',
            model_activate: 'model',
            storage_clear: 'system',
        };

        tbody.innerHTML = data.logs.map(log => {
            const details = log.details ? JSON.stringify(log.details).substring(0, 50) + (JSON.stringify(log.details).length > 50 ? '...' : '') : (detailsFallback[log.action] || '-');
            const resource = log.resource_type || resourceFallback[log.action] || '-';
            return `<tr>
                <td>${new Date(log.timestamp).toLocaleString()}</td>
                <td>${log.user_email || log.user_id || '-'}</td>
                <td>${log.action}</td>
                <td>${details}</td>
                <td>${resource}</td>
                <td>${log.ip_address || '-'}</td>
                <td><span class="tag ${log.outcome === 'success' ? 'success' : 'failure'}">${log.outcome}</span></td>
            </tr>`;
        }).join('');

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