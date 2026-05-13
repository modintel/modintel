(function () {
    'use strict';

    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    const PENDING_RESTART_KEY = 'rules_pending_restart';
    let hasPendingRestart = localStorage.getItem(PENDING_RESTART_KEY) === '1';
    let currentPage = 1;
    let totalPages = 1;
    const pageSize = 50;
    let currentType = 'crs';
    let currentCategory = '';
    let currentSearch = '';
    let currentParanoiaLevel = '';
    let editingRuleId = null;
    let currentMode = 'write';

    function applyRuleDeepLink() {
        const params = new URLSearchParams(window.location.search);
        const ruleId = params.get('rule');
        if (!ruleId) {
            return;
        }
        const row = document.getElementById('rule-' + ruleId);
        if (!row) {
            return;
        }
        toggleRuleDetails(row);
        row.scrollIntoView({ behavior: 'smooth', block: 'center' });
        row.classList.add('highlight-row');
        setTimeout(() => row.classList.remove('highlight-row'), 4000);
    }

    function createDetailsRow(rule) {
        const detailsRow = document.createElement('tr');
        detailsRow.className = 'rule-details-row';
        detailsRow.id = `rule-${rule.id}-details`;
        
        let detailsHTML = '<td colspan="4" class="rule-details-cell"><div class="rule-details">';
        
        if (rule.type === 'crs') {
            detailsHTML += `
                <div class="rule-detail-item"><b>Type</b><span>OWASP CRS Rule</span></div>
                <div class="rule-detail-item"><b>Severity</b><span>${escapeHtml(rule.severity) || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Phase</b><span>${escapeHtml(rule.phase) || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Paranoia Level</b><span>${escapeHtml(rule.paranoia_level) || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Source</b><span>${escapeHtml(rule.source) || 'owasp-crs'}</span></div>
                <div class="rule-detail-item"><b>Note</b><span class="text-muted">CRS rules are read-only. Only enable/disable is allowed.</span></div>
            `;
        } else {
            const source = rule.source || 'modintel-custom';
            detailsHTML += `
                <div class="rule-detail-item"><b>Type</b><span>Custom Rule</span></div>
                <div class="rule-detail-item"><b>Severity</b><span>${escapeHtml(rule.severity) || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Phase</b><span>${escapeHtml(rule.phase) || 'N/A'}</span></div>
                <div class="rule-detail-item" style="display:flex;align-items:flex-start;gap:0.5rem;">
                    <div><b>Source</b><span>${escapeHtml(source)}</span></div>
                    <button class="btn-delete-rule" data-rule-id="${escapeHtml(rule.id)}" style="margin-left:auto;">Delete</button>
                </div>
                <div class="rule-detail-item"><b>Created</b><span>${rule.created_at ? escapeHtml(new Date(rule.created_at).toLocaleString()) : 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Updated</b><span>${rule.updated_at ? escapeHtml(new Date(rule.updated_at).toLocaleString()) : 'N/A'}</span></div>
            `;
        }
        
        detailsHTML += '</div></td>';
        detailsRow.innerHTML = detailsHTML;
        return detailsRow;
    }

    function setRuleRowUI(row, enabled) {
        const statusSpan = row.querySelector('.rule-status');
        const button = row.querySelector('.rule-toggle-btn');
        if (!statusSpan || !button) {
            return;
        }
        if (enabled) {
            statusSpan.classList.remove('disabled');
            statusSpan.classList.add('enabled');
            statusSpan.textContent = 'Enabled';
            button.textContent = 'Disable';
        } else {
            statusSpan.classList.remove('enabled');
            statusSpan.classList.add('disabled');
            statusSpan.textContent = 'Disabled';
            button.textContent = 'Enable';
        }
    }

    function updateRestartButtonState() {
        const btn = document.getElementById('restart-waf-btn');
        if (!btn) {
            return;
        }
        localStorage.setItem(PENDING_RESTART_KEY, hasPendingRestart ? '1' : '0');
        btn.classList.toggle('pending-restart', hasPendingRestart);
    }

    function attachRuleRowBehavior(row, rule) {
        row.classList.add('rule-row');
        const firstCell = row.querySelector('td');
        if (firstCell && !firstCell.querySelector('.rule-id-wrap')) {
            const current = firstCell.innerHTML;
            firstCell.innerHTML = `<span class="rule-id-wrap"><span class="rule-toggle">&#8250;</span>${current}</span>`;
        }
        row.addEventListener('click', () => {
            toggleRuleDetails(row, rule);
            if (rule.type === 'custom') {
                populateEditForm(rule);
            }
        });
        const actionBtn = row.querySelector('.rule-toggle-btn');
        if (actionBtn) {
            actionBtn.addEventListener('click', (event) => {
                event.stopPropagation();
                toggleRuleStatus(rule.id, row);
            });
        }
    }

    function buildRuleRow(rule) {
        const row = document.createElement('tr');
        row.id = `rule-${rule.id}`;
        
        if (rule.type === 'crs') {
            row.classList.add('crs-rule');
        }

        const idCell = document.createElement('td');
        idCell.className = 'rule-id';
        idCell.textContent = String(rule.id || '');

        const categoryCell = document.createElement('td');
        categoryCell.textContent = String(rule.category || 'Uncategorized');

        const descCell = document.createElement('td');
        descCell.textContent = String(rule.description || 'No description provided');

        const statusCell = document.createElement('td');
        statusCell.className = 'rule-status-cell';
        const statusWrap = document.createElement('div');
        statusWrap.className = 'rule-status-controls';

        const statusSpan = document.createElement('span');
        statusSpan.className = `rule-status ${rule.enabled ? 'enabled' : 'disabled'}`;
        statusSpan.textContent = rule.enabled ? 'Enabled' : 'Disabled';

        const actionBtn = document.createElement('button');
        actionBtn.className = 'rule-toggle-btn';
        actionBtn.textContent = rule.enabled ? 'Disable' : 'Enable';

        statusWrap.appendChild(statusSpan);
        statusWrap.appendChild(actionBtn);
        statusCell.appendChild(statusWrap);

        row.appendChild(idCell);
        row.appendChild(categoryCell);
        row.appendChild(descCell);
        row.appendChild(statusCell);

        return row;
    }

    async function loadRules(page = 1) {
        const tbody = document.getElementById('rules-tbody');
        if (!tbody) {
            return;
        }
        tbody.innerHTML = '<tr><td colspan="4">Loading...</td></tr>';

        try {
            let queryParams = `page=${page}&limit=${pageSize}`;
            if (currentType) {
                queryParams += `&type=${currentType}`;
            }
            if (currentCategory) {
                queryParams += `&category=${encodeURIComponent(currentCategory)}`;
            }
            if (currentSearch) {
                queryParams += `&search=${encodeURIComponent(currentSearch)}`;
            }
            if (currentParanoiaLevel && currentType === 'crs') {
                queryParams += `&paranoia_level=${currentParanoiaLevel}`;
            }

            const response = await apiFetch(`/api/rules?${queryParams}`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const payload = await response.json();
            
            let rules;
            if (payload.data) {
                rules = payload.data;
                currentPage = payload.page || 1;
                totalPages = payload.total_pages || 1;
            } else if (Array.isArray(payload)) {
                rules = payload;
                currentPage = 1;
                totalPages = 1;
            } else {
                rules = [];
            }

            tbody.innerHTML = '';
            
            if (rules.length === 0) {
                const row = document.createElement('tr');
                row.innerHTML = '<td colspan="4">No rules found.</td>';
                tbody.appendChild(row);
            } else {
                rules.forEach((rule) => {
                    const row = buildRuleRow(rule);
                    tbody.appendChild(row);
                    attachRuleRowBehavior(row, rule);
                });
            }
            
            renderPaginationControls();
            updateRuleCount(payload.total_count || rules.length);
        } catch (error) {
            console.error('Failed to load rules from API:', error);
            tbody.innerHTML = '<td colspan="4">Failed to load rules from API.</td>';
        }

        applyRuleDeepLink();
    }

    function updateRuleCount(count) {
        const countEl = document.getElementById('rule-count');
        if (countEl) {
            countEl.textContent = `${count} rule${count !== 1 ? 's' : ''}`;
        }
    }

    async function loadRegexRules() {
        const tbody = document.getElementById('rules-tbody');
        if (!tbody) return;

        currentPage = 1;
        totalPages = 1;
        const pagination = document.getElementById('pagination-controls');
        if (pagination) pagination.innerHTML = '';
        
        tbody.innerHTML = '<tr><td colspan="4" class="text-center">Loading regex signatures...</td></tr>';
        
        try {
            const response = await apiFetch('/api/rules/regex');
            if (!response.ok) throw new Error('Failed to load');
            const data = await response.json();
            
            if (!Array.isArray(data) || data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4">No regex signatures found.</td></tr>';
                return;
            }
            
            tbody.innerHTML = '';
            data.forEach(cat => {
                const row = document.createElement('tr');
                row.className = 'rule-row';
                row.innerHTML = `
                    <td><span class="rule-id-wrap"><span class="rule-toggle">&#8250;</span>${cat.category}</span></td>
                    <td>${cat.severity.toUpperCase()}</td>
                    <td>${cat.name}</td>
                    <td><span class="rule-status enabled">${cat.patterns} patterns</span></td>
                `;
                row.style.cursor = 'default';
                tbody.appendChild(row);
            });
            
            const total = data.reduce((sum, c) => sum + c.patterns, 0);
            updateRuleCount(total);
        } catch (err) {
            console.error('Failed to load regex rules:', err);
            tbody.innerHTML = '<tr><td colspan="4">Failed to load regex signatures.</td></tr>';
        }
    }

    function renderPaginationControls() {
        const container = document.getElementById('pagination-controls');
        if (!container) return;

        if (totalPages <= 1) {
            container.innerHTML = '';
            return;
        }

        container.innerHTML = `
            <div class="pagination" style="display:flex;align-items:center;justify-content:center;gap:10px;padding:15px;">
                <button class="btn btn-secondary" id="prev-page-btn" ${currentPage <= 1 ? 'disabled' : ''}>Previous</button>
                <span style="color:#f97316;font-size:0.875rem;">Page ${currentPage} of ${totalPages}</span>
                <button class="btn btn-secondary" id="next-page-btn" ${currentPage >= totalPages ? 'disabled' : ''}>Next</button>
            </div>
        `;

        document.getElementById('prev-page-btn')?.addEventListener('click', () => loadRules(currentPage - 1));
        document.getElementById('next-page-btn')?.addEventListener('click', () => loadRules(currentPage + 1));
    }

    function toggleRuleDetails(row, rule) {
        const ruleId = row.id.replace('rule-', '');
        const detailsId = `rule-${ruleId}-details`;
        let detailsRow = document.getElementById(detailsId);
        if (!detailsRow) {
            detailsRow = createDetailsRow(rule);
            row.insertAdjacentElement('afterend', detailsRow);
            const deleteBtn = detailsRow.querySelector('.btn-delete-rule');
            if (deleteBtn) {
                deleteBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    window.deleteRule(deleteBtn.dataset.ruleId);
                });
            }
        }
        const isOpen = detailsRow.classList.contains('open');
        detailsRow.classList.toggle('open', !isOpen);
        row.classList.toggle('expanded', !isOpen);
    }

    window.clearRuleForm = function () {
        document.getElementById('rule-id').value = '';
        document.getElementById('rule-category').value = 'SQLi';
        document.getElementById('rule-desc').value = '';
        document.getElementById('rule-syntax').value = '';
    };

    window.restartWAF = async function () {
        const btn = document.getElementById('restart-waf-btn');
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Restarting...';
        }
        try {
            const response = await apiFetch('/api/system/restart/proxy-waf', { method: 'POST' });
            if (!(response.ok || response.status === 202)) {
                throw new Error(`HTTP ${response.status}`);
            }
            hasPendingRestart = false;
            updateRestartButtonState();
            showModal('Restart Triggered', 'WAF restart command has been sent. Wait a few seconds and refresh if needed.');
        } catch (_) {
            showModal('Restart Failed', 'Could not restart WAF automatically. Please check service permissions/logs.', 'error');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Restart WAF';
            }
        }
    };

    window.toggleRuleStatus = async function (ruleId, rowEl) {
        const row = rowEl || document.getElementById(`rule-${ruleId}`);
        if (!row) {
            return;
        }
        const statusSpan = row.querySelector('.rule-status');
        if (!statusSpan) {
            return;
        }
        const wasEnabled = statusSpan.classList.contains('enabled');
        const nextEnabled = !wasEnabled;
        try {
            const response = await apiFetch(`/api/rules/${ruleId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: nextEnabled })
            });
            if (!response.ok) {
                if (response.status === 403) {
                    showModal('Permission Denied', 'You need admin privileges to toggle rules.', 'error');
                } else if (response.status === 404) {
                    showModal('Rule Not Found', 'This rule does not exist in the database.', 'error');
                }
                return;
            }
            setRuleRowUI(row, nextEnabled);
            hasPendingRestart = true;
            updateRestartButtonState();
        } catch (err) {
            console.error('Toggle error:', err);
            showModal('Error', 'Failed to toggle rule status.', 'error');
        }
    };

    window.saveRule = async function () {
        const id = document.getElementById('rule-id').value.trim();
        const category = document.getElementById('rule-category').value;
        const desc = document.getElementById('rule-desc').value.trim();
        const syntax = document.getElementById('rule-syntax').value.trim();
        
        if (!id || !desc) {
            showModal('Error', 'Rule ID and Description are required.', 'error');
            return;
        }
        
        try {
            const resp = await apiFetch('/api/rules', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({id, category, description: desc, severity: 'MEDIUM', phase: 2})
            });
            if (!resp.ok) throw new Error('Failed');
            showModal('Success', 'Rule created. Toggle to enable.');
            document.getElementById('clear-rule-btn').click();
            loadRules(1);
        } catch (e) {
            showModal('Error', 'Failed to create rule.', 'error');
        }
};

    function populateEditForm(rule) {
        document.getElementById('edit-rule-id-display').textContent = `#${rule.id}`;
        document.getElementById('edit-rule-category').value = rule.category || 'Custom';
        document.getElementById('edit-rule-desc').value = rule.description || '';
        document.getElementById('edit-rule-severity').value = rule.severity || 'MEDIUM';
        document.getElementById('edit-rule-phase').value = String(rule.phase || 2);
        editingRuleId = rule.id;
        switchMode('edit');
    }

    function switchMode(mode) {
        currentMode = mode;
        document.querySelectorAll('.rule-mode-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.mode === mode);
        });
        document.getElementById('write-rule-section').style.display = mode === 'write' ? 'block' : 'none';
        document.getElementById('edit-rule-section').style.display = mode === 'edit' ? 'block' : 'none';
    }

    window.saveEditRule = async function () {
        if (!editingRuleId) {
            showModal('Error', 'No rule selected for editing.', 'error');
            return;
        }
        const category = document.getElementById('edit-rule-category').value;
        const description = document.getElementById('edit-rule-desc').value.trim();
        const severity = document.getElementById('edit-rule-severity').value;
        const phase = parseInt(document.getElementById('edit-rule-phase').value, 10);

        if (!description) {
            showModal('Error', 'Description is required.', 'error');
            return;
        }

        try {
            const resp = await apiFetch(`/api/rules/${editingRuleId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ category, description, severity, phase })
            });
            if (!resp.ok) throw new Error('Failed to update rule');
            showModal('Success', 'Rule updated successfully.');
            switchMode('write');
            loadRules(currentPage);
        } catch (e) {
            showModal('Error', 'Failed to update rule.', 'error');
        }
    };

    window.deleteRule = async function (ruleId) {
        if (!ruleId) return;
        showConfirm(
            'Delete Rule',
            `Are you sure you want to delete rule #${ruleId}? This cannot be undone.`,
            async () => {
                try {
                    const resp = await apiFetch(`/api/rules/${ruleId}`, {
                        method: 'DELETE'
                    });
                    if (!resp.ok) {
                        if (resp.status === 403) {
                            showModal('Permission Denied', 'Cannot delete CRS rules.', 'error');
                        } else {
                            showModal('Error', 'Failed to delete rule.', 'error');
                        }
                        return;
                    }
                    showModal('Deleted', `Rule #${ruleId} has been deleted.`);
                    if (editingRuleId === ruleId) {
                        switchMode('write');
                    }
                    loadRules(currentPage);
                } catch (e) {
                    showModal('Error', 'Failed to delete rule.', 'error');
                }
            }
        );
    };

    function setupTabs() {
        const tabs = document.querySelectorAll('.rules-tab');
        const paranoiaFilter = document.getElementById('paranoia-filter');
        
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                
                const type = tab.getAttribute('data-type');
                if (type === 'regex') {
                    loadRegexRules();
                    return;
                }
                currentType = type;
                currentPage = 1;
                
                if (paranoiaFilter) {
                    if (type === 'crs') {
                        paranoiaFilter.style.display = 'block';
                    } else {
                        paranoiaFilter.style.display = 'none';
                        currentParanoiaLevel = '';
                    }
                }
                
                loadRules(1);
            });
        });
    }

    function setupSearch() {
        const searchInput = document.getElementById('rule-search');
        if (searchInput) {
            let searchTimeout;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    currentSearch = e.target.value.trim();
                    currentPage = 1;
                    loadRules(1);
                }, 300);
            });
        }
    }

    function setupCategoryFilter() {
        const categorySelect = document.getElementById('category-filter');
        if (categorySelect) {
            categorySelect.addEventListener('change', (e) => {
                currentCategory = e.target.value;
                currentPage = 1;
                loadRules(1);
            });
        }
    }

    function setupParanoiaFilter() {
        const paranoiaSelect = document.getElementById('paranoia-filter');
        if (paranoiaSelect) {
            paranoiaSelect.addEventListener('change', (e) => {
                currentParanoiaLevel = e.target.value;
                currentPage = 1;
                loadRules(1);
            });
        }
    }

    document.querySelectorAll('.rule-mode-btn').forEach(btn => {
        btn.addEventListener('click', () => switchMode(btn.dataset.mode));
    });

    const saveRuleBtn = document.getElementById('save-rule-btn');
    if (saveRuleBtn) {
        saveRuleBtn.addEventListener('click', window.saveRule);
    }

    const clearRuleBtn = document.getElementById('clear-rule-btn');
    if (clearRuleBtn) {
        clearRuleBtn.addEventListener('click', window.clearRuleForm);
    }

    const saveEditBtn = document.getElementById('save-edit-btn');
    if (saveEditBtn) {
        saveEditBtn.addEventListener('click', window.saveEditRule);
    }

    const cancelEditBtn = document.getElementById('cancel-edit-btn');
    if (cancelEditBtn) {
        cancelEditBtn.addEventListener('click', () => {
            switchMode('write');
            editingRuleId = null;
        });
    }

    const restartWafBtn = document.getElementById('restart-waf-btn');
    if (restartWafBtn) {
        restartWafBtn.addEventListener('click', window.restartWAF);
    }

    setupTabs();
    setupSearch();
    setupCategoryFilter();
    setupParanoiaFilter();
    const paranoiaFilter = document.getElementById('paranoia-filter');
    if (paranoiaFilter && currentType === 'crs') {
        paranoiaFilter.style.display = 'block';
    }
    loadRules();
    updateRestartButtonState();
})();
