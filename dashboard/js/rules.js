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
    let regexSignatureLookup = {};

    function applyRuleDeepLink() {
        const params = new URLSearchParams(window.location.search);
        const ruleId = params.get('rule');
        if (!ruleId) {
            return;
        }
        
        const expandRule = (rule) => {
            const row = document.getElementById('rule-' + rule.id);
            if (!row) return;
            toggleRuleDetails(row);
            row.scrollIntoView({ behavior: 'smooth', block: 'center' });
            row.classList.add('highlight-row');
            setTimeout(() => row.classList.remove('highlight-row'), 4000);
        };

        const existingRow = document.getElementById('rule-' + ruleId);
        if (existingRow) {
            expandRule(existingRow._ruleData);
            return;
        }

        const tabSearchOrder = ['custom', 'crs'];
        
        (async () => {
            for (const type of tabSearchOrder) {
                try {
                    const res = await apiFetch(`/api/rules?limit=1&type=${type}&search=${ruleId}`);
                    if (!res.ok) continue;
                    const data = await res.json();
                    const rules = data.data || data;
                    
                    if (rules.length > 0) {
                        setActiveTab(type, true);
                        currentSearch = ruleId;
                        await loadRules(1, true);
                        
                        const row = document.getElementById('rule-' + ruleId);
                        if (row) {
                            expandRule(row._ruleData);
                            return;
                        }
                    }
                } catch (e) {
                    console.warn(`Failed to search ${type} tab:`, e);
                }
            }
            
            if (!/^\d+$/.test(ruleId)) {
                setActiveTab('regex', true);
                return;
            }
        })();
    }

    function clearRuleQuery() {
        const url = new URL(window.location.href);
        if (!url.searchParams.has('rule')) return;
        url.searchParams.delete('rule');
        window.history.replaceState({}, '', url.toString());
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
                ${rule.signature ? `<div class="rule-detail-item" style="grid-column:1/-1;"><b>SecRule Line</b><code style="display:block;font-size:0.7rem;word-break:break-all;white-space:pre-wrap;max-height:200px;overflow-y:auto;background:var(--bg-panel);padding:0.5rem;border-radius:4px;margin-top:0.25rem;line-height:1.5;">${escapeHtml(rule.signature)}</code></div>` : ''}
            `;
        } else if (rule.type === 'crs-blocking') {
            detailsHTML += `
                <div class="rule-detail-item"><b>Type</b><span>CRS Blocking Evaluation</span></div>
                <div class="rule-detail-item"><b>Severity</b><span>${escapeHtml(rule.severity) || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Phase</b><span>${escapeHtml(rule.phase) || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Paranoia Level</b><span>${escapeHtml(rule.paranoia_level) || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Source</b><span>${escapeHtml(rule.source) || 'owasp-crs'}</span></div>
                <div class="rule-detail-item"><b>Note</b><span class="text-muted">Aggregate rule — fires when cumulative anomaly score exceeds the paranoia threshold. Links detection rules to the block decision. Read-only.</span></div>
                ${rule.signature ? `<div class="rule-detail-item" style="grid-column:1/-1;"><b>SecRule Line</b><code style="display:block;font-size:0.7rem;word-break:break-all;white-space:pre-wrap;max-height:200px;overflow-y:auto;background:var(--bg-panel);padding:0.5rem;border-radius:4px;margin-top:0.25rem;line-height:1.5;">${escapeHtml(rule.signature)}</code></div>` : ''}
            `;
        } else if (rule.type === 'crs-init') {
            detailsHTML += `
                <div class="rule-detail-item"><b>Type</b><span>CRS Initialization</span></div>
                <div class="rule-detail-item"><b>Severity</b><span>${escapeHtml(rule.severity) || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Phase</b><span>${escapeHtml(rule.phase) || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Paranoia Level</b><span>${escapeHtml(rule.paranoia_level) || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Source</b><span>${escapeHtml(rule.source) || 'owasp-crs'}</span></div>
                <div class="rule-detail-item"><b>Note</b><span class="text-muted">Initialization rule — sets up CRS variables, exclusions, and configuration on engine start. Read-only.</span></div>
                ${rule.signature ? `<div class="rule-detail-item" style="grid-column:1/-1;"><b>SecRule Line</b><code style="display:block;font-size:0.7rem;word-break:break-all;white-space:pre-wrap;max-height:200px;overflow-y:auto;background:var(--bg-panel);padding:0.5rem;border-radius:4px;margin-top:0.25rem;line-height:1.5;">${escapeHtml(rule.signature)}</code></div>` : ''}
            `;
        } else {
            const source = rule.source || 'modintel-custom';
            const sig = rule.signature || '';
            detailsHTML += `
                <div class="rule-detail-item"><b>Type</b><span>Custom Rule</span></div>
                <div class="rule-detail-item"><b>Severity</b><span>${escapeHtml(rule.severity) || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Phase</b><span>${escapeHtml(rule.phase) || 'N/A'}</span></div>
                <div class="rule-detail-item" style="display:flex;align-items:flex-start;gap:0.5rem;">
                    <div><b>Source</b><span>${escapeHtml(source)}</span></div>
                    <button class="btn-delete-rule" data-rule-id="${escapeHtml(rule.id)}" style="margin-left:auto;">Delete</button>
                </div>
                ${sig ? `<div class="rule-detail-item"><b>Signature</b><code style="font-size:0.75rem;word-break:break-all;white-space:pre-wrap;">${escapeHtml(sig)}</code></div>` : ''}
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
                hideReadOnlyRule();
                populateEditForm(rule);
            } else if (rule.type === 'crs' || rule.type === 'crs-blocking' || rule.type === 'crs-init') {
                showReadOnlyRule(rule);
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
        row._ruleData = rule;
        
        if (rule.type === 'crs') {
            row.classList.add('crs-rule');
        } else if (rule.type === 'crs-blocking') {
            row.classList.add('crs-blocking-rule');
        } else if (rule.type === 'crs-init') {
            row.classList.add('crs-init-rule');
        }

        const idCell = document.createElement('td');
        idCell.className = 'rule-id';
        idCell.textContent = String(rule.id || '');

        const categoryCell = document.createElement('td');
        categoryCell.textContent = String(rule.category || 'Uncategorized');

        const descCell = document.createElement('td');
        descCell.textContent = String(rule.description || 'No description provided');
        descCell.className = 'desc-collapsed';
        descCell.title = 'Click to expand';
        descCell.addEventListener('click', (e) => {
            e.stopPropagation();
            const isCollapsed = descCell.classList.contains('desc-collapsed');
            descCell.classList.toggle('desc-collapsed', !isCollapsed);
            descCell.classList.toggle('desc-expanded', isCollapsed);
            descCell.title = isCollapsed ? 'Click to collapse' : 'Click to expand';
        });

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

    async function loadRules(page = 1, silent) {
        const tbody = document.getElementById('rules-tbody');
        if (!tbody) {
            return;
        }
        if (!silent) {
            tbody.innerHTML = '<tr><td colspan="4">Loading...</td></tr>';
        }

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
            tbody.innerHTML = '<tr><td colspan="4">Failed to load rules from API.</td></tr>';
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
        
        regexSignatureLookup = {};

        try {
            const sigResp = await apiFetch('/api/rules/regex/all');
            if (!sigResp.ok) throw new Error('Failed to load');
            const sigs = await sigResp.json();
            
            if (!Array.isArray(sigs) || sigs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4">No regex signatures found.</td></tr>';
                return;
            }
            
            sigs.forEach(sig => {
                regexSignatureLookup[sig.id] = sig;
            });
            
            tbody.innerHTML = '';
            sigs.forEach(sig => {
                const row = document.createElement('tr');
                row.id = `rule-${sig.id}`;
                row.className = 'rule-row regex-sig-row';
                const patternCount = sig.patterns || 1;
                const sigData = { ...sig, type: 'regex', description: sig.name };
                row._ruleData = sigData;
                row.innerHTML = `
                    <td><span class="rule-id-wrap"><span class="rule-toggle">&#8250;</span>${sig.id}</span></td>
                    <td>${sig.category}</td>
                    <td>${sig.name}</td>
                    <td><span class="rule-status enabled">${patternCount} pattern${patternCount !== 1 ? 's' : ''}</span></td>
                `;
                row.style.cursor = 'pointer';
                row.addEventListener('click', () => toggleRuleDetails(row));
                tbody.appendChild(row);
            });
            
            const totalPatterns = sigs.reduce((sum, sig) => sum + (sig.patterns || 0), 0);
            updateRuleCount(totalPatterns);
            
            applyRuleDeepLink();
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
            detailsRow = createDetailsRow(rule || row._ruleData);
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
        const sigEl = document.getElementById('rule-signature');
        if (sigEl) sigEl.value = '';
        const sevEl = document.getElementById('rule-severity');
        if (sevEl) sevEl.value = 'MEDIUM';
        const phaseEl = document.getElementById('rule-phase');
        if (phaseEl) phaseEl.value = '2';
        syncCustomSelect('rule-category');
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
        const severity = document.getElementById('rule-severity')?.value || 'MEDIUM';
        const phase = parseInt(document.getElementById('rule-phase')?.value, 10) || 2;
        const signature = document.getElementById('rule-signature')?.value.trim() || '';
        
        if (!id || !desc || !signature) {
            const missing = [];
            if (!id) missing.push('Rule ID');
            if (!desc) missing.push('Description');
            if (!signature) missing.push('Signature (SecRule line)');
            showModal('Error', `<b>Required fields:</b> ${missing.join(', ')}`, 'error');
            return;
        }
        
        try {
            const resp = await apiFetch('/api/rules', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({id, category, description: desc, severity, phase, signature})
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
        const sigEl = document.getElementById('edit-rule-signature');
        if (sigEl) sigEl.value = rule.signature || '';
        editingRuleId = rule.id;
        switchMode('edit');
        syncCustomSelect('edit-rule-category');
    }

    function showReadOnlyRule(rule) {
        document.getElementById('edit-rule-id-display').textContent = `#${rule.id}`;
        document.getElementById('edit-rule-category').value = rule.category || '';
        document.getElementById('edit-rule-desc').value = rule.description || '';
        document.getElementById('edit-rule-severity').value = rule.severity || 'MEDIUM';
        document.getElementById('edit-rule-phase').value = String(rule.phase || 2);
        const sigEl = document.getElementById('edit-rule-signature');
        if (sigEl) {
            sigEl.value = rule.signature || '';
            sigEl.readOnly = true;
        }
        editingRuleId = null;
        switchMode('edit', true);
        syncCustomSelect('edit-rule-category');
    }

    function hideReadOnlyRule() {
        const editSection = document.getElementById('edit-rule-section');
        if (editSection) editSection.classList.remove('readonly');
        const writeSection = document.getElementById('write-rule-section');
        if (writeSection) writeSection.classList.remove('readonly');
        const sigEl = document.getElementById('edit-rule-signature');
        if (sigEl) sigEl.readOnly = false;
    }

    function switchMode(mode, readonly) {
        currentMode = mode;
        document.querySelectorAll('.rule-mode-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.mode === mode);
        });
        const writeSection = document.getElementById('write-rule-section');
        const editSection = document.getElementById('edit-rule-section');
        writeSection.style.display = mode === 'write' ? 'block' : 'none';
        editSection.style.display = mode === 'edit' ? 'block' : 'none';
        writeSection.classList.remove('readonly');
        editSection.classList.remove('readonly');
        if (!readonly) {
            const sigEl = document.getElementById('edit-rule-signature');
            if (sigEl) sigEl.readOnly = false;
        }
        if (mode === 'edit' && readonly) {
            editSection.classList.add('readonly');
        }
    }

    window.saveEditRule = async function () {
        if (!editingRuleId) {
            if (document.getElementById('edit-rule-section').classList.contains('readonly')) {
                switchMode('write');
                return;
            }
            showModal('Error', 'No rule selected for editing.', 'error');
            return;
        }
        const category = document.getElementById('edit-rule-category').value;
        const description = document.getElementById('edit-rule-desc').value.trim();
        const severity = document.getElementById('edit-rule-severity').value;
        const phase = parseInt(document.getElementById('edit-rule-phase').value, 10);
        const signature = document.getElementById('edit-rule-signature')?.value.trim() || '';

        if (!description) {
            showModal('Error', '<b>Required field:</b> Description', 'error');
            return;
        }

        const body = { category, description, severity, phase };
        if (signature) body.signature = signature;

        try {
            const resp = await apiFetch(`/api/rules/${editingRuleId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
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
        } else if (rule.type === 'regex') {
            detailsHTML += `
                <div class="rule-detail-item"><b>Type</b><span>Regex Signature</span></div>
                <div class="rule-detail-item"><b>Category</b><span>${escapeHtml(rule.category) || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Severity</b><span>${escapeHtml(rule.severity) || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Source</b><span>modintel-regex</span></div>
            `;
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

    function setActiveTab(type, silent) {
        const tabs = document.querySelectorAll('.rules-tab');
        const paranoiaFilter = document.getElementById('paranoia-filter');
        tabs.forEach(tab => {
            const isActive = tab.getAttribute('data-type') === type;
            tab.classList.toggle('active', isActive);
        });

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
                paranoiaFilter.value = '';
            }
        }

        loadRules(1, silent);
    }

    function setupTabs() {
        const tabs = document.querySelectorAll('.rules-tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const type = tab.getAttribute('data-type');
                setActiveTab(type);
            });
        });
    }

    function setupSearch() {
        const searchInput = document.getElementById('rule-search');
        const clearBtn = document.getElementById('clear-search-btn');
        if (searchInput) {
            let searchTimeout;
            const toggleClear = () => {
                if (clearBtn) clearBtn.style.display = searchInput.value.trim() ? 'inline-block' : 'none';
            };
            searchInput.addEventListener('input', (e) => {
                const val = e.target.value.trim();
                toggleClear();
                clearTimeout(searchTimeout);
                if (val === currentSearch) return;
                searchTimeout = setTimeout(() => {
                    currentSearch = val;
                    currentPage = 1;
                    loadRules(1);
                }, 300);
            });
            if (clearBtn) {
                clearBtn.addEventListener('click', () => {
                    clearTimeout(searchTimeout);
                    currentSearch = '';
                    searchInput.value = '';
                    currentCategory = '';
                    currentParanoiaLevel = '';
                    currentPage = 1;
                    clearBtn.style.display = 'none';
                    const categorySelect = document.getElementById('category-filter');
                    if (categorySelect) categorySelect.value = '';
                    const paranoiaSelect = document.getElementById('paranoia-filter');
                    if (paranoiaSelect) paranoiaSelect.value = '';
                    clearRuleQuery();
                    setActiveTab('crs', true);
                });
            }
            if (searchInput.value.trim()) toggleClear();
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
            hideReadOnlyRule();
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
    const linkParams = new URLSearchParams(window.location.search);
    const linkRuleId = linkParams.get('rule');
    if (linkRuleId) {
        currentSearch = linkRuleId;
        const searchInput = document.getElementById('rule-search');
        if (searchInput) searchInput.value = linkRuleId;
        const clearBtn = document.getElementById('clear-search-btn');
        if (clearBtn) clearBtn.style.display = 'inline-block';
    }
    loadRules();
    updateRestartButtonState();

    const customSelects = {};

    function buildCustomSelect(selectId) {
        const select = document.getElementById(selectId);
        if (!select || select.dataset.customBuilt) return;
        select.dataset.customBuilt = '1';

        const wrap = document.createElement('div');
        wrap.className = 'custom-select-wrap';
        select.parentNode.insertBefore(wrap, select);
        wrap.appendChild(select);

        const trigger = document.createElement('button');
        trigger.type = 'button';
        trigger.className = 'custom-select-trigger';
        wrap.appendChild(trigger);

        const dropdown = document.createElement('div');
        dropdown.className = 'custom-select-dropdown';

        function addOpt(label, value, selected) {
            const div = document.createElement('div');
            div.className = 'custom-select-option';
            if (selected) div.classList.add('selected');
            div.textContent = label;
            div.dataset.value = value;
            div.addEventListener('click', (e) => {
                e.stopPropagation();
                select.value = value;
                trigger.textContent = label;
                dropdown.querySelectorAll('.custom-select-option').forEach(o => o.classList.remove('selected'));
                div.classList.add('selected');
                dropdown.classList.remove('open');
                select.dispatchEvent(new Event('change', { bubbles: true }));
            });
            dropdown.appendChild(div);
        }

        for (const child of select.children) {
            if (child.tagName === 'OPTGROUP') {
                const lbl = document.createElement('div');
                lbl.className = 'custom-select-optgroup';
                lbl.textContent = child.label;
                dropdown.appendChild(lbl);
                for (const opt of child.children) {
                    addOpt(opt.textContent, opt.value, opt.selected);
                }
            } else if (child.tagName === 'OPTION') {
                addOpt(child.textContent, child.value, child.selected);
            }
        }

        wrap.appendChild(dropdown);

        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            dropdown.classList.toggle('open');
        });

        document.addEventListener('click', (e) => {
            if (!wrap.contains(e.target)) {
                dropdown.classList.remove('open');
            }
        });

        const selectedOpt = select.options[select.selectedIndex];
        trigger.textContent = selectedOpt ? selectedOpt.text : '';

        customSelects[selectId] = { wrap, trigger, dropdown };
    }

    function syncCustomSelect(selectId) {
        const select = document.getElementById(selectId);
        const cs = customSelects[selectId];
        if (!select || !cs) return;
        const selectedOpt = select.options[select.selectedIndex];
        if (selectedOpt) {
            cs.trigger.textContent = selectedOpt.text;
            cs.dropdown.querySelectorAll('.custom-select-option').forEach(o => {
                o.classList.toggle('selected', o.dataset.value === select.value);
            });
        }
    }

    buildCustomSelect('rule-category');
    buildCustomSelect('edit-rule-category');
})();
