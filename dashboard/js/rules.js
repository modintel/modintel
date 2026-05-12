(function () {
    'use strict';

    const PENDING_RESTART_KEY = 'rules_pending_restart';
    let hasPendingRestart = localStorage.getItem(PENDING_RESTART_KEY) === '1';
    let currentPage = 1;
    let totalPages = 1;
    const pageSize = 50;
    let currentType = 'custom'; // Start with custom rules
    let currentCategory = '';
    let currentSearch = '';
    let currentParanoiaLevel = ''; // For CRS rules filtering

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
        
        let detailsHTML = '<td colspan="5" class="rule-details-cell"><div class="rule-details">';
        
        // Show different details based on rule type
        if (rule.type === 'crs') {
            detailsHTML += `
                <div class="rule-detail-item"><b>Type</b><span>OWASP CRS Rule</span></div>
                <div class="rule-detail-item"><b>Severity</b><span>${rule.severity || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Phase</b><span>${rule.phase || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Paranoia Level</b><span>${rule.paranoia_level || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Source</b><span>${rule.source || 'owasp-crs'}</span></div>
                <div class="rule-detail-item"><b>Note</b><span class="text-muted">CRS rules are read-only. Only enable/disable is allowed.</span></div>
            `;
        } else {
            detailsHTML += `
                <div class="rule-detail-item"><b>Type</b><span>Custom Rule</span></div>
                <div class="rule-detail-item"><b>Severity</b><span>${rule.severity || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Phase</b><span>${rule.phase || 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Source</b><span>${rule.source || 'modintel-custom'}</span></div>
                <div class="rule-detail-item"><b>Created</b><span>${rule.created_at ? new Date(rule.created_at).toLocaleString() : 'N/A'}</span></div>
                <div class="rule-detail-item"><b>Updated</b><span>${rule.updated_at ? new Date(rule.updated_at).toLocaleString() : 'N/A'}</span></div>
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
        row.addEventListener('click', () => toggleRuleDetails(row, rule));
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
        
        // Add type indicator class
        if (rule.type === 'crs') {
            row.classList.add('crs-rule');
        }

        const idCell = document.createElement('td');
        idCell.className = 'rule-id';
        idCell.textContent = String(rule.id || '');

        const typeCell = document.createElement('td');
        typeCell.textContent = rule.type === 'crs' ? 'CRS' : 'Custom';
        typeCell.className = 'rule-type';

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
        row.appendChild(typeCell);
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
        tbody.innerHTML = '<tr><td colspan="5">Loading...</td></tr>';

        try {
            // Build query string
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
                row.innerHTML = '<td colspan="5">No rules found.</td>';
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
            tbody.innerHTML = '<td colspan="5">Failed to load rules from API.</td>';
        }

        applyRuleDeepLink();
    }

    function updateRuleCount(count) {
        const countEl = document.getElementById('rule-count');
        if (countEl) {
            countEl.textContent = `${count} rule${count !== 1 ? 's' : ''}`;
        }
    }

    function renderPaginationControls() {
        const container = document.getElementById('pagination-controls');
        if (!container) return;

        container.innerHTML = '';

        if (totalPages <= 1) {
            container.style.display = 'none';
            return;
        }

        container.style.display = 'flex';

        const prevBtn = document.createElement('button');
        prevBtn.textContent = 'Previous';
        prevBtn.className = 'btn btn-secondary';
        prevBtn.disabled = currentPage === 1;
        prevBtn.addEventListener('click', () => loadRules(currentPage - 1));
        container.appendChild(prevBtn);

        const pageInfo = document.createElement('span');
        pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
        pageInfo.style.margin = '0 1rem';
        pageInfo.style.alignSelf = 'center';
        container.appendChild(pageInfo);

        const nextBtn = document.createElement('button');
        nextBtn.textContent = 'Next';
        nextBtn.className = 'btn btn-secondary';
        nextBtn.disabled = currentPage === totalPages;
        nextBtn.addEventListener('click', () => loadRules(currentPage + 1));
        container.appendChild(nextBtn);
    }

    function toggleRuleDetails(row, rule) {
        const ruleId = row.id.replace('rule-', '');
        const detailsId = `rule-${ruleId}-details`;
        let detailsRow = document.getElementById(detailsId);
        if (!detailsRow) {
            detailsRow = createDetailsRow(rule);
            row.insertAdjacentElement('afterend', detailsRow);
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

    window.saveRule = function () {
        showModal('Not implemented', 'Custom rule creation UI is not wired yet. Use API-backed managed overrides for now.');
    };

    // Tab switching
    function setupTabs() {
        const tabs = document.querySelectorAll('.rules-tab');
        const paranoiaFilter = document.getElementById('paranoia-filter');
        
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                // Update active tab
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                
                // Update current type and reload
                const type = tab.getAttribute('data-type');
                if (type === 'regex') {
                    // Regex tab not implemented yet
                    showModal('Not Implemented', 'Regex rules section coming soon.');
                    return;
                }
                currentType = type;
                currentPage = 1;
                
                // Show/hide paranoia filter based on tab
                if (paranoiaFilter) {
                    if (type === 'crs') {
                        paranoiaFilter.style.display = 'block';
                    } else {
                        paranoiaFilter.style.display = 'none';
                        currentParanoiaLevel = ''; // Reset when switching away from CRS
                    }
                }
                
                loadRules(1);
            });
        });
    }

    // Search functionality
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

    // Category filter
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

    // Paranoia level filter (CRS only)
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

    const saveRuleBtn = document.getElementById('save-rule-btn');
    if (saveRuleBtn) {
        saveRuleBtn.addEventListener('click', window.saveRule);
    }

    const clearRuleBtn = document.getElementById('clear-rule-btn');
    if (clearRuleBtn) {
        clearRuleBtn.addEventListener('click', window.clearRuleForm);
    }

    const restartWafBtn = document.getElementById('restart-waf-btn');
    if (restartWafBtn) {
        restartWafBtn.addEventListener('click', window.restartWAF);
    }

    setupTabs();
    setupSearch();
    setupCategoryFilter();
    setupParanoiaFilter();
    loadRules();
    updateRestartButtonState();
})();
