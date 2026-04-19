(function () {
    'use strict';

    const ruleNotes = {
        "913100": {
            purpose: "Detects common scanner and automation fingerprints in requests.",
            triggers: "Suspicious scanner user-agents, probing patterns, and known recon signatures.",
            impact: "Can block pentest tools and noisy recon traffic quickly.",
            analyst: "Verify source IP and request frequency before relaxing; disabling increases exposure to discovery scans."
        },
        "930100": {
            purpose: "Protects against path traversal attempts targeting local files.",
            triggers: "../, encoded traversal payloads, and unsafe file path fragments.",
            impact: "Stops attempts to read system files or app secrets.",
            analyst: "If false positives occur, inspect endpoint file handling logic before editing the rule."
        },
        "931100": {
            purpose: "Detects remote file inclusion style payloads.",
            triggers: "External file references in parameters where local-only values are expected.",
            impact: "Prevents attackers from forcing remote script/resource loading.",
            analyst: "Allow only trusted domains or strict URL formats at app layer instead of disabling broadly."
        },
        "932100": {
            purpose: "Detects command execution payloads and shell syntax abuse.",
            triggers: "Command separators, shell operators, and execution-like patterns.",
            impact: "Reduces RCE risk through input-level blocking.",
            analyst: "Review whether endpoint intentionally accepts shell-like syntax before tuning."
        },
        "932105": {
            purpose: "Focused protection for Unix command injection variants.",
            triggers: "Unix-specific command chaining and invocation tokens.",
            impact: "Catches command abuse missed by generic filters.",
            analyst: "Prefer targeted allow-list exceptions per route if needed."
        },
        "932115": {
            purpose: "Catches common Unix command keywords used in exploit strings.",
            triggers: "Payloads containing command names and suspicious shell composition.",
            impact: "Improves early stop rate for command injection probes.",
            analyst: "Check request context and whether user input legitimately contains command text."
        },
        "933100": {
            purpose: "Detects PHP injection and executable PHP payload characteristics.",
            triggers: "PHP function patterns, code fragments, and injection tokens.",
            impact: "Protects PHP execution surfaces and templating paths.",
            analyst: "If disabled, ensure backend sanitization and strict validation are enforced."
        },
        "933160": {
            purpose: "Detects PHP file inclusion attempts and related patterns.",
            triggers: "Inclusion keywords and path payloads aimed at dynamic include behavior.",
            impact: "Blocks attempts to load attacker-controlled files.",
            analyst: "Review include/require usage in app code before changing rule behavior."
        },
        "934110": {
            purpose: "Generic language/runtime injection detection (Node/Ruby style vectors).",
            triggers: "Template/expression payloads and runtime-specific exploit syntax.",
            impact: "Broadly protects mixed-language stacks.",
            analyst: "Tune carefully because broad signatures can hit legitimate advanced query inputs."
        },
        "934130": {
            purpose: "Detects NoSQL and non-traditional injection payload patterns.",
            triggers: "Operators and structures commonly used in NoSQL injection attempts.",
            impact: "Helps protect Mongo-like query paths.",
            analyst: "Validate server-side query construction safety before weakening this rule."
        },
        "941100": {
            purpose: "Primary XSS detection using libinjection heuristics.",
            triggers: "Script-like payload structure and known XSS token sequences.",
            impact: "High-value XSS coverage with low overhead.",
            analyst: "Usually keep enabled; add narrow exceptions if business input truly needs markup."
        },
        "941110": {
            purpose: "XSS category filter for additional script injection patterns.",
            triggers: "Encoded/obfuscated tags and script execution vectors.",
            impact: "Catches variants not matched by a single detector.",
            analyst: "Check encoding context in payload and output rendering path."
        },
        "941160": {
            purpose: "Detects HTML injection via NoScript-style checker patterns.",
            triggers: "Injected HTML elements and unsafe tag structures.",
            impact: "Prevents content injection that can evolve into XSS.",
            analyst: "Review endpoints that accept rich text and enforce sanitization profiles."
        },
        "941170": {
            purpose: "Detects attribute-level XSS payloads.",
            triggers: "Event handlers, javascript: URLs, and unsafe attribute injections.",
            impact: "Stops common DOM/event-based XSS vectors.",
            analyst: "Inspect whether UI input is reflected into HTML attributes without escaping."
        },
        "941210": {
            purpose: "IE/XSS filter-related attack signature coverage.",
            triggers: "Legacy browser-oriented XSS payload forms.",
            impact: "Extra defensive depth for compatibility-heavy environments.",
            analyst: "Safe to keep on unless strong evidence of benign legacy payload conflicts."
        },
        "942100": {
            purpose: "Core SQL injection detection signature set.",
            triggers: "SQL operators, union/select patterns, tautologies, and injection syntax.",
            impact: "Primary SQLi barrier across request inputs.",
            analyst: "Only relax with endpoint-level allow-lists and prepared statements verified in code."
        },
        "942151": {
            purpose: "Detects GROUP BY based SQLi techniques.",
            triggers: "GROUP BY payload manipulation and aggregation abuse patterns.",
            impact: "Improves detection of advanced SQLi probing.",
            analyst: "Review analytics/search endpoints that legitimately use SQL-like text in inputs."
        },
        "942160": {
            purpose: "Detects time-based SQLi via sleep/delay functions.",
            triggers: "SLEEP() and timing payload constructs.",
            impact: "Stops blind SQLi enumeration tactics.",
            analyst: "Investigate any hits immediately; these are often high-confidence attack probes."
        },
        "942190": {
            purpose: "Detects BENCHMARK-based SQLi timing attacks.",
            triggers: "BENCHMARK() function and related heavy-operation injection patterns.",
            impact: "Protects against resource abuse and blind extraction attempts.",
            analyst: "Treat repeated hits as hostile recon or exploitation attempts."
        },
        "942270": {
            purpose: "Detects SQL tautology logic injection.",
            triggers: "OR/AND truthy expression chains (e.g., 1=1 style payloads).",
            impact: "Blocks common authentication bypass attempts.",
            analyst: "Rarely safe to disable globally; prefer route-specific tuning only."
        },
        "942350": {
            purpose: "Covers time-based blind SQLi patterns.",
            triggers: "Conditional delay constructs and blind extraction patterns.",
            impact: "Improves resilience to low-noise SQLi attacks.",
            analyst: "Pair with DB query audit logs when investigating alerts."
        },
        "942360": {
            purpose: "Detects stacked query SQL injection attempts.",
            triggers: "Statement separators and multi-query payload structures.",
            impact: "Prevents chained SQL command execution.",
            analyst: "Check DB driver behavior; stacked queries are high risk in many engines."
        },
        "949110": {
            purpose: "Inbound anomaly threshold enforcement and blocking decision.",
            triggers: "Total anomaly score exceeds configured inbound threshold.",
            impact: "Acts as final gate for high-risk requests.",
            analyst: "Tuning this affects overall strictness; adjust with care and Monitor FP/FN rates."
        },
        "990001": {
            purpose: "Protocol compliance sanity checks for malformed requests.",
            triggers: "Header/protocol combinations that violate expected HTTP patterns.",
            impact: "Blocks malformed traffic used in evasions.",
            analyst: "Useful baseline rule; disable only for proven client compatibility issues."
        },
        "990002": {
            purpose: "Host header validation and compliance checks.",
            triggers: "Invalid, missing, or suspicious Host header values.",
            impact: "Mitigates host-header based attacks and routing abuse.",
            analyst: "Coordinate with proxy and virtual-host config before editing."
        },
        "990003": {
            purpose: "Content-Length header consistency validation.",
            triggers: "Mismatched or malformed length declarations.",
            impact: "Helps prevent request smuggling and parser confusion.",
            analyst: "Do not relax unless upstream clients are known and trusted."
        },
        "990004": {
            purpose: "Transfer/content encoding compliance checks.",
            triggers: "Unsupported or malformed encoding combinations.",
            impact: "Reduces evasive payload delivery via encoding tricks.",
            analyst: "Validate proxy/app decoder behavior when investigating hits."
        },
        "990006": {
            purpose: "Protocol-level guardrail for abnormal POST/body characteristics.",
            triggers: "Suspicious post size or malformed body metadata.",
            impact: "Limits abuse through malformed large body traffic.",
            analyst: "If false positives happen, align body limits across edge and backend."
        },
        "990008": {
            purpose: "Range header and request range compliance checks.",
            triggers: "Malformed/abusive range usage patterns.",
            impact: "Mitigates range abuse and some DoS-style probes.",
            analyst: "Check CDN/proxy behavior before adjusting to avoid cache inconsistencies."
        },
        "990009": {
            purpose: "TE/transfer-encoding header validation.",
            triggers: "Conflicting or malformed TE header combinations.",
            impact: "Helps defend against request smuggling vectors.",
            analyst: "Keep strict unless legacy intermediaries require exceptions."
        },
        "990011": {
            purpose: "Detects empty or invalid host header conditions.",
            triggers: "Missing/empty Host header in contexts where it is required.",
            impact: "Blocks malformed and potentially evasive requests.",
            analyst: "Investigate client stack before allowing exceptions."
        },
        "990012": {
            purpose: "HTTP method case/compliance enforcement.",
            triggers: "Method formatting/casing anomalies.",
            impact: "Normalizes protocol handling and blocks parser edge-case probes.",
            analyst: "Adjust only if you have clients producing nonstandard but safe methods."
        },
        "990030": {
            purpose: "Custom XSS protection for direct HTML tag injection.",
            triggers: "Raw HTML/script-like tags in input fields and query payloads.",
            impact: "Adds immediate block coverage for obvious reflected/stored XSS attempts.",
            analyst: "For rich-text features, use sanitization + scoped exceptions instead of global disable."
        }
    };

    const PENDING_RESTART_KEY = 'rules_pending_restart';
    let hasPendingRestart = localStorage.getItem(PENDING_RESTART_KEY) === '1';

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

    function createDetailsRow(ruleId) {
        const note = ruleNotes[ruleId] || {
            purpose: 'No analyst note defined for this rule yet.',
            triggers: 'Review Coraza/CRS rule docs and local logs.',
            impact: 'Depends on endpoint usage and traffic profile.',
            analyst: 'Validate false-positive risk before changing status.'
        };
        const detailsRow = document.createElement('tr');
        detailsRow.className = 'rule-details-row';
        detailsRow.id = `rule-${ruleId}-details`;
        detailsRow.innerHTML = `
            <td colspan="4" class="rule-details-cell">
                <div class="rule-details">
                    <div class="rule-detail-item"><b>What This Rule Does</b><span>${note.purpose}</span></div>
                    <div class="rule-detail-item"><b>How It Is Triggered</b><span>${note.triggers}</span></div>
                    <div class="rule-detail-item"><b>Security Impact</b><span>${note.impact}</span></div>
                    <div class="rule-detail-item"><b>Analyst Guidance Before Editing</b><span>${note.analyst}</span></div>
                </div>
            </td>
        `;
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

    function attachRuleRowBehavior(row) {
        row.classList.add('rule-row');
        const firstCell = row.querySelector('td');
        if (firstCell && !firstCell.querySelector('.rule-id-wrap')) {
            const current = firstCell.innerHTML;
            firstCell.innerHTML = `<span class="rule-id-wrap"><span class="rule-toggle">&#8250;</span>${current}</span>`;
        }
        row.addEventListener('click', () => toggleRuleDetails(row));
        const actionBtn = row.querySelector('.rule-toggle-btn');
        if (actionBtn) {
            actionBtn.addEventListener('click', (event) => {
                event.stopPropagation();
                toggleRuleStatus(row.id.replace('rule-', ''), row);
            });
        }
    }

    function buildRuleRow(rule) {
        const row = document.createElement('tr');
        row.id = `rule-${rule.id}`;

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

    async function loadRules() {
        const tbody = document.getElementById('rules-tbody');
        if (!tbody) {
            return;
        }
        tbody.innerHTML = '';

        try {
            const response = await apiFetch('/api/rules');
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const payload = await response.json();
            const rules = Array.isArray(payload) ? payload : (payload?.data?.rules || []);
            if (rules.length === 0) {
                const row = document.createElement('tr');
                row.innerHTML = '<td colspan="4">No rules returned by API.</td>';
                tbody.appendChild(row);
            } else {
                rules.forEach((rule) => {
                    const row = buildRuleRow(rule);
                    tbody.appendChild(row);
                    attachRuleRowBehavior(row);
                });
            }
        } catch (error) {
            console.error('Failed to load rules from API:', error);
            const row = document.createElement('tr');
            row.innerHTML = '<td colspan="4">Failed to load rules from API.</td>';
            tbody.appendChild(row);
        }

        applyRuleDeepLink();
    }

    function toggleRuleDetails(row) {
        const ruleId = row.id.replace('rule-', '');
        const detailsId = `rule-${ruleId}-details`;
        let detailsRow = document.getElementById(detailsId);
        if (!detailsRow) {
            detailsRow = createDetailsRow(ruleId);
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
                return;
            }
            setRuleRowUI(row, nextEnabled);
            hasPendingRestart = true;
            updateRestartButtonState();
        } catch (_) {
        }
    };

    window.saveRule = function () {
        showModal('Not implemented', 'Custom rule creation UI is not wired yet. Use API-backed managed overrides for now.');
    };

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

    loadRules();
    updateRestartButtonState();
})();
