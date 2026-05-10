let originalDisplayName = '';
let originalEmail = '';
let currentUser = null;

async function loadProfile() {
    try {
        const res = await apiFetch('/api/v1/auth/me');
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }
        const payload = await res.json();
        const user = payload?.data;
        currentUser = user;
        if (user) {
            const displayNameEl = document.getElementById('display-name');
            const emailEl = document.getElementById('email');
            const fullName = user.first_name && user.last_name
                ? `${user.first_name} ${user.last_name}`
                : user.first_name || 'Security Analyst';
            originalDisplayName = fullName;
            originalEmail = user.email || '';
            if (displayNameEl) displayNameEl.value = fullName;
            if (emailEl) emailEl.value = originalEmail;

            const avatarEl = document.querySelector('.account-avatar');
            const nameEl2 = document.querySelector('.account-name');
            const roleEl = document.querySelector('.account-role');
            if (avatarEl) {
                const initials = user.first_name?.[0] || user.email?.[0] || 'U';
                avatarEl.textContent = initials.toUpperCase();
            }
            if (nameEl2) {
                nameEl2.textContent = user.first_name && user.last_name
                    ? `${user.first_name} ${user.last_name}`
                    : user.first_name || user.email || 'User';
            }
            if (roleEl) roleEl.textContent = user.email || '';
        }
    } catch (err) {
        console.error('Failed to load profile:', err);
    }
}

function setProfileEditable(editable) {
    const displayNameEl = document.getElementById('display-name');
    const editBtn = document.getElementById('edit-profile-btn');
    const saveBtn = document.getElementById('save-profile-btn');
    const cancelBtn = document.getElementById('cancel-profile-btn');

    if (editable) {
        if (displayNameEl) displayNameEl.removeAttribute('readonly');
        if (editBtn) editBtn.style.display = 'none';
        if (saveBtn) saveBtn.style.display = 'inline-block';
        if (cancelBtn) cancelBtn.style.display = 'inline-block';
    } else {
        if (displayNameEl) {
            displayNameEl.setAttribute('readonly', '');
            displayNameEl.value = originalDisplayName;
        }
        if (editBtn) editBtn.style.display = 'inline-block';
        if (saveBtn) saveBtn.style.display = 'none';
        if (cancelBtn) cancelBtn.style.display = 'none';
    }
}

async function saveProfile() {
    const displayName = document.getElementById('display-name').value.trim();
    const nameParts = displayName.split(' ');
    const firstName = nameParts[0] || '';
    const lastName = nameParts.length > 1 ? nameParts.slice(1).join(' ') : '';

    try {
        const res = await apiFetch('/api/v1/auth/profile', {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ first_name: firstName, last_name: lastName }),
        });
        if (!res.ok) {
            const errPayload = await res.json();
            throw new Error(errPayload?.error || `HTTP ${res.status}`);
        }
        const payload = await res.json();
        const user = payload?.data;
        if (user) {
            const avatarEl = document.querySelector('.account-avatar');
            const nameEl = document.querySelector('.account-name');
            if (avatarEl) {
                const initials = user.first_name?.[0] || user.email?.[0] || 'U';
                avatarEl.textContent = initials.toUpperCase();
            }
            if (nameEl) {
                nameEl.textContent = user.first_name && user.last_name
                    ? `${user.first_name} ${user.last_name}`
                    : user.first_name || user.email || 'User';
            }
        }
        originalDisplayName = displayName;
        setProfileEditable(false);
        showModal('Profile Saved', 'Your profile has been updated.');
    } catch (err) {
        showModal('Profile Error', err.message || 'Failed to save profile.', 'error');
    }
}

const saveProfileBtn = document.getElementById('save-profile-btn');
if (saveProfileBtn) {
    saveProfileBtn.addEventListener('click', saveProfile);
}

function formatSessionDate(value) {
    if (!value) return '-';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return '-';
    return d.toLocaleString();
}

function shortUserAgent(ua) {
    if (!ua) return 'Unknown device';
    if (ua.length <= 72) return ua;
    return ua.slice(0, 72) + '...';
}

function renderSessions(sessions) {
    const listEl = document.getElementById('sessions-list');
    const emptyEl = document.getElementById('sessions-empty');
    if (!listEl || !emptyEl) return;

    listEl.innerHTML = '';

    if (!Array.isArray(sessions) || sessions.length === 0) {
        emptyEl.style.display = 'block';
        return;
    }

    emptyEl.style.display = 'none';

    sessions.forEach((session) => {
        const item = document.createElement('div');
        item.className = 'session-item';

        const details = document.createElement('div');
        details.innerHTML = `
            <div class="session-title">${shortUserAgent(session.user_agent)}</div>
            <div class="session-meta">
                <span>IP: ${session.client_ip || '-'}</span>
                <span>Created: ${formatSessionDate(session.created_at)}</span>
                <span>Last used: ${formatSessionDate(session.last_used_at)}</span>
                <span>Expires: ${formatSessionDate(session.expires_at)}</span>
            </div>
        `;

        const revokeBtn = document.createElement('button');
        revokeBtn.className = 'btn btn-danger session-revoke-btn';
        revokeBtn.textContent = 'Revoke';
        revokeBtn.addEventListener('click', () => revokeSession(session.id));

        item.appendChild(details);
        item.appendChild(revokeBtn);
        listEl.appendChild(item);
    });
}

async function loadSessions() {
    try {
        const res = await apiFetch('/api/v1/auth/sessions');
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }
        const payload = await res.json();
        let sessions = payload?.data?.sessions || [];
        renderSessions(sessions);
    } catch (err) {
        renderSessions([]);
        if (err.message !== 'HTTP 401') {
            showModal('Session Error', 'Failed to load active sessions.', 'error');
        }
    }
}

async function revokeSession(sessionId) {
    showConfirm(
        'Revoke Session',
        'Are you sure you want to revoke this session?',
        async () => {
            try {
                const res = await apiFetch('/api/v1/auth/sessions/revoke', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: sessionId }),
                });
                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}`);
                }
                await loadSessions();
                showModal('Session Revoked', 'The selected session has been revoked.');
            } catch (err) {
                showModal('Session Error', 'Failed to revoke session.', 'error');
            }
        }
    );
}

async function revokeAllSessionsAction() {
    showConfirm(
        'Revoke All Sessions',
        'This will revoke all your active sessions. Continue?',
        async () => {
            try {
                const res = await apiFetch('/api/v1/auth/sessions/revoke-all', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({}),
                });
                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}`);
                }
                await loadSessions();
                showModal('Sessions Revoked', 'All active sessions have been revoked.');
            } catch (err) {
                showModal('Session Error', 'Failed to revoke all sessions.', 'error');
            }
        }
    );
}

function renderUsers(users) {
    const listEl = document.getElementById('users-list');
    const emptyEl = document.getElementById('users-empty');
    if (!listEl || !emptyEl) return;

    listEl.innerHTML = '';

    if (!Array.isArray(users) || users.length === 0) {
        emptyEl.style.display = 'block';
        emptyEl.textContent = 'No users found.';
        return;
    }

    emptyEl.style.display = 'none';

    users.forEach((user) => {
        const item = document.createElement('div');
        item.className = 'user-item';

        const avatar = document.createElement('div');
        const initials = (user.first_name?.[0] || user.email?.[0] || 'U').toUpperCase();
        avatar.className = 'user-avatar-sm';
        avatar.textContent = initials;

        const info = document.createElement('div');
        info.className = 'user-info';
        const name = user.first_name && user.last_name
            ? `${user.first_name} ${user.last_name}`
            : user.first_name || user.email;
        info.innerHTML = `
            <div class="user-name">${name}</div>
            <div class="user-email">${user.email || ''}</div>
        `;

        const status = document.createElement('div');
        status.className = `user-status ${user.is_active !== false ? 'active' : 'inactive'}`;
        status.title = user.is_active !== false ? 'Active' : 'Inactive';

        const roleDisplay = document.createElement('div');
        roleDisplay.className = 'user-role-display';
        roleDisplay.textContent = user.role.charAt(0).toUpperCase() + user.role.slice(1);

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn btn-danger user-delete-btn';
        deleteBtn.textContent = 'Remove';
        deleteBtn.addEventListener('click', () => deleteUser(user));

        item.appendChild(avatar);
        item.appendChild(info);
        item.appendChild(status);
        item.appendChild(roleDisplay);
        item.appendChild(deleteBtn);
        listEl.appendChild(item);
    });
}

async function loadUsers() {
    try {
        const res = await apiFetch('/api/v1/users');
        if (!res.ok) {
            if (res.status === 403) return;
            throw new Error(`HTTP ${res.status}`);
        }
        const payload = await res.json();
        const users = payload?.data?.users || payload?.data || [];
        renderUsers(Array.isArray(users) ? users : []);
    } catch (err) {
        console.error('Failed to load users:', err);
    }
}

async function deleteUser(user) {
    if (currentUser && (user.id === currentUser.id || user._id === currentUser.id)) {
        showModal('Cannot Delete', 'You cannot delete your own account.', 'error');
        return;
    }

    const userName = user.first_name && user.last_name
        ? `${user.first_name} ${user.last_name}`
        : user.first_name || user.email || 'User';

    const requiredText = `Remove user - ${userName}`;

    showPrompt(
        'Confirm User Removal',
        `To remove this user, type: <strong>${requiredText}</strong>`,
        '',
        async (input) => {
            if (input.trim() !== requiredText) {
                showModal('Invalid Confirmation', 'The confirmation text does not match. User not removed.', 'error');
                return;
            }

            try {
                const res = await apiFetch(`/api/v1/users/${user.id || user._id}`, {
                    method: 'DELETE',
                });
                if (!res.ok) {
                    const err = await res.json().catch(() => ({}));
                    throw new Error(err.error || `HTTP ${res.status}`);
                }
                showModal('User Removed', 'The user has been successfully removed.');
                await loadUsers();
            } catch (err) {
                showModal('Error', err.message || 'Failed to remove user.', 'error');
            }
        }
    );
}

async function sendInvite() {
    const email = document.getElementById('invite-email').value.trim();
    const role = document.getElementById('invite-role').value;
    if (!email) {
        showModal('Invite Error', 'Please enter an email address.', 'error');
        return;
    }
    try {
        const res = await apiFetch('/api/v1/users/invite', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, role }),
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            showModal('Invite Failed', err.error || 'Failed to invite user', 'error');
            return;
        }
        const data = await res.json();
        document.getElementById('invite-email').value = '';
        const msg = data.data && data.data.accept_link
            ? `Invitation sent to ${data.data.email || email}.\n\nAccept link (share if email not configured):\n${data.data.accept_link}`
            : (data.message || `Invitation sent to ${email}.`);
        showModal('Invitation Sent', msg, 'info');
        loadUsers();
    } catch (e) {
        showModal('Invite Error', 'Failed to send invite.', 'error');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const refreshBtn = document.getElementById('refresh-sessions-btn');
    const revokeAllBtn = document.getElementById('revoke-all-sessions-btn');
    const editBtn = document.getElementById('edit-profile-btn');
    const cancelBtn = document.getElementById('cancel-profile-btn');

    if (refreshBtn) refreshBtn.addEventListener('click', loadSessions);
    if (revokeAllBtn) revokeAllBtn.addEventListener('click', revokeAllSessionsAction);
    if (editBtn) editBtn.addEventListener('click', () => setProfileEditable(true));
    if (cancelBtn) cancelBtn.addEventListener('click', () => setProfileEditable(false));

    const inviteBtn = document.getElementById('invite-btn');
    if (inviteBtn) inviteBtn.addEventListener('click', sendInvite);
    const inviteEmail = document.getElementById('invite-email');
    if (inviteEmail && inviteBtn) {
        inviteEmail.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendInvite(); });
    }

    const saveParanoiaBtn = document.getElementById('paranoia-save-btn');
    if (saveParanoiaBtn) saveParanoiaBtn.addEventListener('click', saveParanoiaConfig);

    // 2FA buttons
    const setup2faBtn = document.getElementById('setup-2fa-btn');
    if (setup2faBtn) setup2faBtn.addEventListener('click', () => window.location.href = '/setup-2fa');

    const disable2faBtn = document.getElementById('disable-2fa-btn');
    if (disable2faBtn) {
        disable2faBtn.addEventListener('click', () => {
            showPrompt('Disable 2FA', 'Enter your password to confirm:', '', async (password) => {
                if (!password) return;
                try {
                    const res = await apiFetch('/api/v1/auth/2fa/disable', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ password }),
                    });
                    const data = await res.json();
                    if (!res.ok) { showModal('Error', data.error || 'Failed to disable 2FA', 'error'); return; }
                    showModal('2FA Disabled', '2FA has been disabled for your account.');
                    load2FAStatus();
                } catch (_) { showModal('Error', 'Network error.', 'error'); }
            });
        });
    }

    // SMTP buttons
    const smtpSaveBtn = document.getElementById('smtp-save-btn');
    if (smtpSaveBtn) smtpSaveBtn.addEventListener('click', saveSMTPSettings);

    const smtpTestBtn = document.getElementById('smtp-test-btn');
    if (smtpTestBtn) smtpTestBtn.addEventListener('click', testSMTPSettings);

    if (getUser()) {
        loadProfile();
        loadSessions();
        loadParanoiaConfig();
        loadLayer2Threshold();
        load2FAStatus();
        scrollToParanoia();

        const user = getUser();
        if (user && user.role === 'admin') {
            const usersPanel = document.getElementById('users-panel');
            if (usersPanel) usersPanel.style.display = 'flex';
            loadUsers();
            // Show SMTP section for admins
            const smtpSection = document.getElementById('section-smtp');
            if (smtpSection) { smtpSection.style.display = 'block'; loadSMTPSettings(); }
        }
    }
});

// ── 2FA ───────────────────────────────────────────────────────────────────────

async function load2FAStatus() {
    try {
        const res = await apiFetch('/api/v1/auth/2fa/status');
        if (!res.ok) return;
        const data = await res.json();
        const statusText = document.getElementById('twofa-status-text');
        const setupBtn = document.getElementById('setup-2fa-btn');
        const disableBtn = document.getElementById('disable-2fa-btn');
        if (!statusText) return;
        if (data.totp_enabled) {
            statusText.textContent = '2FA is enabled on your account.';
            statusText.style.color = 'var(--success)';
            if (setupBtn) setupBtn.style.display = 'none';
            if (disableBtn) disableBtn.style.display = 'inline-flex';
        } else {
            statusText.textContent = '2FA is not enabled. We recommend enabling it for better security.';
            statusText.style.color = 'var(--fg-muted)';
            if (setupBtn) setupBtn.style.display = 'inline-flex';
            if (disableBtn) disableBtn.style.display = 'none';
        }
    } catch (_) {}
}

// ── SMTP ──────────────────────────────────────────────────────────────────────

async function loadSMTPSettings() {
    try {
        const res = await apiFetch('/api/v1/settings/smtp');
        if (!res.ok) return;
        const data = (await res.json()).data || {};
        const set = (id, val) => { const el = document.getElementById(id); if (el) el.value = val || ''; };
        set('smtp-host', data.smtp_host);
        set('smtp-port', data.smtp_port || 587);
        set('smtp-username', data.smtp_username);
        set('smtp-from', data.smtp_from);
        set('smtp-from-name', data.smtp_from_name);
        const tls = document.getElementById('smtp-use-tls');
        if (tls) tls.checked = !!data.smtp_use_tls;
    } catch (_) {}
}

async function saveSMTPSettings() {
    const get = (id) => { const el = document.getElementById(id); return el ? el.value.trim() : ''; };
    const body = {
        smtp_host:      get('smtp-host'),
        smtp_port:      parseInt(get('smtp-port'), 10) || 587,
        smtp_username:  get('smtp-username'),
        smtp_password:  get('smtp-password'),
        smtp_from:      get('smtp-from'),
        smtp_from_name: get('smtp-from-name'),
        smtp_use_tls:   document.getElementById('smtp-use-tls')?.checked || false,
    };
    if (!body.smtp_host || !body.smtp_from) {
        showModal('Validation Error', 'SMTP host and from address are required.', 'error');
        return;
    }
    try {
        const res = await apiFetch('/api/v1/settings/smtp', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await res.json();
        if (!res.ok) { showModal('Error', data.error || 'Failed to save SMTP settings.', 'error'); return; }
        document.getElementById('smtp-password').value = '';
        showModal('SMTP Saved', 'Email settings saved successfully.');
    } catch (_) { showModal('Error', 'Network error.', 'error'); }
}

async function testSMTPSettings() {
    try {
        const res = await apiFetch('/api/v1/settings/smtp/test', { method: 'POST' });
        const data = await res.json();
        if (!res.ok) { showModal('Test Failed', data.error || 'SMTP test failed.', 'error'); return; }
        showModal('Test Sent', data.message || 'Test email sent successfully.');
    } catch (_) { showModal('Error', 'Network error.', 'error'); }
}

function scrollToParanoia() {
    if (window.location.hash === "#waf-paranoia") {
        var el = document.getElementById("waf-paranoia");
        if (el) el.scrollIntoView({ behavior: "smooth", block: "center" });
    }
}

document.querySelectorAll(".paranoia-stepper").forEach(function (btn) {
    btn.addEventListener("click", function () {
        var target = document.getElementById(this.dataset.target);
        var val = parseInt(target.value, 10) || 0;
        var dir = this.dataset.dir;
        var min = parseInt(target.min, 10);
        var max = parseInt(target.max, 10);
        if (dir === "up" && val < max) target.value = val + 1;
        if (dir === "down" && val > min) target.value = val - 1;
        highlightActivePreset();
    });
});

async function loadParanoiaConfig() {
    try {
        const res = await apiFetch('/api/waf/paranoia');
        if (!res.ok) return;
        const payload = await res.json();
        const data = payload?.data;
        if (!data) return;
        document.getElementById('paranoia-level').value = data.paranoia;
        document.getElementById('blocking-paranoia').value = data.blocking_paranoia;
        document.getElementById('anomaly-inbound').value = data.anomaly_inbound;
        const toggle = document.getElementById('rule-engine-enabled');
        if (toggle) {
            toggle.checked = data.rule_engine === 'On';
            if (!toggle.hasAttribute('data-listener-added')) {
                toggle.addEventListener('change', (e) => {
                    const isOn = e.target.checked;
                    showConfirm(
                        'Layer 1 Blocking',
                        isOn ? 'Enable WAF blocking? Matching requests will be blocked.' : 'Disable WAF blocking? Suspicious requests will only be detected, not blocked.',
                        () => {
                            updateParanoiaInputsState();
                            saveParanoiaConfig();
                        },
                        () => {
                            e.target.checked = !isOn;
                            updateParanoiaInputsState();
                        }
                    );
                });
                toggle.setAttribute('data-listener-added', 'true');
            }
        }
        if (data.layer2_block_threshold !== undefined) {
            const slider = document.getElementById('layer2-threshold');
            const val = document.getElementById('layer2-threshold-val');
            if (slider) slider.value = Math.round(data.layer2_block_threshold * 100);
            if (val) val.textContent = Math.round(data.layer2_block_threshold * 100) + '%';
        }
        updateParanoiaInputsState();
        highlightActivePreset();
    } catch (e) {
        console.error('Failed to load paranoia config', e);
    }
}

function updateParanoiaInputsState() {
    const toggle = document.getElementById('rule-engine-enabled');
    const isBlocking = toggle && toggle.checked;
    const inputs = [
        document.getElementById('paranoia-level'),
        document.getElementById('blocking-paranoia'),
        document.getElementById('anomaly-inbound'),
        document.querySelector('.paranoia-stepper')
    ];
    const rows = document.querySelectorAll('.paranoia-row');
    const presets = document.querySelector('.paranoia-presets');
    const saveBtn = document.getElementById('paranoia-save-btn');

    if (isBlocking) {
        inputs.forEach(el => { if (el) el.removeAttribute('readonly'); if (el) el.removeAttribute('disabled'); });
        document.querySelectorAll('.paranoia-stepper').forEach(el => el.removeAttribute('disabled'));
        document.querySelectorAll('.paranoia-row').forEach(el => el.style.opacity = '1');
        if (presets) presets.style.opacity = '1';
        if (saveBtn) saveBtn.removeAttribute('disabled');
    } else {
        inputs.forEach(el => { if (el) el.setAttribute('readonly', ''); if (el) el.setAttribute('disabled', ''); });
        document.querySelectorAll('.paranoia-stepper').forEach(el => el.setAttribute('disabled', ''));
        document.querySelectorAll('.paranoia-row').forEach(el => el.style.opacity = '0.5');
        if (presets) presets.style.opacity = '0.5';
        if (saveBtn) saveBtn.setAttribute('disabled', '');
    }
}

let _savingParanoia = false;

async function saveParanoiaConfig() {
    if (_savingParanoia) return;
    _savingParanoia = true;
    const paranoia = parseInt(document.getElementById('paranoia-level').value, 10);
    const blocking = parseInt(document.getElementById('blocking-paranoia').value, 10);
    const anomaly = parseInt(document.getElementById('anomaly-inbound').value, 10);
    const toggle = document.getElementById('rule-engine-enabled');
    const ruleEngine = toggle && toggle.checked ? 'On' : 'DetectionOnly';
    const layer2Threshold = parseInt(document.getElementById('layer2-threshold').value, 10) / 100;

    try {
        const res = await apiFetch('/api/waf/paranoia', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                paranoia: paranoia,
                blocking_paranoia: blocking,
                anomaly_inbound: anomaly,
                rule_engine: ruleEngine
            })
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${res.status}`);
        }
        const payload = await res.json();
        showModal('WAF Updated', `Paranoia level set to ${payload.data.paranoia}. WAF restarting...`);
    } catch (e) {
        showModal('Error', e.message || 'Failed to save WAF config.', 'error');
    }

    try {
        await saveLayer2Threshold();
    } catch (e) {
        console.error('Failed to update layer2 threshold', e);
    } finally {
        _savingParanoia = false;
    }
}

function highlightActivePreset() {
    const paranoia = parseInt(document.getElementById('paranoia-level')?.value, 10);
    const blocking = parseInt(document.getElementById('blocking-paranoia')?.value, 10);
    const anomaly = parseInt(document.getElementById('anomaly-inbound')?.value, 10);

    const presets = {
        1: { p: 1, b: 1, a: 12 },
        2: { p: 2, b: 2, a: 8 },
        3: { p: 3, b: 3, a: 5 },
        4: { p: 4, b: 4, a: 3 }
    };

    let activePreset = 'custom';
    for (const [level, vals] of Object.entries(presets)) {
        if (vals.p === paranoia && vals.b === blocking && vals.a === anomaly) {
            activePreset = level;
            break;
        }
    }

    document.querySelectorAll('.paranoia-presets .btn').forEach(btn => {
        const preset = btn.dataset.preset;
        if (preset === activePreset) {
            btn.classList.add('active');
            btn.style.backgroundColor = '#fff';
            btn.style.borderColor = '#ff570a';
            btn.style.color = '#ff570a';
        } else {
            btn.classList.remove('active');
            btn.style.backgroundColor = '';
            btn.style.borderColor = '';
            btn.style.color = '';
        }
    });
}

document.querySelectorAll(".paranoia-presets .btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
        var level = parseInt(this.dataset.preset, 10);
        if (isNaN(level)) return;
        document.getElementById("paranoia-level").value = level;
        document.getElementById("blocking-paranoia").value = level;
        document.getElementById("anomaly-inbound").value = level === 1 ? 12 : (level === 2 ? 8 : (level === 3 ? 5 : 3));
        highlightActivePreset();
    });
});

const LAYER2_WARNING_TITLE = 'Enable Layer-2 Blocking?';
const LAYER2_WARNING_BODY = 'Layer-2 blocking uses a machine learning model to detect attacks that bypass the Coraza WAF (Layer-1). Unlike Layer-1, which combines deterministic Coraza rules with ML for false-positive reduction, Layer-2 is a pure ML classifier. It may produce false positives and block legitimate traffic. Only enable this if you understand the risk and have reviewed the model\'s performance on your traffic.';

async function saveLayer2Config(enabled) {
    try {
        const res = await apiFetch('/api/waf/layer2', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enabled })
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'HTTP ' + res.status);
        }
        showModal('Layer-2 Updated', enabled
            ? 'Layer-2 ML blocking has been enabled. Requests flagged by the ML model will be blocked.'
            : 'Layer-2 ML blocking has been disabled.');
    } catch (e) {
        showModal('Error', e.message || 'Failed to update Layer-2 config.', 'error');
    }
}

const layer2Toggle = document.getElementById('layer2-enabled');
if (layer2Toggle) {
    layer2Toggle.addEventListener('change', function () {
        if (this.checked) {
            this.checked = false;
            showConfirm(LAYER2_WARNING_TITLE, LAYER2_WARNING_BODY, () => {
                layer2Toggle.checked = true;
                saveLayer2Config(true);
            });
        } else {
            saveLayer2Config(false);
        }
    });
}

const layer2ThresholdSlider = document.getElementById('layer2-threshold');
const layer2ThresholdVal = document.getElementById('layer2-threshold-val');
if (layer2ThresholdSlider && layer2ThresholdVal) {
    layer2ThresholdSlider.addEventListener('input', function () {
        layer2ThresholdVal.textContent = this.value + '%';
    });
    layer2ThresholdSlider.addEventListener('change', function () {
        layer2ThresholdVal.textContent = this.value + '%';
        saveLayer2Threshold(true);
    });
}

async function loadLayer2Threshold() {
    try {
        const res = await apiFetch('/api/waf/layer2/threshold');
        if (!res.ok) return;
        const payload = await res.json();
        const threshold = payload?.data?.layer2_block_threshold;
        if (threshold !== undefined) {
            const val = Math.round(threshold * 100);
            if (layer2ThresholdSlider) layer2ThresholdSlider.value = val;
            if (layer2ThresholdVal) layer2ThresholdVal.textContent = val + '%';
        }
    } catch (e) {
        console.error('Failed to load layer2 threshold', e);
    }
}

async function saveLayer2Threshold(silent) {
    const slider = document.getElementById('layer2-threshold');
    if (!slider) return;
    const threshold = parseInt(slider.value, 10) / 100;

    try {
        const res = await apiFetch('/api/waf/layer2/threshold', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ layer2_block_threshold: threshold })
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${res.status}`);
        }
        if (!silent) {
            showModal('Layer-2 Threshold Updated', `Block threshold set to ${Math.round(threshold * 100)}%.`);
        }
    } catch (e) {
        if (!silent) {
            showModal('Error', e.message || 'Failed to update layer2 threshold.', 'error');
        } else {
            console.error('Failed to save layer2 threshold', e);
        }
    }
}
