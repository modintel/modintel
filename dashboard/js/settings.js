let originalDisplayName = '';
let originalEmail = '';

async function loadProfile() {
    try {
        const res = await apiFetch('/api/v1/auth/me');
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }
        const payload = await res.json();
        const user = payload?.data;
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
        const sessions = payload?.data?.sessions || [];
        renderSessions(sessions);
    } catch (err) {
        renderSessions([]);
        showModal('Session Error', 'Failed to load active sessions.', 'error');
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

document.addEventListener('DOMContentLoaded', () => {
    const refreshBtn = document.getElementById('refresh-sessions-btn');
    const revokeAllBtn = document.getElementById('revoke-all-sessions-btn');
    const editBtn = document.getElementById('edit-profile-btn');
    const cancelBtn = document.getElementById('cancel-profile-btn');

    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadSessions);
    }
    if (revokeAllBtn) {
        revokeAllBtn.addEventListener('click', revokeAllSessionsAction);
    }
    if (editBtn) {
        editBtn.addEventListener('click', () => setProfileEditable(true));
    }
    if (cancelBtn) {
        cancelBtn.addEventListener('click', () => setProfileEditable(false));
    }

    loadProfile();
    loadSessions();
});
