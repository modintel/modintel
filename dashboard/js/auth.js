(() => {
    'use strict';

    const SIGNIN_ROUTE = '/signin';
    let refreshPromise = null;

    function getUser() {
        try {
            return JSON.parse(localStorage.getItem('user'));
        } catch (_) {
            return null;
        }
    }

    function clearAuth() {
        localStorage.removeItem('user');
    }

    function getAccessToken() {
        return null;
    }

    async function requireAuth() {
        const user = getUser();
        if (user) {
            return true;
        }

        if (window.location.pathname === SIGNIN_ROUTE) {
            return true;
        }

        try {
            const resp = await fetch('/api/v1/auth/me', { credentials: 'same-origin' });
            if (resp.ok) {
                const data = await resp.json();
                const userData = data.data || data;
                localStorage.setItem('user', JSON.stringify(userData.user || userData));
                return true;
            }
        } catch (_) {
        }

        window.location.href = SIGNIN_ROUTE;
        return false;
    }

    async function apiFetch(url, options = {}) {
        let response = await fetch(url, {
            ...options,
            headers: options.headers || {},
            credentials: 'same-origin',
        });

        if (response.status === 401 && window.location.pathname !== SIGNIN_ROUTE) {
            const refreshed = await tryRefreshToken();
            if (refreshed) {
                response = await fetch(url, {
                    ...options,
                    headers: options.headers || {},
                    credentials: 'same-origin',
                });
                return response;
            }
            clearAuth();
            window.location.href = SIGNIN_ROUTE;
            throw new Error('HTTP 401');
        }

        return response;
    }

    async function tryRefreshToken() {
        if (refreshPromise) return refreshPromise;
        refreshPromise = (async () => {
            try {
                const resp = await fetch('/api/v1/auth/refresh', {
                    method: 'POST',
                    credentials: 'same-origin',
                });
                if (resp.ok) {
                    const data = await resp.json();
                    if (data.success) return true;
                }
                return false;
            } catch (_) {
                return false;
            } finally {
                refreshPromise = null;
            }
        })();
        return refreshPromise;
    }

    async function logout() {
        try {
            await fetch('/api/v1/auth/logout', {
                method: 'POST',
                credentials: 'same-origin',
            });
        } catch (_) {
        }
        clearAuth();
        if (window.location.pathname !== SIGNIN_ROUTE) {
            window.location.href = SIGNIN_ROUTE;
        }
    }

    async function revokeAllSessions() {
        await apiFetch('/api/v1/auth/sessions/revoke-all', { method: 'POST' });
    }

    function attachLogoutButtons() {
        const selectors = ['#logout-btn', '.logout-btn', '[data-action="logout"]'];
        const seen = new Set();
        selectors.forEach((selector) => {
            document.querySelectorAll(selector).forEach((el) => {
                if (seen.has(el)) return;
                seen.add(el);
                el.addEventListener('click', async (event) => {
                    event.preventDefault();
                    showConfirm(
                        'Logout',
                        'Are you sure you want to log out?',
                        async () => { await logout(); }
                    );
                });
            });
        });
    }

    window.getAccessToken = getAccessToken;
    window.getUser = getUser;
    window.clearAuth = clearAuth;
    window.requireAuth = requireAuth;
    window.apiFetch = apiFetch;
    window.logout = logout;
    window.revokeAllSessions = revokeAllSessions;
    window.attachLogoutButtons = attachLogoutButtons;
    window.tryRefreshToken = tryRefreshToken;
})();
