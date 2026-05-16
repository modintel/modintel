(() => {
    'use strict';

    const SIGNIN_ROUTE = '/signin';

    function getAccessToken() {
        return localStorage.getItem('access_token');
    }

    function clearAuth() {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
    }

    function requireAuth() {
        const token = getAccessToken();
        if (!token && window.location.pathname !== SIGNIN_ROUTE) {
            window.location.href = SIGNIN_ROUTE;
            return false;
        }
        return true;
    }

    async function apiFetch(url, options = {}) {
        const token = getAccessToken();
        const headers = new Headers(options.headers || {});
        if (token) {
            headers.set('Authorization', `Bearer ${token}`);
        }

        const response = await fetch(url, {
            ...options,
            headers,
        });

        if ((response.status === 401 || response.status === 403) && window.location.pathname !== SIGNIN_ROUTE) {
            clearAuth();
            window.location.href = SIGNIN_ROUTE;
            throw new Error(`HTTP ${response.status}`);
        }

        return response;
    }

    async function logout() {
        const refreshToken = localStorage.getItem('refresh_token');
        if (refreshToken) {
            try {
                await apiFetch('/api/v1/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ refresh_token: refreshToken }),
                });
            } catch (_) {
            }
        }

        clearAuth();
        if (window.location.pathname !== SIGNIN_ROUTE) {
            window.location.href = SIGNIN_ROUTE;
        }
    }

    async function revokeAllSessions() {
        await apiFetch('/api/v1/auth/sessions/revoke-all', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({}),
        });
    }

    function attachLogoutButtons() {
        const selectors = ['#logout-btn', '.logout-btn', '[data-action="logout"]'];
        const seen = new Set();
        selectors.forEach((selector) => {
            document.querySelectorAll(selector).forEach((el) => {
                if (seen.has(el)) {
                    return;
                }
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
    window.clearAuth = clearAuth;
    window.requireAuth = requireAuth;
    window.apiFetch = apiFetch;
    window.logout = logout;
    window.revokeAllSessions = revokeAllSessions;
    window.attachLogoutButtons = attachLogoutButtons;
})();
