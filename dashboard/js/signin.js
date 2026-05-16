(function() {
    'use strict';

    const signinForm = document.getElementById('signin-form');
    const alertBox = document.getElementById('alert');
    const signinBtn = document.getElementById('signin-btn');
    const loadingDots = document.getElementById('loading-dots');

    const AUTH_SERVICE_URL = '/api/v1/auth/login';
    const DASHBOARD_URL = '/events';

    function showAlert(type, message) {
        alertBox.className = `signin-alert signin-alert-${type}`;
        alertBox.textContent = message;
        alertBox.style.display = 'block';
    }

    function hideAlert() {
        alertBox.style.display = 'none';
    }

    function setLoading(loading) {
        if (loading) {
            signinBtn.textContent = 'Signing in...';
            signinBtn.disabled = true;
        } else {
            signinBtn.textContent = 'Sign In';
            signinBtn.disabled = false;
        }
    }

    function storeAuthData(token, user, remember) {
        localStorage.setItem('access_token', token);
        if (remember && user && user.refresh_token) {
            localStorage.setItem('refresh_token', user.refresh_token);
        }
        localStorage.setItem('user', JSON.stringify(user));
    }

    function handleLoginSuccess(data, remember) {
        storeAuthData(data.access_token, {
            ...data.user,
            refresh_token: data.refresh_token,
        }, remember);
        hideAlert();
        signinForm.style.display = 'none';
        if (loadingDots) loadingDots.style.display = 'flex';

        setTimeout(() => {
            window.location.href = DASHBOARD_URL;
        }, 500);
    }

    async function authenticate(email, password, remember) {
        try {
            const response = await fetch(AUTH_SERVICE_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password }),
            });

            const data = await response.json();

            if (response.ok && data.success) {
                handleLoginSuccess(data.data, remember);
            } else {
                showAlert('danger', data.error || 'Invalid credentials. Please try again.');
                setLoading(false);
            }
        } catch (error) {
            console.error('Auth service error:', error);
            showAlert('danger', 'Authentication service unavailable. Please try again shortly.');
            setLoading(false);
        }
    }

    function handleFormSubmit(e) {
        e.preventDefault();

        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const remember = document.getElementById('remember')?.checked || false;

        hideAlert();
        setLoading(true);

        authenticate(email, password, remember);
    }

    window.showComingSoon = function(e) {
        if (e) e.preventDefault();
        showAlert('danger', 'Feature coming soon. Please use email sign in.');
    };

    function bindComingSoonLinks() {
        const forgotPasswordLink = document.getElementById('forgot-password-link');
        if (forgotPasswordLink) {
            forgotPasswordLink.addEventListener('click', window.showComingSoon);
        }

        const requestAccessLink = document.getElementById('request-access-link');
        if (requestAccessLink) {
            requestAccessLink.addEventListener('click', window.showComingSoon);
        }
    }

    async function checkExistingAuth() {
        const token = localStorage.getItem('access_token');
        if (!token) {
            return;
        }

        try {
            const response = await fetch('/api/v1/auth/me', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            });

            if (response.ok) {
                window.location.href = DASHBOARD_URL;
                return;
            }
        } catch (_) {
        }

        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
    }

    async function init() {
        await checkExistingAuth();

        if (signinForm) {
            signinForm.addEventListener('submit', handleFormSubmit);
        }

        const emailInput = document.getElementById('email');
        if (emailInput) {
            setTimeout(() => emailInput.focus(), 100);
        }

        bindComingSoonLinks();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
