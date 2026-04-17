// Sign In Page JavaScript

(function() {
    'use strict';

    // DOM Elements
    const signinForm = document.getElementById('signin-form');
    const alertBox = document.getElementById('alert');
    const signinBtn = document.getElementById('signin-btn');

    // Configuration
    const AUTH_SERVICE_URL = '/api/v1/auth/login';
    const DASHBOARD_URL = '/events';

    /**
     * Show alert message
     * @param {string} type - 'danger' or 'success'
     * @param {string} message - The message to display
     */
    function showAlert(type, message) {
        alertBox.className = `signin-alert signin-alert-${type}`;
        alertBox.textContent = message;
        alertBox.style.display = 'block';
    }

    /**
     * Hide alert message
     */
    function hideAlert() {
        alertBox.style.display = 'none';
    }

    /**
     * Set button loading state
     * @param {boolean} loading - Whether the button is loading
     */
    function setLoading(loading) {
        if (loading) {
            signinBtn.textContent = 'Signing in...';
            signinBtn.disabled = true;
        } else {
            signinBtn.textContent = 'Sign In';
            signinBtn.disabled = false;
        }
    }

    /**
     * Store authentication data
     * @param {string} token - Access token
     * @param {object} user - User data
     */
    function storeAuthData(token, user) {
        localStorage.setItem('access_token', token);
        if (user && user.refresh_token) {
            localStorage.setItem('refresh_token', user.refresh_token);
        }
        localStorage.setItem('user', JSON.stringify(user));
    }

    /**
     * Handle successful login
     * @param {object} data - Response data from auth service
     */
    function handleLoginSuccess(data) {
        storeAuthData(data.access_token, {
            ...data.user,
            refresh_token: data.refresh_token,
        });
        showAlert('success', 'Sign in successful! Redirecting...');
        
        setTimeout(() => {
            window.location.href = DASHBOARD_URL;
        }, 500);
    }

    /**
     * Handle demo mode login (fallback when auth service is unavailable)
     * @param {string} email - User email
     */
    function handleDemoLogin(email) {
        const isAdmin = email.includes('admin');
        const demoToken = 'demo_token_' + Date.now();
        const demoUser = {
            id: 'demo_user_' + Date.now(),
            email: email,
            role: isAdmin ? 'admin' : 'analyst',
            first_name: 'Demo',
            last_name: 'User'
        };

        storeAuthData(demoToken, demoUser);
        showAlert('success', 'Demo mode: Sign in successful! Redirecting...');
        
        setTimeout(() => {
            window.location.href = DASHBOARD_URL;
        }, 800);
    }

    /**
     * Attempt to authenticate with the auth service
     * @param {string} email - User email
     * @param {string} password - User password
     */
    async function authenticate(email, password) {
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
                handleLoginSuccess(data.data);
            } else {
                showAlert('danger', data.error || 'Invalid credentials. Please try again.');
                setLoading(false);
            }
        } catch (error) {
            console.error('Auth service error:', error);
            
            // Fallback to demo mode for development
            if (email === 'admin@modintel.io' || email === 'analyst@modintel.io') {
                handleDemoLogin(email);
            } else {
                showAlert('danger', 'Authentication service unavailable. Try admin@modintel.io or analyst@modintel.io with any password for demo.');
                setLoading(false);
            }
        }
    }

    /**
     * Handle form submission
     * @param {Event} e - Form submit event
     */
    function handleFormSubmit(e) {
        e.preventDefault();

        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;

        hideAlert();
        setLoading(true);

        authenticate(email, password);
    }

    /**
     * Show coming soon notification
     * @param {Event} e - Click event (optional)
     */
    window.showComingSoon = function(e) {
        if (e) e.preventDefault();
        showAlert('danger', 'Feature coming soon. Please use email sign in.');
    };

    /**
     * Check if user is already authenticated
     */
    function checkExistingAuth() {
        const token = localStorage.getItem('access_token');
        if (token) {
            // User already has a token, redirect to dashboard
            window.location.href = DASHBOARD_URL;
        }
    }

    /**
     * Initialize the sign in page
     */
    function init() {
        // Check for existing authentication
        checkExistingAuth();

        // Attach form submit handler
        if (signinForm) {
            signinForm.addEventListener('submit', handleFormSubmit);
        }

        // Focus email input on page load
        const emailInput = document.getElementById('email');
        if (emailInput) {
            setTimeout(() => emailInput.focus(), 100);
        }
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();

