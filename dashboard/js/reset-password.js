(async function () {
    const params = new URLSearchParams(window.location.search);
    const token  = params.get('token');

    const form      = document.getElementById('reset-form');
    const alertBox  = document.getElementById('alert');
    const loadingEl = document.getElementById('loading-dots');
    const submitBtn = document.getElementById('submit-btn');

    function showAlert(msg, isError) {
        alertBox.textContent = msg;
        alertBox.className = 'signin-alert ' + (isError ? 'signin-alert-error' : 'signin-alert-success');
        alertBox.style.display = 'block';
    }

    function setLoading(loading) {
        loadingEl.style.display = loading ? 'flex' : 'none';
        submitBtn.disabled = loading;
        submitBtn.textContent = loading ? 'Resetting…' : 'Reset Password';
    }

    // No token — show error
    if (!token) {
        form.style.display = 'none';
        document.getElementById('page-title').textContent = 'Invalid Link';
        document.getElementById('page-subtitle').textContent = 'This reset link is missing a token.';
        showAlert('No reset token found. Please request a new password reset.', true);
        return;
    }

    // Validate token before showing the form
    try {
        const res = await fetch('/api/v1/auth/reset-password/validate?token=' + encodeURIComponent(token));
        if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            form.style.display = 'none';
            document.getElementById('page-title').textContent = 'Link Expired';
            document.getElementById('page-subtitle').textContent = data.error || 'This reset link is no longer valid.';
            showAlert(data.error || 'This reset link has expired or already been used.', true);
            return;
        }
    } catch (_) {
        // Network error — let the form render and fail on submit
    }

    form.addEventListener('submit', async function (e) {
        e.preventDefault();
        alertBox.style.display = 'none';

        const password = document.getElementById('password').value;
        const confirm  = document.getElementById('confirm-password').value;

        if (!password) {
            showAlert('Password is required.', true);
            return;
        }
        if (password !== confirm) {
            showAlert('Passwords do not match.', true);
            return;
        }
        if (password.length < 10) {
            showAlert('Password must be at least 10 characters.', true);
            return;
        }

        setLoading(true);

        try {
            const res = await fetch('/api/v1/auth/reset-password/complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, new_password: password }),
            });

            const data = await res.json();

            if (!res.ok) {
                showAlert(data.error || 'Failed to reset password.', true);
                setLoading(false);
                return;
            }

            showAlert('Password reset successfully! Redirecting to sign in…', false);
            setTimeout(() => {
                window.location.replace('/signin');
            }, 1500);

        } catch (_) {
            showAlert('Network error. Please try again.', true);
            setLoading(false);
        }
    });
})();
