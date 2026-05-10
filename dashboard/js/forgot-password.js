(function () {
    const form      = document.getElementById('forgot-form');
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
        submitBtn.textContent = loading ? 'Sending…' : 'Send Reset Link';
    }

    form.addEventListener('submit', async function (e) {
        e.preventDefault();
        alertBox.style.display = 'none';

        const email = document.getElementById('email').value.trim();
        if (!email) {
            showAlert('Email is required.', true);
            return;
        }

        setLoading(true);

        try {
            const res = await fetch('/api/v1/auth/reset-password/request', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email }),
            });

            // Always show success — backend never reveals if email exists
            showAlert('If that email is registered, a reset link has been sent. Check your inbox.', false);
            form.reset();
        } catch (_) {
            showAlert('Network error. Please try again.', true);
        } finally {
            setLoading(false);
        }
    });
})();
