(function () {
    const params = new URLSearchParams(window.location.search);
    const token  = params.get('token');

    const alertBox  = document.getElementById('alert');
    const loadingEl = document.getElementById('loading-dots');
    const submitBtn = document.getElementById('accept-btn');
    const form      = document.getElementById('accept-form');

    function showAlert(msg, isError) {
        alertBox.textContent = msg;
        alertBox.className = 'signin-alert ' + (isError ? 'signin-alert-error' : 'signin-alert-success');
        alertBox.style.display = 'block';
    }

    function setLoading(loading) {
        loadingEl.style.display = loading ? 'flex' : 'none';
        submitBtn.disabled = loading;
        submitBtn.textContent = loading ? 'Creating account…' : 'Create Account';
    }

    if (!token) {
        form.style.display = 'none';
        document.getElementById('page-title').textContent = 'Invalid Invitation';
        document.getElementById('page-subtitle').textContent = 'This invitation link is missing a token.';
        showAlert('No invitation token found. Please use the link from your invitation email.', true);
        return;
    }

    form.addEventListener('submit', async function (e) {
        e.preventDefault();
        alertBox.style.display = 'none';

        const password = document.getElementById('password').value;
        const confirm  = document.getElementById('confirm-password').value;
        const firstName = document.getElementById('first-name').value.trim();
        const lastName  = document.getElementById('last-name').value.trim();

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
            const res = await fetch('/api/v1/auth/accept-invite', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    token,
                    password,
                    first_name: firstName,
                    last_name:  lastName,
                }),
            });

            const data = await res.json();

            if (!res.ok) {
                showAlert(data.error || 'Failed to accept invitation.', true);
                setLoading(false);
                return;
            }

            showAlert('Account created! Redirecting to sign in…', false);
            setTimeout(() => {
                window.location.replace('/signin');
            }, 1500);

        } catch (err) {
            showAlert('Network error. Please try again.', true);
            setLoading(false);
        }
    });
})();