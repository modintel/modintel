(async function () {
    // If users already exist, redirect to sign-in immediately
    try {
        const res = await fetch('/api/v1/auth/status');
        if (res.ok) {
            const data = await res.json();
            if (data.has_users) {
                window.location.replace('/signin');
                return;
            }
        }
    } catch (_) {
        // Network error — let the form render anyway
    }

    const form      = document.getElementById('setup-form');
    const alertBox  = document.getElementById('alert');
    const loadingEl = document.getElementById('loading-dots');
    const submitBtn = document.getElementById('setup-btn');

    function showAlert(msg, isError) {
        alertBox.textContent = msg;
        alertBox.className = 'signin-alert ' + (isError ? 'signin-alert-error' : 'signin-alert-success');
        alertBox.style.display = 'block';
    }

    function hideAlert() {
        alertBox.style.display = 'none';
    }

    function setLoading(loading) {
        loadingEl.style.display = loading ? 'flex' : 'none';
        submitBtn.disabled = loading;
        submitBtn.textContent = loading ? 'Creating account…' : 'Create Admin Account';
    }

    form.addEventListener('submit', async function (e) {
        e.preventDefault();
        hideAlert();

        const email    = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value;
        const confirm  = document.getElementById('confirm-password').value;
        const firstName = document.getElementById('first-name').value.trim();
        const lastName  = document.getElementById('last-name').value.trim();

        if (!email || !password) {
            showAlert('Email and password are required.', true);
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
            const res = await fetch('/api/v1/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email,
                    password,
                    first_name: firstName,
                    last_name:  lastName,
                }),
            });

            const data = await res.json();

            if (!res.ok) {
                showAlert(data.error || 'Registration failed.', true);
                setLoading(false);
                return;
            }

            showAlert('Admin account created! Redirecting to sign in…', false);
            setTimeout(() => {
                window.location.replace('/signin');
            }, 1500);

        } catch (err) {
            showAlert('Network error. Please try again.', true);
            setLoading(false);
        }
    });
})();
