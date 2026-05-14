(function () {
    const twoFAToken = sessionStorage.getItem('2fa_token');

    const alertBox  = document.getElementById('alert');
    const loadingEl = document.getElementById('loading-dots');

    function showAlert(msg, isError) {
        alertBox.textContent = msg;
        alertBox.className = 'signin-alert ' + (isError ? 'signin-alert-error' : 'signin-alert-success');
        alertBox.style.display = 'block';
    }

    function setLoading(loading) {
        loadingEl.style.display = loading ? 'flex' : 'none';
    }

    if (!twoFAToken) {
        showAlert('Session expired. Please sign in again.', true);
        document.getElementById('twofa-form').style.display = 'none';
        setTimeout(() => window.location.replace('/signin'), 2000);
        return;
    }

    document.getElementById('twofa-form').addEventListener('submit', async function (e) {
        e.preventDefault();
        alertBox.style.display = 'none';

        const code = document.getElementById('code').value.trim();
        if (code.length !== 6) {
            showAlert('Enter the 6-digit code from your authenticator app.', true);
            return;
        }

        const btn = document.getElementById('submit-btn');
        btn.disabled = true;
        setLoading(true);

        try {
            const res = await fetch('/api/v1/auth/2fa/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ '2fa_token': twoFAToken, code }),
            });
            const data = await res.json();

            if (!res.ok) {
                showAlert(data.error || 'Invalid code.', true);
                btn.disabled = false;
                setLoading(false);
                return;
            }

            sessionStorage.removeItem('2fa_token');
            window.location.replace('/events');
        } catch (_) {
            showAlert('Network error. Please try again.', true);
            btn.disabled = false;
            setLoading(false);
        }
    });

    document.getElementById('use-recovery-link').addEventListener('click', function (e) {
        e.preventDefault();
        document.getElementById('twofa-form').style.display = 'none';
        document.getElementById('recovery-form').style.display = 'block';
        alertBox.style.display = 'none';
    });

    document.getElementById('back-to-code-link').addEventListener('click', function (e) {
        e.preventDefault();
        document.getElementById('recovery-form').style.display = 'none';
        document.getElementById('twofa-form').style.display = 'block';
        alertBox.style.display = 'none';
    });

    document.getElementById('recovery-form').addEventListener('submit', async function (e) {
        e.preventDefault();
        alertBox.style.display = 'none';

        const recoveryCode = document.getElementById('recovery-code').value.trim();
        if (!recoveryCode) {
            showAlert('Enter your recovery code.', true);
            return;
        }

        const btn = document.getElementById('recovery-btn');
        btn.disabled = true;
        setLoading(true);

        try {
            const res = await fetch('/api/v1/auth/2fa/recover', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ '2fa_token': twoFAToken, recovery_code: recoveryCode }),
            });
            const data = await res.json();

            if (!res.ok) {
                showAlert(data.error || 'Invalid recovery code.', true);
                btn.disabled = false;
                setLoading(false);
                return;
            }

            sessionStorage.removeItem('2fa_token');
            if (data.data && data.data.codes_remaining === 0) {
                showAlert('All recovery codes used. Please set up new ones in Settings.', false);
                setTimeout(() => window.location.replace('/events'), 2000);
            } else {
                window.location.replace('/events');
            }
        } catch (_) {
            showAlert('Network error. Please try again.', true);
            btn.disabled = false;
            setLoading(false);
        }
    });
})();