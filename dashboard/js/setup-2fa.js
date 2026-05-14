(async function () {
    const alertBox = document.getElementById('alert');

    function showAlert(msg, isError) {
        alertBox.textContent = msg;
        alertBox.className = 'signin-alert ' + (isError ? 'signin-alert-error' : 'signin-alert-success');
        alertBox.style.display = 'block';
    }

    function setStep(n) {
        [1, 2, 3].forEach(i => {
            document.getElementById('step-' + i).classList.toggle('active', i === n);
            const dot = document.getElementById('dot-' + i);
            dot.classList.toggle('active', i === n);
            dot.classList.toggle('done', i < n);
        });
        alertBox.style.display = 'none';
    }

    try {
        const res = await apiFetch('/api/v1/auth/2fa/setup', { method: 'POST' });
        const data = await res.json();
        if (!res.ok) {
            showAlert(data.error || 'Failed to generate 2FA setup.', true);
            return;
        }
        document.getElementById('qr-loading').style.display = 'none';
        const img = document.getElementById('qr-image');
        img.src = data.qr_code;
        img.style.display = 'inline-block';
        document.getElementById('manual-key').textContent = data.manual_key;
    } catch (err) {
        showAlert('Failed to load 2FA setup. Make sure you are signed in.', true);
        return;
    }

    document.getElementById('next-to-verify').addEventListener('click', () => setStep(2));

    let recoveryCodes = [];

    document.getElementById('verify-form').addEventListener('submit', async function (e) {
        e.preventDefault();
        alertBox.style.display = 'none';

        const code = document.getElementById('totp-code').value.trim();
        if (code.length !== 6) {
            showAlert('Enter the 6-digit code from your authenticator app.', true);
            return;
        }

        const btn = document.getElementById('verify-btn');
        const loading = document.getElementById('loading-dots');
        btn.disabled = true;
        loading.style.display = 'flex';

        try {
            const res = await apiFetch('/api/v1/auth/2fa/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code }),
            });
            const data = await res.json();

            if (!res.ok) {
                showAlert(data.error || 'Verification failed.', true);
                btn.disabled = false;
                loading.style.display = 'none';
                return;
            }

            recoveryCodes = data.recovery_codes || [];
            renderRecoveryCodes(recoveryCodes);
            setStep(3);
        } catch (_) {
            showAlert('Network error. Please try again.', true);
            btn.disabled = false;
            loading.style.display = 'none';
        }
    });

    function renderRecoveryCodes(codes) {
        const container = document.getElementById('recovery-codes');
        container.innerHTML = codes.map(c =>
            `<div class="recovery-code">${c}</div>`
        ).join('');
    }

    document.getElementById('copy-codes-btn').addEventListener('click', function () {
        navigator.clipboard.writeText(recoveryCodes.join('\n')).then(() => {
            this.textContent = 'Copied!';
            setTimeout(() => { this.textContent = 'Copy All Codes'; }, 2000);
        });
    });

    document.getElementById('done-btn').addEventListener('click', function () {
        window.location.replace('/events');
    });
})();