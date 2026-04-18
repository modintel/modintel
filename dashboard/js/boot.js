(function () {
    'use strict';

    if (typeof requireAuth === 'function') {
        const ok = requireAuth();
        if (!ok) {
            return;
        }
    }

    if (typeof attachLogoutButtons === 'function' && document.body?.dataset?.attachLogout === 'true') {
        attachLogoutButtons();
    }
})();
