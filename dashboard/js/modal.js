function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function showModal(title, message, type = 'info') {
    let modal = document.getElementById('app-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'app-modal';
        modal.className = 'modal';
        document.body.appendChild(modal);
    }

    modal.innerHTML = `
        <div class="modal-backdrop"></div>
        <div class="modal-content">
            <h3 id="modal-title"></h3>
            <p id="modal-message"></p>
            <div class="modal-actions">
                <button class="btn btn-primary" id="modal-close">OK</button>
            </div>
        </div>
    `;

    const titleEl = document.getElementById('modal-title');
    const messageEl = document.getElementById('modal-message');
    const closeBtn = document.getElementById('modal-close');

    titleEl.textContent = title;
    messageEl.innerHTML = message;

    titleEl.className = type === 'error' ? 'modal-title-error' : '';
    closeBtn.className = type === 'error' ? 'btn btn-danger' : 'btn btn-primary';

    modal.classList.add('open');

    document.getElementById('modal-close').onclick = () => modal.classList.remove('open');
    modal.querySelector('.modal-backdrop').onclick = () => modal.classList.remove('open');
}

function showConfirm(title, message, onConfirm, onCancel) {
    let modal = document.getElementById('app-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'app-modal';
        modal.className = 'modal';
        document.body.appendChild(modal);
    }

    modal.innerHTML = `
        <div class="modal-backdrop"></div>
        <div class="modal-content">
            <h3>${escapeHtml(title)}</h3>
            <p>${escapeHtml(message)}</p>
            <div class="modal-actions">
                <button class="btn btn-secondary" id="modal-cancel">Cancel</button>
                <button class="btn btn-primary" id="modal-confirm">Confirm</button>
            </div>
        </div>
    `;

    modal.classList.add('open');

    document.getElementById('modal-confirm').onclick = () => {
        modal.classList.remove('open');
        if (onConfirm) onConfirm();
    };

    document.getElementById('modal-cancel').onclick = () => {
        modal.classList.remove('open');
        if (onCancel) onCancel();
    };

    modal.querySelector('.modal-backdrop').onclick = () => {
        modal.classList.remove('open');
        if (onCancel) onCancel();
    };
}

function showPrompt(title, message, defaultValue, onConfirm, onCancel) {
    let modal = document.getElementById('app-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'app-modal';
        modal.className = 'modal';
        document.body.appendChild(modal);
    }

    modal.innerHTML = `
        <div class="modal-backdrop"></div>
        <div class="modal-content">
            <h3 id="modal-title"></h3>
            <p id="modal-message"></p>
            <input type="text" id="modal-input" class="modal-input" value="${escapeHtml(defaultValue) || ''}" />
            <div class="modal-actions">
                <button class="btn btn-secondary" id="modal-cancel">Cancel</button>
                <button class="btn btn-primary" id="modal-confirm">OK</button>
            </div>
        </div>
    `;

    const titleEl = document.getElementById('modal-title');
    const messageEl = document.getElementById('modal-message');
    const inputEl = document.getElementById('modal-input');

    titleEl.textContent = title;
    messageEl.innerHTML = message;

    modal.classList.add('open');

    inputEl.focus();
    inputEl.select();

    document.getElementById('modal-confirm').onclick = () => {
        modal.classList.remove('open');
        if (onConfirm) onConfirm(inputEl.value);
    };

    document.getElementById('modal-cancel').onclick = () => {
        modal.classList.remove('open');
        if (onCancel) onCancel();
    };

    modal.querySelector('.modal-backdrop').onclick = () => {
        modal.classList.remove('open');
        if (onCancel) onCancel();
    };
}