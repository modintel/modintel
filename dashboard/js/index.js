const API_BASE = 'http://localhost:8082/api';

async function updateStats() {
    try {
        const res = await fetch(`${API_BASE}/stats`);
        const data = await res.json();
        document.getElementById('stat-total').textContent = data.total_alerts;
        document.getElementById('stat-rule').textContent = data.latest_rule;
    } catch (e) { }
}

async function updateLogs() {
    try {
        const res = await fetch(`${API_BASE}/logs`);
        const data = await res.json();
        const tbody = document.getElementById('logs-body');
        tbody.innerHTML = '';
        data.alerts.forEach((alert, i) => {
            const row = document.createElement('tr');
            row.style.animation = `slideIn 0.2s ease ${i * 0.05}s both`;
            const ts = alert.timestamp ? alert.timestamp.replace(/\//g, '-').replace(' ', 'T') + 'Z' : '-';
            const rules = alert.triggered_rules ? alert.triggered_rules.map(r => `<span class="rule-code">${r}</span>`).join(' ') : '-';
            row.innerHTML = `
                <td style="color:var(--fg-muted);">${new Date(ts).toLocaleTimeString()}</td>
                <td>${alert.client_ip}</td>
                <td style="font-family:monospace;font-size:0.75rem;">${alert.uri}</td>
                <td class="anomaly-badge">${alert.anomaly_score}</td>
                <td>${rules}</td>
            `;
            tbody.appendChild(row);
        });
    } catch (e) { }
}

setInterval(() => { updateStats(); updateLogs(); }, 2000);
updateStats(); updateLogs();

function toggleSidebar() {
    const panelDefault = document.getElementById('panel-default');
    const sidebarContent = document.getElementById('sidebar-content');
    const isOpen = sidebarContent.classList.contains('visible');

    if (isOpen) {
        sidebarContent.classList.remove('visible');
        panelDefault.classList.remove('hidden');
    } else {
        sidebarContent.classList.add('visible');
        panelDefault.classList.add('hidden');
    }
}
