const API_BASE = 'http://localhost:8082/api';

async function updateStats() {
    try {
        const res = await fetch(`${API_BASE}/stats`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        document.getElementById('stat-total').textContent = data.total_alerts || 0;
        document.getElementById('stat-ai-count').textContent = data.ai_enriched_count || 0;
        document.getElementById('stat-rule').textContent = data.latest_rule || '—';
        
        const priorityEl = document.getElementById('stat-priority');
        if (data.latest_priority && data.latest_priority !== '—') {
            priorityEl.textContent = data.latest_priority;
            priorityEl.className = 'stat-value priority-' + data.latest_priority.toLowerCase();
        } else {
            priorityEl.textContent = '—';
            priorityEl.className = 'stat-value';
        }
    } catch (e) { }
}

async function updateLogs() {
    try {
        const res = await fetch(`${API_BASE}/logs`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (!data.alerts) {
            return;
        }
        const tbody = document.getElementById('logs-body');
        tbody.innerHTML = '';
        data.alerts.forEach((alert, i) => {
            const row = document.createElement('tr');
            row.style.animation = `slideIn 0.2s ease ${i * 0.05}s both`;
            const ts = alert.timestamp ? alert.timestamp.replace(/\//g, '-').replace(' ', 'T') + 'Z' : '-';
            const rules = alert.triggered_rules ? alert.triggered_rules.map(r => `<span class="rule-code">${r}</span>`).join(' ') : '-';
            
            const aiScoreVal = alert.ai_score;
            const aiScore = aiScoreVal !== null && aiScoreVal !== undefined 
                ? `<span class="ai-score">${(aiScoreVal * 100).toFixed(1)}%</span>` 
                : '-';
            const aiPriority = alert.ai_priority 
                ? `<span class="priority-${alert.ai_priority.toLowerCase()}">${alert.ai_priority}</span>` 
                : '-';
            const aiConf = alert.ai_confidence !== null && alert.ai_confidence !== undefined
                ? `${alert.ai_confidence.toFixed(0)}%`
                : '-';
            
            row.innerHTML = `
                <td style="color:var(--fg-muted);">${new Date(ts).toLocaleTimeString()}</td>
                <td>${alert.client_ip}</td>
                <td style="font-family:monospace;font-size:0.75rem;">${alert.uri}</td>
                <td class="anomaly-badge" style="text-align: center;">${alert.anomaly_score}</td>
                <td style="text-align: center;">${rules}</td>
                <td style="text-align: center;">${aiScore}</td>
                <td style="text-align: center;">${aiConf}</td>
                <td style="text-align: center;">${aiPriority}</td>
            `;
            tbody.appendChild(row);
        });
    } catch (e) { 
        console.error('Error in updateLogs:', e); 
    }
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