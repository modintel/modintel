const REPORTS_CONFIG_KEY = "modintel.dashboard.config";
const REPORTS_API_BASE = "/api";
const REPORTS_DEFAULT_BASE = window.location.origin;

function getConfig() {
    try {
        const raw = localStorage.getItem(REPORTS_CONFIG_KEY);
        if (!raw) return { reviewApiBase: REPORTS_DEFAULT_BASE };
        const parsed = JSON.parse(raw);
        return { reviewApiBase: parsed.reviewApiBase || REPORTS_DEFAULT_BASE };
    } catch (_) {
        return { reviewApiBase: REPORTS_DEFAULT_BASE };
    }
}

function resolveApiBase() {
    const cfg = getConfig();
    if (!cfg.reviewApiBase) return REPORTS_API_BASE;
    try {
        const current = window.location.origin;
        if (cfg.reviewApiBase === current) {
            return REPORTS_API_BASE;
        }
        return `${cfg.reviewApiBase}/api`;
    } catch (_) {
        return REPORTS_API_BASE;
    }
}

function detectVector(rule) {
    if (!rule) return { key: "other", label: "Other" };
    const code = Number(rule);
    
    if (code >= 913000 && code < 914000) return { key: "scanner", label: "Scanner" };
    if (code >= 920000 && code < 921000) return { key: "protocol", label: "Protocol" };
    if (code >= 921000 && code < 922000) return { key: "protocol", label: "Protocol Attack" };
    if (code >= 930000 && code < 931000) return { key: "lfi", label: "LFI/Traversal" };
    if (code >= 931000 && code < 932000) return { key: "rfi", label: "RFI Attack" };
    if (code >= 932000 && code < 933000) return { key: "cmdi", label: "Command Injection" };
    if (code >= 933000 && code < 934000) return { key: "php", label: "PHP Attack" };
    if (code >= 934000 && code < 935000) return { key: "nosql", label: "NoSQL Injection" };
    if (code >= 941000 && code < 942000) return { key: "xss", label: "XSS" };
    if (code >= 942000 && code < 943000) return { key: "sqli", label: "SQL Injection" };
    if (code >= 943000 && code < 944000) return { key: "session", label: "Session Fixation" };
    if (code >= 949000 && code < 950000) return { key: "anomaly", label: "Anomaly" };
    if (code >= 990000 && code < 991000) return { key: "custom", label: "Custom Rule" };
    
    return { key: "other", label: "Other" };
}

function detectVectorFromRules(rules) {
    if (!rules || rules.length === 0) return detectVector(null);
    
    const votes = {};
    for (const rule of rules) {
        const v = detectVector(rule);
        votes[v.key] = (votes[v.key] || 0) + 1;
    }
    
    const sorted = Object.entries(votes).sort((a, b) => b[1] - a[1]);
    if (sorted.length === 0) return detectVector(null);
    
    const winner = sorted[0][0];
    for (const rule of rules) {
        const v = detectVector(rule);
        if (v.key === winner) return v;
    }
    
    return detectVector(rules[0]);
}

function vectorClass(index) {
    return ["", "v2", "v3", "v4", "v5"][index] || "v5";
}

function renderVectors(alerts) {
    const box = document.getElementById("attack-vectors");
    const counts = new Map();

    alerts.forEach((a) => {
        const rules = a.triggered_rules || [];
        const v = detectVectorFromRules(rules);
        counts.set(v.label, (counts.get(v.label) || 0) + 1);
    });

    const entries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const total = entries.reduce((sum, [, c]) => sum + c, 0) || 1;

    box.innerHTML = "";
    if (!entries.length) {
        box.innerHTML = '<div class="empty-row">No data yet.</div>';
        return;
    }

    entries.forEach(([name, count], i) => {
        const pct = Math.max(4, Math.round((count / total) * 100));
        const row = document.createElement("div");
        row.className = "attack-vector";
        row.innerHTML = `
            <div class="vector-name">${name}</div>
            <div class="vector-bar">
                <div class="vector-fill ${vectorClass(i)}" style="width: ${pct}%;"></div>
            </div>
            <div class="vector-count">${count}</div>
        `;
        box.appendChild(row);
    });
}

function renderTable(alerts) {
    const tbody = document.getElementById("attacks-list");
    tbody.innerHTML = "";

    if (!alerts.length) {
        const tr = document.createElement("tr");
        tr.innerHTML = '<td colspan="5" class="empty-row">No attacks recorded.</td>';
        tbody.appendChild(tr);
        return;
    }

    alerts.slice(0, 50).forEach((a) => {
        const ts = a.timestamp ? a.timestamp.replace(/\//g, "-").replace(" ", "T") + "Z" : "";
        const time = ts ? new Date(ts).toLocaleTimeString() : "-";
        const rule = (a.triggered_rules && a.triggered_rules[0]) || "-";
        const vector = detectVectorFromRules(a.triggered_rules);
        const score = a.ai_score !== null && a.ai_score !== undefined ? `${(a.ai_score * 100).toFixed(1)}%` : "-";

        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>${time}</td>
            <td>${a.client_ip || "-"}</td>
            <td><span class="tag ${vector.key}">${vector.label}</span></td>
            <td>${rule}</td>
            <td>${score}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderStats(alerts) {
    const total = alerts.length;
    const blocked = alerts.filter((a) => (a.anomaly_score || 0) >= 5).length;
    const pct = total > 0 ? ((blocked / total) * 100).toFixed(1) : "0.0";

    document.getElementById("total-attacks").textContent = `${total}`;
    document.getElementById("blocked-attacks").textContent = `${pct}%`;
}

async function refreshReports() {
    const apiBase = resolveApiBase();
    try {
        const res = await fetch(`${apiBase}/logs`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const alerts = data.alerts || [];

        renderStats(alerts);
        renderVectors(alerts);
        renderTable(alerts);
    } catch (err) {
        const tbody = document.getElementById("attacks-list");
        tbody.innerHTML = `<tr><td colspan="5" class="empty-row">Failed to load report data: ${err.message}</td></tr>`;
        document.getElementById("attack-vectors").innerHTML = '<div class="empty-row">No data available.</div>';
        document.getElementById("total-attacks").textContent = "0";
        document.getElementById("blocked-attacks").textContent = "0%";
    }
}

function generateReport() {
    const reportType = document.getElementById("report-type").value;
    const dateRange = document.getElementById("date-range").value;
    const rows = Array.from(document.querySelectorAll("#attacks-list tr"));

    let csv = "time,ip,type,rule,ai_score\n";
    rows.forEach((row) => {
        const cells = row.querySelectorAll("td");
        if (cells.length !== 5) return;
        const values = Array.from(cells).map((c) => `"${(c.textContent || "").trim().replace(/"/g, '""')}"`);
        csv += values.join(",") + "\n";
    });

    const blob = new Blob([`report_type:${reportType}\nrange:${dateRange}\n\n${csv}`], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `modintel_report_${reportType}_${dateRange}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

setInterval(refreshReports, 5000);
refreshReports();
