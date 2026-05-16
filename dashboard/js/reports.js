const REPORTS_CONFIG_KEY = "modintel.dashboard.config";
const REPORTS_API_BASE = "/api";
const REPORTS_DEFAULT_BASE = window.location.origin;

// ── pagination state ──────────────────────────────────────────────────────────
let currentCursor = null;
let hasMore = false;
let allLoadedAlerts = [];

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
        if (cfg.reviewApiBase === current) return REPORTS_API_BASE;
        return `${cfg.reviewApiBase}/api`;
    } catch (_) {
        return REPORTS_API_BASE;
    }
}

// ── attack vector detection ───────────────────────────────────────────────────
function detectVector(rule) {
    if (!rule) return { key: "other", label: "Other" };
    const code = Number(rule);
    if (code >= 913000 && code < 914000) return { key: "scanner",  label: "Scanner" };
    if (code >= 920000 && code < 922000) return { key: "protocol", label: "Protocol" };
    if (code >= 930000 && code < 931000) return { key: "lfi",      label: "LFI/Traversal" };
    if (code >= 931000 && code < 932000) return { key: "rfi",      label: "RFI Attack" };
    if (code >= 932000 && code < 933000) return { key: "cmdi",     label: "Command Injection" };
    if (code >= 933000 && code < 934000) return { key: "php",      label: "PHP Attack" };
    if (code >= 934000 && code < 935000) return { key: "nosql",    label: "NoSQL Injection" };
    if (code >= 941000 && code < 942000) return { key: "xss",      label: "XSS" };
    if (code >= 942000 && code < 943000) return { key: "sqli",     label: "SQL Injection" };
    if (code >= 943000 && code < 944000) return { key: "session",  label: "Session Fixation" };
    if (code >= 949000 && code < 950000) return { key: "anomaly",  label: "Anomaly" };
    if (code >= 990000 && code < 991000) return { key: "custom",   label: "Custom Rule" };
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

// ── date range filter ─────────────────────────────────────────────────────────
function getDateRangeCutoff() {
    const range = document.getElementById("date-range").value;
    const now = Date.now();
    switch (range) {
        case "today": {
            const d = new Date(); d.setHours(0, 0, 0, 0); return d.getTime();
        }
        case "24h":  return now - 24 * 60 * 60 * 1000;
        case "7d":   return now - 7  * 24 * 60 * 60 * 1000;
        case "30d":  return now - 30 * 24 * 60 * 60 * 1000;
        default:     return 0;
    }
}

function parseAlertTime(ts) {
    if (!ts) return 0;
    const cleaned = ts.replace(/\//g, "-").replace(" ", "T");
    const t = new Date(cleaned.endsWith("Z") ? cleaned : cleaned + "Z");
    return isNaN(t.getTime()) ? 0 : t.getTime();
}

function filterByDateRange(alerts) {
    const cutoff = getDateRangeCutoff();
    if (!cutoff) return alerts;
    return alerts.filter(a => parseAlertTime(a.timestamp) >= cutoff);
}

// ── render helpers ────────────────────────────────────────────────────────────
function renderVectors(alerts) {
    const box = document.getElementById("attack-vectors");
    const filtered = filterByDateRange(alerts);
    const counts = new Map();
    filtered.forEach(a => {
        const v = detectVectorFromRules(a.triggered_rules || []);
        counts.set(v.label, (counts.get(v.label) || 0) + 1);
    });
    const entries = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const total = entries.reduce((s, [, c]) => s + c, 0) || 1;
    box.innerHTML = "";
    if (!entries.length) { box.innerHTML = '<div class="empty-row">No data yet.</div>'; return; }
    entries.forEach(([name, count], i) => {
        const pct = Math.max(4, Math.round((count / total) * 100));
        const row = document.createElement("div");
        row.className = "attack-vector";
        row.innerHTML = `
            <div class="vector-name">${name}</div>
            <div class="vector-bar"><div class="vector-fill ${vectorClass(i)}" style="width:${pct}%"></div></div>
            <div class="vector-count">${count}</div>`;
        box.appendChild(row);
    });
}

function renderTable(alerts) {
    const tbody = document.getElementById("attacks-list");
    tbody.innerHTML = "";
    const filtered = filterByDateRange(alerts);
    if (!filtered.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-row">No attacks in selected range.</td></tr>';
        return;
    }
    filtered.forEach(a => {
        const ts = a.timestamp ? a.timestamp.replace(/\//g, "-").replace(" ", "T") + "Z" : "";
        const time = ts ? new Date(ts).toLocaleTimeString() : "-";
        const rule = (a.triggered_rules && a.triggered_rules[0]) || "-";
        const vector = detectVectorFromRules(a.triggered_rules);
        const score = a.ai_score != null ? `${(a.ai_score * 100).toFixed(1)}%` : "-";
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>${time}</td>
            <td>${a.client_ip || "-"}</td>
            <td><span class="tag ${vector.key}">${vector.label}</span></td>
            <td>${rule}</td>
            <td>${score}</td>`;
        tbody.appendChild(tr);
    });
}

function renderStats(totalCount, alerts) {
    document.getElementById("total-attacks").textContent = totalCount !== undefined ? totalCount : alerts.length;
    const filtered = filterByDateRange(alerts);
    const blocked = filtered.filter(a => (a.anomaly_score || 0) >= 5).length;
    const pct = filtered.length > 0 ? ((blocked / filtered.length) * 100).toFixed(1) : "0.0";
    document.getElementById("blocked-attacks").textContent = `${pct}%`;
}

function updateLoadMoreBtn() {
    let btn = document.getElementById("load-more-btn");
    if (!btn) {
        btn = document.createElement("button");
        btn.id = "load-more-btn";
        btn.className = "btn btn-secondary";
        btn.style.cssText = "margin:12px auto;display:block;";
        btn.textContent = "Load More";
        btn.addEventListener("click", loadMore);
        document.querySelector(".panel-right").appendChild(btn);
    }
    btn.style.display = hasMore ? "block" : "none";
}

// ── data fetching ─────────────────────────────────────────────────────────────
async function loadMore() {
    const apiBase = resolveApiBase();
    const url = currentCursor
        ? `${apiBase}/logs?cursor=${currentCursor}`
        : `${apiBase}/logs`;
    try {
        const res = await apiFetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const page = data.data || data.alerts || [];
        allLoadedAlerts = allLoadedAlerts.concat(page);
        currentCursor = data.next_cursor || null;
        hasMore = !!currentCursor;
        renderTable(allLoadedAlerts);
        renderVectors(allLoadedAlerts);
        updateLoadMoreBtn();
    } catch (err) {
        console.error("Load more failed:", err);
    }
}

async function refreshReports() {
    const apiBase = resolveApiBase();
    try {
        // Reset pagination on full refresh
        currentCursor = null;
        allLoadedAlerts = [];

        const [logsRes, statsRes] = await Promise.all([
            apiFetch(`${apiBase}/logs`),
            apiFetch(`${apiBase}/stats`),
        ]);

        if (!logsRes.ok) throw new Error(`HTTP ${logsRes.status}`);
        const logsData = await logsRes.json();
        const page = logsData.data || logsData.alerts || [];
        allLoadedAlerts = page;
        currentCursor = logsData.next_cursor || null;
        hasMore = !!currentCursor;

        let totalCount;
        if (statsRes.ok) {
            const statsData = await statsRes.json();
            totalCount = statsData.total_alerts;
        }

        renderStats(totalCount, allLoadedAlerts);
        renderVectors(allLoadedAlerts);
        renderTable(allLoadedAlerts);
        updateLoadMoreBtn();
    } catch (err) {
        document.getElementById("attacks-list").innerHTML =
            `<tr><td colspan="5" class="empty-row">Failed to load: ${err.message}</td></tr>`;
        document.getElementById("attack-vectors").innerHTML = '<div class="empty-row">No data available.</div>';
        document.getElementById("total-attacks").textContent = "0";
        document.getElementById("blocked-attacks").textContent = "0%";
    }
}

// ── report generation ─────────────────────────────────────────────────────────
function generateReport() {
    const reportType = document.getElementById("report-type").value;
    const dateRange  = document.getElementById("date-range").value;
    const filtered   = filterByDateRange(allLoadedAlerts);

    let csv = "";

    if (reportType === "ml-performance") {
        csv = "timestamp,ip,uri,ai_score,ai_confidence,ai_priority,ai_status\n";
        filtered.forEach(a => {
            const score = a.ai_score != null ? (a.ai_score * 100).toFixed(1) : "";
            const conf  = a.ai_confidence != null ? (a.ai_confidence * 100).toFixed(1) : "";
            csv += [
                q(a.timestamp), q(a.client_ip), q(a.uri),
                q(score), q(conf), q(a.ai_priority), q(a.ai_status)
            ].join(",") + "\n";
        });
    } else if (reportType === "rule-trigger") {
        csv = "timestamp,ip,uri,rules_triggered,anomaly_score\n";
        filtered.forEach(a => {
            const rules = (a.triggered_rules || []).join("|");
            csv += [q(a.timestamp), q(a.client_ip), q(a.uri), q(rules), q(a.anomaly_score)].join(",") + "\n";
        });
    } else if (reportType === "detailed") {
        csv = "timestamp,ip,uri,type,rule,ai_score,ai_confidence,ai_priority,anomaly_score\n";
        filtered.forEach(a => {
            const vector = detectVectorFromRules(a.triggered_rules);
            const rule   = (a.triggered_rules && a.triggered_rules[0]) || "";
            const score  = a.ai_score != null ? (a.ai_score * 100).toFixed(1) : "";
            const conf   = a.ai_confidence != null ? (a.ai_confidence * 100).toFixed(1) : "";
            csv += [
                q(a.timestamp), q(a.client_ip), q(a.uri),
                q(vector.label), q(rule), q(score), q(conf),
                q(a.ai_priority), q(a.anomaly_score)
            ].join(",") + "\n";
        });
    } else {
        // summary
        csv = "time,ip,type,rule,ai_score\n";
        filtered.forEach(a => {
            const vector = detectVectorFromRules(a.triggered_rules);
            const rule   = (a.triggered_rules && a.triggered_rules[0]) || "";
            const score  = a.ai_score != null ? `${(a.ai_score * 100).toFixed(1)}%` : "";
            csv += [q(a.timestamp), q(a.client_ip), q(vector.label), q(rule), q(score)].join(",") + "\n";
        });
    }

    const header = `report_type:${reportType}\nrange:${dateRange}\nrecords:${filtered.length}\n\n`;
    const blob = new Blob([header + csv], { type: "text/csv;charset=utf-8;" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url;
    a.download = `modintel_${reportType}_${dateRange}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

function q(v) {
    return `"${String(v == null ? "" : v).replace(/"/g, '""')}"`;
}

// ── re-render on filter change ────────────────────────────────────────────────
document.getElementById("date-range").addEventListener("change", () => {
    renderTable(allLoadedAlerts);
    renderVectors(allLoadedAlerts);
});

document.getElementById("report-type").addEventListener("change", () => {
    // just visual feedback — actual export happens on button click
});

const generateReportBtn = document.getElementById("generate-report-btn");
if (generateReportBtn) generateReportBtn.addEventListener("click", generateReport);

setInterval(refreshReports, 30000); // slower refresh — 30s instead of 5s
refreshReports();
