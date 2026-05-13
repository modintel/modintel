const REPORTS_CONFIG_KEY = "modintel.dashboard.config";
const REPORTS_API_BASE = "/api";
const REPORTS_DEFAULT_BASE = window.location.origin;
const GEO_CACHE_KEY = "modintel.geo.cache";

function getConfig() {
    try {
        var raw = localStorage.getItem(REPORTS_CONFIG_KEY);
        if (!raw) return { reviewApiBase: REPORTS_DEFAULT_BASE };
        return JSON.parse(raw);
    } catch (_) {
        return { reviewApiBase: REPORTS_DEFAULT_BASE };
    }
}

function resolveApiBase() {
    var cfg = getConfig();
    if (!cfg.reviewApiBase) return REPORTS_API_BASE;
    try {
        if (cfg.reviewApiBase === window.location.origin) return REPORTS_API_BASE;
        return cfg.reviewApiBase + "/api";
    } catch (_) {
        return REPORTS_API_BASE;
    }
}

var API_BASE = resolveApiBase();

var PIE_COLORS = [
    "#dc2626", "#d97706", "#a855f7", "#06b6d4", "#ec4899",
    "#3b82f6", "#16a34a", "#f97316", "#8b5cf6", "#6b7280"
];

var GEO_COLORS = [
    "#dc2626", "#d97706", "#a855f7", "#06b6d4", "#3b82f6",
    "#16a34a", "#ec4899", "#f97316", "#8b5cf6", "#e11d48",
    "#0891b2", "#7c3aed", "#ca8a04", "#059669", "#be123c"
];

function detectVector(rule) {
    if (!rule) return { key: "other", label: "Other" };
    var code = Number(rule);
    if (code >= 900000 && code < 910000) return { key: "protocol", label: "Protocol" };
    if (code >= 910000 && code < 913000) return { key: "protocol", label: "Protocol" };
    if (code >= 913000 && code < 914000) return { key: "scanner", label: "Scanner" };
    if (code >= 914000 && code < 920000) return { key: "protocol", label: "Protocol" };
    if (code >= 920000 && code < 930000) return { key: "protocol", label: "Protocol" };
    if (code >= 930000 && code < 931000) return { key: "lfi", label: "LFI/Traversal" };
    if (code >= 931000 && code < 932000) return { key: "rfi", label: "RFI Attack" };
    if (code >= 932000 && code < 933000) return { key: "cmdi", label: "CMD Injection" };
    if (code >= 933000 && code < 934000) return { key: "php", label: "PHP Attack" };
    if (code >= 934000 && code < 936000) return { key: "nosql", label: "NoSQL Injection" };
    if (code >= 936000 && code < 941000) return { key: "protocol", label: "Protocol" };
    if (code >= 941000 && code < 942000) return { key: "xss", label: "XSS" };
    if (code >= 942000 && code < 943000) return { key: "sqli", label: "SQL Injection" };
    if (code >= 943000 && code < 944000) return { key: "session", label: "Session Fix.." };
    if (code >= 944000 && code < 949000) return { key: "ssrf", label: "SSRF/XXE" };
    if (code >= 949000 && code < 950000) return { key: "anomaly", label: "Anomaly" };
    if (code >= 950000 && code < 990000) return { key: "anomaly", label: "Anomaly" };
    if (code >= 990000 && code < 1000000) return { key: "custom", label: "Custom Rule" };
    return { key: "other", label: "Other" };
}

function detectVectorFromRules(rules) {
    if (!rules || rules.length === 0) return detectVector(null);
    var votes = {};
    for (var i = 0; i < rules.length; i++) {
        var v = detectVector(rules[i]);
        votes[v.key] = (votes[v.key] || 0) + 1;
    }
    var sorted = Object.entries(votes).sort(function (a, b) { return b[1] - a[1]; });
    if (sorted.length === 0) return detectVector(null);
    var winner = sorted[0][0];
    for (var j = 0; j < rules.length; j++) {
        var v2 = detectVector(rules[j]);
        if (v2.key === winner) return v2;
    }
    return detectVector(rules[0]);
}

function renderStats(stats) {
    var total = stats.total_alerts || 0;
    document.getElementById("total-attacks").textContent = total.toLocaleString();
    document.getElementById("blocked-attacks").textContent = (stats.blocked_percentage || 0).toFixed(1) + "%";
}

function renderPieChart(alerts) {
    var canvas = document.getElementById("attack-pie");
    var legend = document.getElementById("pie-legend");
    var ctx = canvas.getContext("2d");
    var w = canvas.width;
    var h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    var counts = {};
    alerts.forEach(function (a) {
        var v = detectVectorFromRules(a.triggered_rules);
        counts[v.label] = (counts[v.label] || 0) + 1;
    });

    var entries = Object.entries(counts).sort(function (a, b) { return b[1] - a[1]; });
    var total = entries.reduce(function (sum, e) { return sum + e[1]; }, 0);

    if (total === 0) {
        legend.innerHTML = '<div class="pie-empty">No attack data</div>';
        return;
    }

    var cx = w / 2;
    var cy = h / 2;
    var r = Math.min(cx, cy) - 10;
    var angle = -Math.PI / 2;
    var legendHtml = "";
    var slices = [];

    entries.forEach(function (item, i) {
        var pct = item[1] / total;
        var sweep = pct * Math.PI * 2;

        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, r, angle, angle + sweep);
        ctx.closePath();
        ctx.fillStyle = PIE_COLORS[i % PIE_COLORS.length];
        ctx.fill();
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 1.5;
        ctx.stroke();

        slices.push({ start: angle, end: angle + sweep, label: item[0], count: item[1], pct: pct });
        angle += sweep;

        legendHtml += '<div class="pie-legend-item">' +
            '<span class="pie-legend-dot" style="background:' + PIE_COLORS[i % PIE_COLORS.length] + '"></span>' +
            '<span>' + escapeHtml(item[0]) + '</span>' +
            '<span class="pie-legend-pct">' + (pct * 100).toFixed(1) + '%</span>' +
            '</div>';
    });

    legend.innerHTML = legendHtml;

    var tooltip = document.getElementById("global-chart-tooltip");
    if (!tooltip) {
        tooltip = document.createElement("div");
        tooltip.id = "global-chart-tooltip";
        tooltip.style.cssText = "position:fixed;display:none;background:#fafafa;border:1px solid rgba(0,0,0,0.08);color:#121212;font-size:0.7rem;padding:4px 8px;border-radius:4px;pointer-events:none;z-index:99999;white-space:nowrap;box-shadow:0 2px 8px rgba(0,0,0,0.15);font-family:var(--font,sans-serif);";
        document.body.appendChild(tooltip);
    }

    canvas.onmousemove = function (e) {
        var rect = canvas.getBoundingClientRect();
        var mx = e.clientX - rect.left - cx;
        var my = e.clientY - rect.top - cy;
        var dist = Math.sqrt(mx * mx + my * my);

        if (dist > r || dist < 2) {
            tooltip.style.display = "none";
            canvas.style.cursor = "default";
            return;
        }

        var mouseAngle = Math.atan2(my, mx);
        if (mouseAngle < -Math.PI / 2) mouseAngle += 2 * Math.PI;

        for (var i = 0; i < slices.length; i++) {
            var s = slices[i];
            if (mouseAngle >= s.start && mouseAngle < s.end) {
                tooltip.textContent = s.label + ": " + s.count + " (" + (s.pct * 100).toFixed(1) + "%)";
                tooltip.style.display = "block";
                tooltip.style.left = (e.clientX + 12) + "px";
                tooltip.style.top = (e.clientY - 10) + "px";
                canvas.style.cursor = "pointer";
                return;
            }
        }
        tooltip.style.display = "none";
        canvas.style.cursor = "default";
    };

    canvas.onmouseleave = function () {
        tooltip.style.display = "none";
    };
}

function getGeoCache() {
    try {
        var raw = sessionStorage.getItem(GEO_CACHE_KEY);
        return raw ? JSON.parse(raw) : {};
    } catch (_) { return {}; }
}

function setGeoCache(cache) {
    try { sessionStorage.setItem(GEO_CACHE_KEY, JSON.stringify(cache)); } catch (_) {}
}

function iso2flag(code) {
    if (!code || code.length !== 2) return "";
    return String.fromCodePoint(0x1F1E6 - 65 + code.charCodeAt(0), 0x1F1E6 - 65 + code.charCodeAt(1));
}

async function resolveIpCountry(ip, cache) {
    if (cache[ip]) return cache[ip];
    if (!ip || ip === "127.0.0.1" || ip === "::1" || ip.startsWith("10.") ||
        ip.startsWith("172.16.") || ip.startsWith("192.168.")) {
        return (cache[ip] = { country_code: "", country_name: "Local / Private" });
    }
    try {
        var resp = await fetch("https://ipapi.co/" + encodeURIComponent(ip) + "/json/", { signal: AbortSignal.timeout(5000) });
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        var data = await resp.json();
        return (cache[ip] = { country_code: data.country_code || "", country_name: data.country_name || "Unknown" });
    } catch (_) {
        return (cache[ip] = { country_code: "", country_name: "Unknown" });
    }
}

async function resolveIpCountries(ips) {
    var cache = getGeoCache();
    return await Promise.all(ips.map(function (ip) { return resolveIpCountry(ip, cache); })).then(function (results) {
        setGeoCache(cache);
        return results;
    });
}

function renderGeoDistribution(geoRows) {
    var box = document.getElementById("geo-dist");
    if (!geoRows.length) {
        box.innerHTML = '<div class="geo-empty">No IP data available</div>';
        return;
    }
    var maxCount = geoRows[0][1].count;
    var html = "";
    geoRows.forEach(function (item, i) {
        var country = item[1];
        var pct = Math.max(4, Math.round((country.count / maxCount) * 100));
        var flag = country.code ? iso2flag(country.code) : "";
        html += '<div class="geo-row">' +
            '<span class="geo-flag">' + flag + '</span>' +
            '<span class="geo-name" title="' + escapeAttr(item[0]) + '">' + escapeHtml(item[0]) + '</span>' +
            '<span class="geo-bar-wrap"><span class="geo-bar-fill" style="width:' + pct + '%;background:' + GEO_COLORS[i % GEO_COLORS.length] + '"></span></span>' +
            '<span class="geo-count">' + country.count + '</span>' +
            '</div>';
    });
    box.innerHTML = html;
}

function renderFPRules(fpAlerts) {
    var tbody = document.getElementById("fp-rules-body");
    if (!fpAlerts.length) {
        tbody.innerHTML = '<tr><td colspan="3" class="empty-row">No false positive reviews yet</td></tr>';
        return;
    }

    var ruleCounts = {};
    var ruleMessages = {};
    fpAlerts.forEach(function (a) {
        var rules = a.triggered_rules || [];
        var details = a.rule_details || [];
        var detailMap = {};
        details.forEach(function (d) { detailMap[d.rule_id] = d.message || ""; });
        var seen = {};
        rules.forEach(function (r) {
            if (!seen[r]) { seen[r] = true; ruleCounts[r] = (ruleCounts[r] || 0) + 1; }
            if (!ruleMessages[r] && detailMap[r]) ruleMessages[r] = detailMap[r];
        });
    });

    var entries = Object.entries(ruleCounts).filter(function(item) { return item[1] >= 10; }).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 15);
    if (!entries.length) {
        tbody.innerHTML = '<tr><td colspan="3" class="empty-row">No rule-level FP data</td></tr>';
        return;
    }

    var maxCount = entries[0][1];
    var html = "";
    entries.forEach(function (item) {
        var pct = Math.round((item[1] / maxCount) * 100);
        html += '<tr>' +
            '<td><span class="rule-id">' + escapeHtml(item[0]) + '</span></td>' +
            '<td>' + escapeHtml(ruleMessages[item[0]] || "") + '</td>' +
            '<td>' +
            '<div class="fp-bar-cell">' +
            '<span class="fp-mini-bar"><span class="fp-mini-fill" style="width:' + pct + '%"></span></span>' +
            '<span class="fp-count">' + item[1] + '</span>' +
            '</div>' +
            '</td>' +
            '</tr>';
    });
    tbody.innerHTML = html;
}

function renderTrendChart(trendData) {
    var box = document.getElementById("trend-chart");
    if (!trendData || !trendData.values || !trendData.values.length) {
        box.innerHTML = '<div class="trend-loading">No trend data</div>';
        return;
    }

    var values = trendData.values;
    var maxVal = Math.max.apply(null, values) || 1;
    var html = "";
    for (var i = 0; i < values.length; i++) {
        var pct = Math.max(2, Math.round((values[i] / maxVal) * 100));
        html += '<div class="trend-bar" style="height:' + pct + '%" data-label="' + escapeAttr(trendData.labels[i] || "") + '" data-value="' + values[i] + '"></div>';
    }
    box.innerHTML = html;

    var tooltip = document.getElementById("global-chart-tooltip");
    if (!tooltip) {
        tooltip = document.createElement("div");
        tooltip.id = "global-chart-tooltip";
        tooltip.style.cssText = "position:fixed;display:none;background:#fafafa;border:1px solid rgba(0,0,0,0.08);color:#121212;font-size:0.7rem;padding:4px 8px;border-radius:4px;pointer-events:none;z-index:99999;white-space:nowrap;box-shadow:0 2px 8px rgba(0,0,0,0.15);font-family:var(--font,sans-serif);";
        document.body.appendChild(tooltip);
    }

    var bars = box.querySelectorAll(".trend-bar");
    bars.forEach(function (bar) {
        bar.addEventListener("mouseenter", function () {
            tooltip.textContent = bar.dataset.label + ": " + bar.dataset.value;
            tooltip.style.display = "block";
        });
        bar.addEventListener("mousemove", function (e) {
            tooltip.style.left = (e.clientX + 12) + "px";
            tooltip.style.top = (e.clientY - 10) + "px";
        });
        bar.addEventListener("mouseleave", function () {
            tooltip.style.display = "none";
        });
    });
}

function renderTopIps(alerts, geoResults) {
    var tbody = document.getElementById("top-ips-body");

    var ipCounts = {};
    alerts.forEach(function (a) {
        var ip = a.client_ip;
        if (ip) ipCounts[ip] = (ipCounts[ip] || 0) + 1;
    });

    var sorted = Object.entries(ipCounts).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 10);

    if (!sorted.length) {
        tbody.innerHTML = '<tr><td colspan="3" class="empty-row">No data</td></tr>';
        return;
    }

    var countryMap = {};
    if (geoResults) {
        var uniqueIps = sorted.map(function (e) { return e[0]; });
        for (var i = 0; i < Math.min(uniqueIps.length, geoResults.length); i++) {
            countryMap[uniqueIps[i]] = geoResults[i] ? geoResults[i].country_name || "" : "";
        }
    }

    var html = "";
    sorted.forEach(function (item) {
        html += '<tr>' +
            '<td><span class="ip-addr">' + escapeHtml(item[0]) + '</span></td>' +
            '<td><span class="ip-country" title="' + escapeAttr(countryMap[item[0]] || "") + '">' + escapeHtml(countryMap[item[0]] || "-") + '</span></td>' +
            '<td>' + item[1] + '</td>' +
            '</tr>';
    });
    tbody.innerHTML = html;
}

function generateReport() {
    var reportType = document.getElementById("report-type").value;
    var dateRange = document.getElementById("date-range").value;
    var lines = [];
    lines.push("report_type:" + reportType);
    lines.push("range:" + dateRange);
    lines.push("generated:" + new Date().toISOString());
    lines.push("");

    lines.push("=== STATS ===");
    lines.push("total_attacks," + (document.getElementById("total-attacks").textContent || "—"));
    lines.push("blocked_pct," + (document.getElementById("blocked-attacks").textContent || "—"));

    lines.push("");
    lines.push("=== TOP IPS ===");
    lines.push("ip,country,count");
    var ipRows = document.querySelectorAll("#top-ips-body tr");
    ipRows.forEach(function (row) {
        var cells = row.querySelectorAll("td");
        if (cells.length === 3) {
            lines.push('"' + (cells[0].textContent || "").trim() + '","' + (cells[1].textContent || "").trim() + '","' + (cells[2].textContent || "").trim() + '"');
        }
    });

    lines.push("");
    lines.push("=== FP RULES ===");
    lines.push("rule_id,message,fp_count");
    var fpRows = document.querySelectorAll("#fp-rules-body tr");
    fpRows.forEach(function (row) {
        var cells = row.querySelectorAll("td");
        if (cells.length === 3) {
            lines.push('"' + (cells[0].textContent || "").trim() + '","' + (cells[1].textContent || "").trim() + '","' + (cells[2].textContent || "").trim() + '"');
        }
    });

    var blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8;" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "modintel_report_" + reportType + "_" + dateRange + ".csv";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

async function refreshReports() {
    try {
        var statsRes = await apiFetch(API_BASE + "/stats");
        if (!statsRes.ok) throw new Error("HTTP " + statsRes.status);
        var stats = await statsRes.json();

        var logsRes = await apiFetch(API_BASE + "/logs?limit=100");
        var alerts = [];
        if (logsRes.ok) {
            var logsData = await logsRes.json();
            alerts = logsData.data || logsData.alerts || [];
        }

        var trendRes = await apiFetch(API_BASE + "/trend?range=day");
        var trendData = null;
        if (trendRes.ok) trendData = await trendRes.json();

        var fpRes = await apiFetch(API_BASE + "/alerts/review?human_label=false_positive&limit=200&status=");
        var fpAlerts = [];
        if (fpRes.ok) {
            var fpData = await fpRes.json();
            fpAlerts = fpData.items || [];
        }

        renderStats(stats);
        renderPieChart(alerts);
        renderFPRules(fpAlerts);
        renderTrendChart(trendData);

        var ips = [];
        var seen = {};
        for (var i = 0; i < alerts.length; i++) {
            var ip = alerts[i].client_ip;
            if (ip && !seen[ip]) { seen[ip] = true; ips.push(ip); }
        }
        var topIps = ips.slice(0, 30);

        if (topIps.length) {
            document.getElementById("geo-dist").innerHTML = '<div class="geo-loading">Resolving ' + topIps.length + ' IP locations&hellip;</div>';
            var geoResults = await resolveIpCountries(topIps);

            var countries = {};
            for (var j = 0; j < geoResults.length; j++) {
                var name = geoResults[j].country_name || geoResults[j].country_code || "Unknown";
                if (!countries[name]) countries[name] = { code: geoResults[j].country_code, count: 0 };
                countries[name].count++;
            }
            var topCountries = Object.entries(countries).sort(function (a, b) { return b[1].count - a[1].count; }).slice(0, 8);
            renderGeoDistribution(topCountries);
            renderTopIps(alerts, geoResults);
        } else {
            document.getElementById("geo-dist").innerHTML = '<div class="geo-empty">No IP data available</div>';
            renderTopIps(alerts, null);
        }
    } catch (err) {
        document.getElementById("geo-dist").innerHTML = '<div class="geo-empty">Data unavailable</div>';
        document.getElementById("pie-legend").innerHTML = '<div class="pie-empty">Data unavailable</div>';
        document.getElementById("fp-rules-body").innerHTML = '<tr><td colspan="3" class="empty-row">Data unavailable</td></tr>';
        document.getElementById("trend-chart").innerHTML = '<div class="trend-loading">Data unavailable</div>';
        document.getElementById("top-ips-body").innerHTML = '<tr><td colspan="3" class="empty-row">Data unavailable</td></tr>';
    }
}

function escapeHtml(str) {
    var div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

function escapeAttr(str) {
    return String(str).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

var auditToggleBtn = document.getElementById("audit-toggle-btn");
var reportsBody = document.querySelector(".reports-right-body");
var auditLogs = document.querySelector(".audit-logs");
var panelHeader = document.querySelector(".panel-right-header div");
var auditActionFilter = document.getElementById("audit-action-filter");

function setAuditView(showAudit) {
    if (!reportsBody || !auditLogs || !panelHeader || !auditToggleBtn) return;
    if (showAudit) {
        reportsBody.style.display = "none";
        auditLogs.style.display = "block";
        panelHeader.textContent = "Audit Logs";
        auditToggleBtn.textContent = "REPORTS";
        if (auditActionFilter) auditActionFilter.style.display = "";
        loadAuditLogs();
    } else {
        reportsBody.style.display = "grid";
        auditLogs.style.display = "none";
        panelHeader.textContent = "Reports Overview";
        auditToggleBtn.textContent = "AUDIT TRAIL";
        if (auditActionFilter) auditActionFilter.style.display = "none";
    }
}

if (auditToggleBtn && reportsBody && auditLogs && panelHeader) {
    auditToggleBtn.addEventListener("click", function () {
        var isAudit = auditLogs.style.display !== "none";
        setAuditView(!isAudit);
    });
}

if (auditActionFilter) auditActionFilter.addEventListener("change", loadAuditLogs);

async function loadAuditLogs() {
    try {
        var actionFilter = document.getElementById("audit-action-filter");
        var action = actionFilter ? actionFilter.value : "";
        var url = API_BASE + "/admin/audit-logs?limit=50";
        if (action) url += "&action=" + encodeURIComponent(action);
        
        var res = await apiFetch(url);
        if (!res.ok) throw new Error("HTTP " + res.status);
        var data = await res.json();
        var logs = data.logs || [];
        renderAuditLogs(logs);
    } catch (err) {
        document.getElementById("audit-logs-body").innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--fg-muted);padding:20px;">Failed to load audit logs</td></tr>';
    }
}

function renderAuditLogs(logs) {
    var tbody = document.getElementById("audit-logs-body");
    if (!logs.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--fg-muted);padding:20px;">No audit logs found</td></tr>';
        return;
    }
    var html = "";
logs.forEach(function (log) {
        var ts = new Date(log.timestamp).toLocaleString();
        var user = escapeHtml(log.user_email || log.user_id);
        var action = escapeHtml(log.action);
        var details = JSON.stringify(log.details || {});
        var resource = escapeHtml(log.resource_type + (log.resource_id ? " (" + log.resource_id + ")" : ""));
        html += '<tr>' +
            '<td>' + ts + '</td>' +
            '<td>' + user + '</td>' +
            '<td>' + action + '</td>' +
            '<td>' + escapeHtml(details) + '</td>' +
            '<td>' + resource + '</td>' +
            '</tr>';
    });
    tbody.innerHTML = html;
}

var generateReportBtn = document.getElementById("generate-report-btn");
if (generateReportBtn) generateReportBtn.addEventListener("click", generateReport);

var paranoiaSettingsBtn = document.getElementById("paranoia-settings-btn");
if (paranoiaSettingsBtn) {
    paranoiaSettingsBtn.addEventListener("click", function () {
        window.location.href = "/settings#waf-paranoia";
    });
}

refreshReports();
setInterval(refreshReports, 30000);
setAuditView(false);

if (auditActionFilter) auditActionFilter.style.display = "none";
