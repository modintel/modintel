const API_BASE = '/api';
let currentRange = '1h';

const RANGE_FIELD = {
    '1h': 'time_1h',
    '6h': 'time_6h',
    '24h': 'time_24h',
    '7d': 'time_7d',
};

function generateChartPoints(data, width, height, padding) {
    let values = Array.isArray(data)
        ? data.map((value) => {
            const n = Number(value);
            return Number.isFinite(n) ? n : 0;
        })
        : [];

    if (values.length === 0) {
        values = new Array(20).fill(0);
    } else if (values.length === 1) {
        values = [values[0], values[0]];
    }

    const max = Math.max(...values, 1);
    const min = Math.min(...values, 0);
    const range = max - min || 1;

    const step = (width - padding * 2) / Math.max(values.length - 1, 1);

    const points = values.map((val, i) => {
        const x = padding + i * step;
        const y = height - padding - ((val - min) / range) * (height - padding * 2);
        return `${x},${y}`;
    }).join(' ');

    const areaPoints = `${padding},${height - padding} ` + points + ` ${width - padding},${height - padding} Z`;

    return { points, areaPoints };
}

function updateRequestRateChart(data) {
    const width = 300;
    const height = 80;
    const padding = 5;

    const { points, areaPoints } = generateChartPoints(data, width, height, padding);

    document.getElementById('request-line').setAttribute('points', points);
    document.getElementById('request-area').setAttribute('d', 'M' + areaPoints);
}

function updateErrorRateChart(data) {
    const width = 600;
    const height = 80;
    const padding = 5;

    const { points, areaPoints } = generateChartPoints(data, width, height, padding);

    document.getElementById('error-line').setAttribute('points', points);
    document.getElementById('error-area').setAttribute('d', 'M' + areaPoints);
}

function updateLatencyBars(p50, p95, p99) {
    const maxLatency = Math.max(p50, p95, p99, 1);

    document.getElementById('latency-p50').style.width = `${(p50 / maxLatency) * 100}%`;
    document.getElementById('latency-p95').style.width = `${(p95 / maxLatency) * 100}%`;
    document.getElementById('latency-p99').style.width = `${(p99 / maxLatency) * 100}%`;

    document.getElementById('latency-p50-value').textContent = `${p50.toFixed(1)}ms`;
    document.getElementById('latency-p95-value').textContent = `${p95.toFixed(1)}ms`;
    document.getElementById('latency-p99-value').textContent = `${p99.toFixed(1)}ms`;
}

async function fetchAggregateHealth() {
    try {
        const res = await apiFetch(`${API_BASE}/monitor/health`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        applyHealthData(data.services);
    } catch (e) {
        console.error('Error fetching service health:', e);
        markAllServicesUnknown();
    }
}

function markAllServicesUnknown() {
    updateServiceStatus('status-log-collector', 'unknown');
    updateServiceStatus('status-inference', 'unknown');
    updateServiceStatus('status-proxy', 'unknown');
    updateServiceStatus('status-review-api', 'unknown');
    updateServiceStatus('status-auth-service', 'unknown');
}

function normalizeServiceStatus(status) {
    if (!status || typeof status !== 'string') {
        return 'unknown';
    }

    const normalized = status.toLowerCase();
    if (normalized === 'ok' || normalized === 'healthy') {
        return 'ok';
    }
    if (normalized === 'degraded' || normalized === 'warn' || normalized === 'warning') {
        return 'degraded';
    }
    if (normalized === 'down' || normalized === 'unhealthy') {
        return 'down';
    }

    return 'unknown';
}

function updateServiceStatus(elementId, status) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const loading = el.querySelector('.status-loading');
    if (loading) loading.remove();

    el.className = 'service-status-indicator';

    if (status === 'ok' || status === 'healthy') {
        el.classList.add('healthy');
    } else if (status === 'degraded') {
        el.classList.add('degraded');
    } else {
        el.classList.add('down');
    }
}

function updateAllServiceStatuses(services) {
    if (!services) return;
    updateServiceStatus('status-log-collector', services['log-collector'] || 'unknown');
    updateServiceStatus('status-inference', services['inference-engine'] || 'unknown');
    updateServiceStatus('status-proxy', services['proxy-waf'] || 'unknown');
    updateServiceStatus('status-review-api', services['review-api'] || 'unknown');
    updateServiceStatus('status-auth-service', services['auth-service'] || 'unknown');
}

function extractTimeSeriesData(timeSeries, fieldName) {
    if (!timeSeries || !Array.isArray(timeSeries)) {
        return [];
    }

    return timeSeries.map(point => {
        const val = point[fieldName];
        return Number.isFinite(val) ? val : 0;
    });
}

function generateLabels(timeSeries) {
    if (!timeSeries || !Array.isArray(timeSeries)) {
        return [];
    }

    return timeSeries.map(point => {
        const ts = point.timestamp;
        if (!ts) return '';
        const date = new Date(ts);
        if (currentRange === '7d') {
            return date.toLocaleDateString([], { month: 'numeric', day: 'numeric' }) + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });
}

async function fetchMetrics() {
    try {
        const res = await apiFetch(`${API_BASE}/monitor/metrics?range=${currentRange}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        applyMetricsData(data);
    } catch (e) {
        console.error('Error fetching metrics:', e);
    }
}

function applyMetricsData(data) {
    document.getElementById('stat-latency').textContent = `${(data.avg_inference_ms || 0).toFixed(1)}ms`;
    document.getElementById('stat-rpm').textContent = (data.requests_per_minute || 0).toFixed(1);

    const system = data.system || {};
    document.getElementById('mongodb-connections').textContent = system.mongodb_connections || 1;
    document.getElementById('memory-used').textContent = `${system.memory_used_mb || 0} / ${system.memory_total_mb || 0} MB`;
    document.getElementById('goroutines').textContent = system.goroutines || 0;
    document.getElementById('sys-dbsize').textContent = formatBytes(system.mongodb_database_size_bytes);

    const timeField = RANGE_FIELD[currentRange] || 'time_1h';
    const timeSeries = data[timeField] || data.time_series || [];
    const requestRates = extractTimeSeriesData(timeSeries, 'requests_per_minute');
    updateRequestRateChart(requestRates);

    const labels = generateLabels(timeSeries);
    updateChartLabels('request-labels', labels);
    updateChartLabels('error-labels', labels);

    const p50 = data.p50_latency_ms || 0;
    const p95 = data.p95_latency_ms || 0;
    const p99 = data.p99_latency_ms || 0;
    updateLatencyBars(p50, p95, p99);

    const errorRates = extractTimeSeriesData(timeSeries, 'errors_per_minute');
    updateErrorRateChart(errorRates);

    updateWorkerBars();
    updateMongoBars();

    const memoryPercent = system.memory_percent || 0;
    document.getElementById('memory-bar').style.width = `${memoryPercent}%`;

    const dbSize = system.mongodb_database_size_bytes || 0;
    const totalStorageMB = 1_000;
    const storagePercent = Math.min((dbSize / (totalStorageMB * 1_024 * 1_024)) * 100, 100);
    document.getElementById('storage-bar').style.width = `${storagePercent}%`;
}

function applyHealthData(services) {
    if (!services) return;
    updateServiceStatus('status-log-collector', services['log-collector'] || 'unknown');
    updateServiceStatus('status-inference', services['inference-engine'] || 'unknown');
    updateServiceStatus('status-proxy', services['proxy-waf'] || 'unknown');
    updateServiceStatus('status-review-api', services['review-api'] || 'unknown');
    updateServiceStatus('status-auth-service', services['auth-service'] || 'unknown');
}

function formatBytes(bytes) {
    if (!bytes || bytes <= 0) return '-';
    const units = ['B', 'KB', 'MB', 'GB'];
    let unitIndex = 0;
    let value = bytes;
    while (value >= 1024 && unitIndex < units.length - 1) {
        value /= 1024;
        unitIndex++;
    }
    return `${value.toFixed(1)} ${units[unitIndex]}`;
}

function updateChartLabels(elementId, labels) {
    const labelsEl = document.getElementById(elementId);
    if (!labelsEl) return;

    labelsEl.innerHTML = '';
    if (!Array.isArray(labels) || labels.length === 0) {
        labelsEl.innerHTML = '<span>-</span><span>-</span><span>-</span>';
        return;
    }

    let indices;
    if (currentRange === '1h') {
        indices = [0, Math.floor(labels.length / 4), Math.floor(labels.length / 2), Math.floor(labels.length * 3 / 4), labels.length - 1];
    } else if (currentRange === '6h') {
        indices = [0, Math.floor(labels.length / 4), Math.floor(labels.length / 2), Math.floor(labels.length * 3 / 4), labels.length - 1];
    } else if (currentRange === '24h') {
        indices = [0, Math.floor(labels.length / 4), Math.floor(labels.length / 2), Math.floor(labels.length * 3 / 4), labels.length - 1];
    } else {
        indices = [0, Math.floor(labels.length / 4), Math.floor(labels.length / 2), Math.floor(labels.length * 3 / 4), labels.length - 1];
    }

    const unique = [...new Set(indices.filter(i => i >= 0 && i < labels.length))];
    unique.forEach(i => {
        const span = document.createElement('span');
        span.textContent = labels[i] || '';
        labelsEl.appendChild(span);
    });
}

function updateWorkerBars() {
    const container = document.getElementById('workers-bars');
    if (!container) return;
    const count = Number(document.getElementById('goroutines').textContent) || 0;
    container.innerHTML = '';
    for (let i = 0; i < count; i++) {
        const bar = document.createElement('div');
        bar.className = 'bar';
        bar.style.height = `${((i + 1) / count) * 100}%`;
        container.appendChild(bar);
    }
}

function updateMongoBars() {
    const container = document.getElementById('mongodb-bars');
    if (!container) return;
    const count = Number(document.getElementById('mongodb-connections').textContent) || 0;
    container.innerHTML = '';
    for (let i = 0; i < count; i++) {
        const bar = document.createElement('div');
        bar.className = 'bar';
        bar.style.height = `${((i + 1) / count) * 100}%`;
        container.appendChild(bar);
    }
}

let sseClient = null;
let pollingInterval = null;

function startSSE() {
    if (sseClient) sseClient.close();

    const indicator = SSE_createIndicator('connection-indicator');
    sseClient = new SSEClient('/api/events/stream', {
        onMetrics: function (data) {
            applyMetricsData(data);
        },
        onHealth: function (data) {
            applyHealthData(data.services);
        },
        onConnect: function () {
            if (sseClient && sseClient.fallbackActive) {
                stopPolling();
                sseClient.fallbackActive = false;
            }
        },
        onFallback: function () {
            startPolling();
        }
    });
    if (indicator) sseClient.indicator = indicator;
    sseClient.connect();
}

function stopSSE() {
    if (sseClient) {
        sseClient.close();
        sseClient = null;
    }
}

function startPolling() {
    if (pollingInterval) return;
    pollingInterval = setInterval(() => {
        fetchAggregateHealth();
        fetchMetrics();
    }, 2000);
}

function stopPolling() {
    if (pollingInterval) {
        clearInterval(pollingInterval);
        pollingInterval = null;
    }
}

fetchMetrics();
fetchAggregateHealth();
startSSE();

document.querySelectorAll('.time-range-buttons .graph-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.time-range-buttons .graph-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentRange = btn.dataset.range;
        fetchMetrics();
    });
});
