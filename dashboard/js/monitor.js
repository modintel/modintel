const API_BASE = '/api';
let currentRange = '1h';

const RANGE_MAX_POINTS = {
    '1h': 60,
    '6h': 72,
    '24h': 96,
    '7d': 168,
};

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

function addChartHoverDots(svgId, values, width, height, padding, unit, dotClass) {
    const svg = document.getElementById(svgId);
    if (!svg) return;
    svg.querySelectorAll('.' + dotClass).forEach(el => el.remove());

    let tooltip = document.getElementById('global-chart-tooltip');
    if (!tooltip) {
        tooltip = document.createElement('div');
        tooltip.id = 'global-chart-tooltip';
        tooltip.style.cssText = 'position:fixed;display:none;background:#fafafa;border:1px solid rgba(0,0,0,0.08);color:#121212;font-size:0.7rem;padding:4px 8px;border-radius:4px;pointer-events:none;z-index:99999;white-space:nowrap;box-shadow:0 2px 8px rgba(0,0,0,0.15);font-family:var(--font,sans-serif);';
        document.body.appendChild(tooltip);
    }

    const clean = values.map(v => Number.isFinite(Number(v)) ? Number(v) : 0);
    if (clean.length === 0) return;

    const max = Math.max(...clean, 1);
    const min = Math.min(...clean, 0);
    const range = max - min || 1;
    const step = (width - padding * 2) / Math.max(clean.length - 1, 1);

    clean.forEach((val, i) => {
        const x = padding + i * step;
        const y = height - padding - ((val - min) / range) * (height - padding * 2);

        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', x);
        circle.setAttribute('cy', y);
        circle.setAttribute('r', '4');
        circle.setAttribute('fill', 'transparent');
        circle.setAttribute('stroke', 'transparent');
        circle.setAttribute('stroke-width', '8');
        circle.classList.add(dotClass);
        circle.style.cursor = 'pointer';

        circle.addEventListener('mouseenter', function () {
            tooltip.textContent = val.toFixed(1) + ' ' + unit;
            tooltip.style.display = 'block';
        });

        circle.addEventListener('mousemove', function (e) {
            tooltip.style.left = (e.clientX + 12) + 'px';
            tooltip.style.top = (e.clientY - 10) + 'px';
        });

        circle.addEventListener('mouseleave', function () {
            tooltip.style.display = 'none';
        });

        svg.appendChild(circle);
    });
}

function updateRequestRateChart(data) {
    const width = 300;
    const height = 80;
    const padding = 5;

    const { points, areaPoints } = generateChartPoints(data, width, height, padding);

    document.getElementById('request-line').setAttribute('points', points);
    document.getElementById('request-area').setAttribute('d', 'M' + areaPoints);

    addChartHoverDots('request-rate-chart', data, width, height, padding, 'req/min', 'req-dot');
}

function updateErrorRateChart(data) {
    const width = 600;
    const height = 80;
    const padding = 5;

    const { points, areaPoints } = generateChartPoints(data, width, height, padding);

    document.getElementById('error-line').setAttribute('points', points);
    document.getElementById('error-area').setAttribute('d', 'M' + areaPoints);

    addChartHoverDots('error-rate-chart', data, width, height, padding, 'err/min', 'error-dot');
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
    const timeSeries = data[timeField] || [];
    const maxPoints = RANGE_MAX_POINTS[currentRange] || 60;
    const sliced = timeSeries.slice(-maxPoints);
    const requestRates = extractTimeSeriesData(sliced, 'requests_per_minute');
    updateRequestRateChart(requestRates);

    const labels = generateLabels(sliced);
    updateChartLabels('request-labels', labels);
    updateChartLabels('error-labels', labels);

    const p50 = data.p50_latency_ms || 0;
    const p95 = data.p95_latency_ms || 0;
    const p99 = data.p99_latency_ms || 0;
    updateLatencyBars(p50, p95, p99);

    const errorRates = extractTimeSeriesData(sliced, 'errors_per_minute');
    updateErrorRateChart(errorRates);

    updateWorkerBars();
    updateMongoBars();

    const memoryPercent = system.memory_percent || 0;
    document.getElementById('memory-bar').style.width = `${memoryPercent}%`;

    const dbSize = system.mongodb_database_size_bytes || 0;
    const totalStorageMB = 1_000;
    const storagePercent = Math.min((dbSize / (totalStorageMB * 1_024 * 1_024)) * 100, 100);
    document.getElementById('storage-bar').style.width = `${storagePercent}%`;

    const cpuPercent = system.cpu_percent || 0;
    document.getElementById('cpu-percent').textContent = `${cpuPercent.toFixed(0)}%`;
    document.getElementById('cpu-ring').setAttribute('stroke-dasharray', `${cpuPercent}, 100`);

    const gpuPercent = system.gpu_percent;
    const gpuRing = document.getElementById('gpu-ring');
    const gpuValue = document.getElementById('gpu-percent');
    if (gpuPercent !== null && gpuPercent !== undefined) {
        gpuValue.textContent = `${gpuPercent.toFixed(0)}%`;
        gpuRing.setAttribute('stroke-dasharray', `${gpuPercent}, 100`);
    } else {
        gpuValue.textContent = 'N/A';
        gpuRing.setAttribute('stroke-dasharray', '0, 100');
    }

    const modelEl = document.getElementById('model-active');
    if (data.model_version) {
        modelEl.textContent = data.model_version;
    }
}

function applyMetricsLiveStats(data) {
    document.getElementById('stat-latency').textContent = `${(data.avg_inference_ms || 0).toFixed(1)}ms`;

    if (data.requests_per_minute !== undefined) {
        document.getElementById('stat-rpm').textContent = (data.requests_per_minute || 0).toFixed(1);
    }

    const p50 = data.p50_latency_ms || 0;
    const p95 = data.p95_latency_ms || 0;
    const p99 = data.p99_latency_ms || 0;
    updateLatencyBars(p50, p95, p99);

    const system = data.system;
    if (system) {
        document.getElementById('mongodb-connections').textContent = system.mongodb_connections || 1;
        document.getElementById('memory-used').textContent = `${system.memory_used_mb || 0} / ${system.memory_total_mb || 0} MB`;
        document.getElementById('goroutines').textContent = system.goroutines || 0;
        document.getElementById('sys-dbsize').textContent = formatBytes(system.mongodb_database_size_bytes);

        updateWorkerBars();
        updateMongoBars();

        const memoryPercent = system.memory_percent || 0;
        document.getElementById('memory-bar').style.width = `${memoryPercent}%`;

        const dbSize = system.mongodb_database_size_bytes || 0;
        const totalStorageMB = 1_000;
        const storagePercent = Math.min((dbSize / (totalStorageMB * 1_024 * 1_024)) * 100, 100);
        document.getElementById('storage-bar').style.width = `${storagePercent}%`;

        const cpuPercent = system.cpu_percent || 0;
        document.getElementById('cpu-percent').textContent = `${cpuPercent.toFixed(0)}%`;
        document.getElementById('cpu-ring').setAttribute('stroke-dasharray', `${cpuPercent}, 100`);

        const gpuPercent = system.gpu_percent;
        const gpuRing = document.getElementById('gpu-ring');
        const gpuValue = document.getElementById('gpu-percent');
        if (gpuPercent !== null && gpuPercent !== undefined) {
            gpuValue.textContent = `${gpuPercent.toFixed(0)}%`;
            gpuRing.setAttribute('stroke-dasharray', `${gpuPercent}, 100`);
        } else {
            gpuValue.textContent = 'N/A';
            gpuRing.setAttribute('stroke-dasharray', '0, 100');
        }
    }

    const modelEl = document.getElementById('model-active');
    if (data.model_version) {
        modelEl.textContent = data.model_version;
    }
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
            if (data.avg_inference_ms !== undefined) {
                applyMetricsLiveStats(data);
            }
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
