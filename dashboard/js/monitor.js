const API_BASE = '/api';
let currentRange = '1h';
let requestRateHistory = [];
let errorRateHistory = [];
const MAX_HISTORY = 20;

const HEALTH_ENDPOINTS = {
    'log-collector': `${API_BASE}/health/log-collector`,
    'inference-engine': `${API_BASE}/health/inference-engine`,
    'proxy-waf': `${API_BASE}/health/proxy-waf`,
    'review-api': `${API_BASE}/health/review-api`,
    'auth-service': `${API_BASE}/health/auth-service`,
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

    const step = (width - padding * 2) / (values.length - 1);

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

async function updateServiceHealth() {
    try {
        const aggregate = await fetchAggregateHealth();
        const [review, logCollector, inference, proxy] = aggregate
            ? [
                aggregate['review-api'] || 'unknown',
                aggregate['log-collector'] || 'unknown',
                aggregate['inference-engine'] || 'unknown',
                aggregate['proxy-waf'] || 'unknown',
            ]
            : await Promise.all([
                fetchServiceStatus(HEALTH_ENDPOINTS['review-api']),
                fetchServiceStatus(HEALTH_ENDPOINTS['log-collector']),
                fetchServiceStatus(HEALTH_ENDPOINTS['inference-engine']),
                fetchServiceStatus(HEALTH_ENDPOINTS['proxy-waf']),
            ]);

        updateServiceStatus('status-review-api', review);
        updateServiceStatus('status-log-collector', logCollector);
        updateServiceStatus('status-inference', inference);
        updateServiceStatus('status-proxy', proxy);
    } catch (e) {
        console.error('Error fetching service health:', e);
        updateServiceStatus('status-review-api', 'unknown');
        updateServiceStatus('status-log-collector', 'unknown');
        updateServiceStatus('status-inference', 'unknown');
        updateServiceStatus('status-proxy', 'unknown');
    }
}

async function fetchAggregateHealth() {
    try {
        const [logCollector, inference, proxy, review, auth] = await Promise.all([
            fetchServiceStatus(HEALTH_ENDPOINTS['log-collector']),
            fetchServiceStatus(HEALTH_ENDPOINTS['inference-engine']),
            fetchServiceStatus(HEALTH_ENDPOINTS['proxy-waf']),
            fetchServiceStatus(HEALTH_ENDPOINTS['review-api']),
            fetchServiceStatus(HEALTH_ENDPOINTS['auth-service']),
        ]);

        updateServiceStatus('status-log-collector', logCollector);
        updateServiceStatus('status-inference', inference);
        updateServiceStatus('status-proxy', proxy);
        updateServiceStatus('status-review-api', review);
        updateServiceStatus('status-auth-service', auth);
} catch (e) {
        console.error('Error fetching service health:', e);
        updateServiceStatus('status-log-collector', 'unknown');
        updateServiceStatus('status-inference', 'unknown');
        updateServiceStatus('status-proxy', 'unknown');
        updateServiceStatus('status-review-api', 'unknown');
        updateServiceStatus('status-auth-service', 'unknown');
    }
}

async function fetchServiceStatus(url) {
    try {
        const res = await fetch(url, {
            headers: {
                Authorization: `Bearer ${getAccessToken()}`,
            },
        });

        if (!res.ok) {
            return res.status >= 500 ? 'down' : 'degraded';
        }

        const payload = await res.json();
        return normalizeServiceStatus(payload.status);
    } catch (_) {
        return 'down';
    }
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

async function updateMetrics() {
    try {
        const res = await apiFetch(`${API_BASE}/monitor/metrics?range=${currentRange}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        document.getElementById('stat-latency').textContent = `${(data.avg_inference_ms || 0).toFixed(1)}ms`;
        document.getElementById('stat-rpm').textContent = (data.predictions_per_minute || 0).toFixed(1);

        const system = data.system || {};
        document.getElementById('mongodb-connections').textContent = system.mongodb_connections || 1;
        document.getElementById('memory-used').textContent = `${system.memory_used_mb || 0} MB`;
        document.getElementById('goroutines').textContent = system.goroutines || 0;
        document.getElementById('sys-dbsize').textContent = formatBytes(system.mongodb_database_size_bytes);

        const rpm = data.predictions_per_minute || 0;
        requestRateHistory.push(rpm);
        if (requestRateHistory.length > MAX_HISTORY) {
            requestRateHistory.shift();
        }
        updateRequestRateChart(requestRateHistory);

        const p50 = data.p50_latency_ms || 0;
        const p95 = data.p95_latency_ms || 0;
        const p99 = data.p99_latency_ms || 0;
        updateLatencyBars(p50, p95, p99);

        const errorRate = (data.error_rate || 0) * 100;
        errorRateHistory.push(errorRate);
        if (errorRateHistory.length > MAX_HISTORY) {
            errorRateHistory.shift();
        }
        updateErrorRateChart(errorRateHistory);

    } catch (e) {
        console.error('Error fetching metrics:', e);
    }
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

function updateChartLabels(range) {
    const labelsEl = document.getElementById('request-labels');
    if (!labelsEl) return;

    labelsEl.innerHTML = '';

    const now = new Date();
    const labels = [];

    for (let i = MAX_HISTORY - 1; i >= 0; i--) {
        const time = new Date(now - i * 5000);
        labels.push(time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
    }

    const step = Math.floor(labels.length / 4);
    [0, step, step * 2, labels.length - 1].forEach(idx => {
        const span = document.createElement('span');
        span.textContent = labels[idx];
        labelsEl.appendChild(span);
    });
}

let isReviewing = false;

async function toggleReview() {
    const btn = document.getElementById('sync-btn');
    const icon = document.getElementById('review-icon');
    isReviewing = !isReviewing;

    if (isReviewing) {
        btn.classList.add('active');
        icon.innerHTML = '<rect x="6" y="6" width="12" height="12"></rect>';
        requestRateHistory = [];
        errorRateHistory = [];
        await updateServiceHealth();
        await updateMetrics();
    } else {
        btn.classList.remove('active');
        icon.innerHTML = '<polygon points="5 3 19 12 5 21 5 3"></polygon>';
    }
}

const syncBtn = document.getElementById('sync-btn');
if (syncBtn) {
    syncBtn.addEventListener('click', toggleReview);
}

const lockBtn = document.getElementById('lock-btn');
if (lockBtn) {
    lockBtn.addEventListener('click', () => {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
        window.location.href = '/signin';
    });
}

document.querySelectorAll('.time-range-buttons .graph-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.time-range-buttons .graph-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentRange = btn.dataset.range;
        requestRateHistory = [];
        errorRateHistory = [];
        updateChartLabels(currentRange);
        updateMetrics();
    });
});

updateServiceHealth();
updateMetrics();
updateChartLabels(currentRange);

setInterval(() => {
    updateServiceHealth();
    updateMetrics();
}, 2000);
