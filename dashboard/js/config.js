const CONFIG_KEY = "modintel.dashboard.config";
const DEFAULT_REVIEW_API = window.location.origin;

function getSavedConfig() {
    try {
        const raw = localStorage.getItem(CONFIG_KEY);
        if (!raw) {
            return { reviewApiBase: DEFAULT_REVIEW_API };
        }
        const parsed = JSON.parse(raw);
        return {
            reviewApiBase: parsed.reviewApiBase || DEFAULT_REVIEW_API
        };
    } catch (_) {
        return { reviewApiBase: DEFAULT_REVIEW_API };
    }
}

function saveConfig() {
    const input = document.getElementById("cfg-review-api");
    const value = (input.value || "").trim().replace(/\/$/, "");
    const config = {
        reviewApiBase: value || DEFAULT_REVIEW_API
    };
    localStorage.setItem(CONFIG_KEY, JSON.stringify(config));
    loadRuntimeValues();
}

async function checkReviewApi(baseUrl) {
    const statusEl = document.getElementById("stat-review-api");
    const endpoint = baseUrl === window.location.origin ? "/api/stats" : `${baseUrl}/api/stats`;
    try {
        const res = await fetch(endpoint);
        statusEl.textContent = res.ok ? "Online" : `Error ${res.status}`;
    } catch (_) {
        statusEl.textContent = "Offline";
    }
}

async function checkInference(baseUrl) {
    const statusEl = document.getElementById("stat-inference");
    const modelEl = document.getElementById("stat-model");
    const predEl = document.getElementById("stat-predictions");

    const guessedInference = baseUrl === window.location.origin ? "/inference" : baseUrl.replace(":8082", ":8083");
    try {
        const res = await fetch(`${guessedInference}/health`);
        if (!res.ok) {
            statusEl.textContent = `Error ${res.status}`;
            return;
        }
        const data = await res.json();
        statusEl.textContent = data.status || "Online";
        modelEl.textContent = data.model_version || "unknown";
        predEl.textContent = `${data.total_predictions ?? 0}`;
        document.getElementById("cfg-inference-url").textContent = guessedInference;
    } catch (_) {
        statusEl.textContent = "Unknown";
        modelEl.textContent = "—";
        predEl.textContent = "—";
        document.getElementById("cfg-inference-url").textContent = guessedInference + " (unreachable)";
    }
}

async function loadSystemConfig(baseUrl) {
    const endpoint = baseUrl === window.location.origin ? "/api/config" : `${baseUrl}/api/config`;
    try {
        const res = await fetch(endpoint);
        if (!res.ok) {
            return;
        }
        const data = await res.json();
        document.getElementById("cfg-inference-url").textContent = data.inference_engine_url || "not-set";
        document.getElementById("cfg-upstream-target").textContent = data.backend_target || "not-set";
    } catch (_) {
        // keep defaults if endpoint unavailable
    }
}

function loadRuntimeValues() {
    const cfg = getSavedConfig();
    document.getElementById("cfg-review-api").value = cfg.reviewApiBase;
    document.getElementById("cfg-upstream-target").textContent = "User-defined in deployment (Caddy/compose/env)";
    checkReviewApi(cfg.reviewApiBase);
    checkInference(cfg.reviewApiBase);
    loadSystemConfig(cfg.reviewApiBase);
}

loadRuntimeValues();
