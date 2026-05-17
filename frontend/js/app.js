const API_BASE = window.location.origin;
const ENDPOINTS = {
    predict: `${API_BASE}/predict`,
    batchPredict: `${API_BASE}/api/batch-predict`,
    dashboard: `${API_BASE}/api/dashboard`,
    reset: `${API_BASE}/reset`
};

const NORMAL_EVENTS = ["login", "logout", "access_resource", "create_backup", "list_instances"];
const ANOMALOUS_EVENTS = [
    "failed_login",
    "access_denied",
    "delete_policy",
    "modify_policy",
    "disable_mfa",
    "export_data",
    "delete_user",
    "delete_config",
    "modify_config",
    "create_user"
];
const USERS = ["admin", "security", "devops", "analyst", "root", "service"];
const IPS_INTERNAL = ["10.0.0.14", "10.0.2.8", "10.1.1.22", "172.16.0.11"];
const IPS_EXTERNAL = ["45.77.88.99", "198.51.100.42", "203.0.113.7", "103.21.244.0"];

const state = {
    isRunning: false,
    timerId: null,
    timeline: [],
    tickInFlight: false
};

const ui = {
    startBtn: document.getElementById("startBtn"),
    startBtnText: document.getElementById("startBtnText"),
    batchBtn: document.getElementById("batchBtn"),
    resetBtn: document.getElementById("resetBtn"),
    fileInput: document.getElementById("fileInput"),
    controlStatus: document.getElementById("controlStatus"),
    riskPill: document.getElementById("riskPill"),
    statTotal: document.getElementById("statTotal"),
    statAnom: document.getElementById("statAnom"),
    statRate: document.getElementById("statRate"),
    statLatency: document.getElementById("statLatency"),
    logTableBody: document.getElementById("logTableBody"),
    threatList: document.getElementById("threatList"),
    threatEmpty: document.getElementById("threatEmpty"),
    timelineCanvas: document.getElementById("timelineCanvas")
};

function setStatus(message) {
    if (ui.controlStatus) {
        ui.controlStatus.textContent = message;
    }
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function pickRandom(list) {
    return list[Math.floor(Math.random() * list.length)];
}

function generateRandomLog() {
    const isAnomaly = Math.random() < 0.2;
    const event = isAnomaly ? pickRandom(ANOMALOUS_EVENTS) : pickRandom(NORMAL_EVENTS);
    return {
        timestamp: new Date().toISOString(),
        user: isAnomaly && Math.random() < 0.6 ? "root" : pickRandom(USERS),
        event,
        source_ip: isAnomaly && Math.random() < 0.8 ? pickRandom(IPS_EXTERNAL) : pickRandom(IPS_INTERNAL),
        status: event.includes("failed") || event.includes("denied") ? "failed" : "success"
    };
}

async function postJson(url, payload) {
    const start = performance.now();
    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });

    if (!response.ok) {
        throw new Error(`Request failed (${response.status})`);
    }
    const elapsed = Math.round(performance.now() - start);
    if (ui.statLatency) {
        ui.statLatency.textContent = `~${elapsed}ms`;
    }
    return response.json();
}

async function fetchDashboard(limit = 50) {
    const response = await fetch(`${ENDPOINTS.dashboard}?limit=${limit}`);
    if (!response.ok) {
        throw new Error(`Dashboard fetch failed (${response.status})`);
    }
    return response.json();
}

function setRiskPill(riskLevel) {
    if (!ui.riskPill) return;
    ui.riskPill.textContent = riskLevel || "NORMAL RANGE";
    ui.riskPill.classList.remove("risk-normal", "risk-elevated", "risk-critical");

    if ((riskLevel || "").includes("CRITICAL")) {
        ui.riskPill.classList.add("risk-critical");
        return;
    }
    if ((riskLevel || "").includes("ELEVATED")) {
        ui.riskPill.classList.add("risk-elevated");
        return;
    }
    ui.riskPill.classList.add("risk-normal");
}

function renderStats(stats) {
    if (!stats) return;
    if (ui.statTotal) ui.statTotal.textContent = String(stats.total_logs ?? 0);
    if (ui.statAnom) ui.statAnom.textContent = String(stats.total_anomalies ?? 0);
    if (ui.statRate) ui.statRate.textContent = `${Number(stats.anomaly_rate || 0).toFixed(1)}%`;
    setRiskPill(stats.risk_level);
}

function renderThreats(threatBreakdown) {
    if (!ui.threatList || !ui.threatEmpty) return;
    ui.threatList.innerHTML = "";
    const hasData = Array.isArray(threatBreakdown) && threatBreakdown.length > 0;
    ui.threatEmpty.style.display = hasData ? "none" : "block";

    if (!hasData) return;

    threatBreakdown.forEach((item) => {
        const row = document.createElement("div");
        row.className = "threat-item";
        const pct = Number(item.percentage || 0).toFixed(1);
        row.innerHTML = `
            <div class="threat-item-header">
                <span class="threat-name">${escapeHtml(item.threat_type || "Unknown")}</span>
                <span class="threat-count">${item.count || 0} (${pct}%)</span>
            </div>
            <div class="threat-track">
                <div class="threat-fill" style="width: ${Math.max(2, Math.min(100, Number(item.percentage || 0)))}%"></div>
            </div>
        `;
        ui.threatList.appendChild(row);
    });
}

function renderTable(recentLogs) {
    if (!ui.logTableBody) return;
    ui.logTableBody.innerHTML = "";

    if (!Array.isArray(recentLogs) || recentLogs.length === 0) {
        ui.logTableBody.innerHTML = '<tr class="placeholder-row"><td colspan="6">No logs processed yet.</td></tr>';
        return;
    }

    recentLogs.forEach((log) => {
        const isAnomaly = Boolean(log.is_anomaly);
        const score = Number(log.anomaly_score || 0);
        const time = new Date(log.timestamp || Date.now()).toLocaleTimeString();
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${escapeHtml(time)}</td>
            <td>${escapeHtml(log.user || "-")}</td>
            <td><span class="event-chip">${escapeHtml(log.event || "-")}</span></td>
            <td>${escapeHtml(log.source_ip || "-")}</td>
            <td>
                <div class="score-cell">
                    <span class="score-track">
                        <span class="score-fill ${isAnomaly ? "score-fill-anomaly" : "score-fill-normal"}" style="width: ${Math.max(2, Math.min(100, score))}%"></span>
                    </span>
                    <span class="score-value">${score.toFixed(1)}</span>
                </div>
            </td>
            <td><span class="result-badge ${isAnomaly ? "result-anomaly" : "result-normal"}">${isAnomaly ? "ANOMALY" : "NORMAL"}</span></td>
        `;
        ui.logTableBody.appendChild(row);
    });
}

function drawTimeline(timeline) {
    if (!ui.timelineCanvas) return;
    const canvas = ui.timelineCanvas;
    const parentWidth = canvas.parentElement ? canvas.parentElement.clientWidth : 640;
    const width = Math.max(320, parentWidth);
    const height = canvas.clientHeight || 390;
    canvas.width = width;
    canvas.height = height;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = "rgba(67, 96, 255, 0.10)";
    ctx.fillRect(0, 0, width, height);

    if (!Array.isArray(timeline) || timeline.length < 2) {
        ctx.fillStyle = "rgba(215, 219, 230, 0.72)";
        ctx.font = "14px Inter";
        ctx.fillText("Waiting for enough datapoints...", 20, 34);
        return;
    }

    const pad = 24;
    const chartW = width - pad * 2;
    const chartH = height - pad * 2;

    ctx.strokeStyle = "rgba(124, 146, 186, 0.30)";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i += 1) {
        const y = pad + (chartH / 4) * i;
        ctx.beginPath();
        ctx.moveTo(pad, y);
        ctx.lineTo(width - pad, y);
        ctx.stroke();
    }

    ctx.beginPath();
    timeline.forEach((point, index) => {
        const score = Math.max(0, Math.min(100, Number(point.anomaly_score || 0)));
        const x = pad + (index / (timeline.length - 1)) * chartW;
        const y = pad + chartH - (score / 100) * chartH;
        if (index === 0) {
            ctx.moveTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }
    });
    ctx.strokeStyle = "#8aa4ff";
    ctx.lineWidth = 2;
    ctx.stroke();
}

async function refreshDashboard() {
    const snapshot = await fetchDashboard(50);
    renderStats(snapshot.stats);
    renderThreats(snapshot.threat_breakdown);
    renderTable(snapshot.recent_logs);
    state.timeline = snapshot.timeline || [];
    drawTimeline(state.timeline);
}

function setRunningState(nextState) {
    state.isRunning = nextState;
    if (!ui.startBtn || !ui.startBtnText) return;

    if (state.isRunning) {
        ui.startBtn.classList.add("is-running");
        ui.startBtnText.textContent = "Stop Live Tracking";
        setStatus("Live tracking started. Generating and analyzing cloud events.");
        return;
    }
    ui.startBtn.classList.remove("is-running");
    ui.startBtnText.textContent = "Go Live Tracking";
    setStatus("Live tracking stopped.");
}

async function tickLiveMode() {
    if (state.tickInFlight) return;
    state.tickInFlight = true;
    try {
        const randomLog = generateRandomLog();
        await postJson(ENDPOINTS.predict, randomLog);
        await refreshDashboard();
    } catch (error) {
        console.error(error);
        setStatus("Live tracking error. Verify backend server is running on port 8000.");
        stopLiveMode();
    } finally {
        state.tickInFlight = false;
    }
}

function startLiveMode() {
    if (state.timerId) return;
    setRunningState(true);
    tickLiveMode();
    state.timerId = window.setInterval(() => {
        if (!state.isRunning) return;
        tickLiveMode();
    }, 1800);
}

function stopLiveMode() {
    setRunningState(false);
    if (state.timerId) {
        window.clearInterval(state.timerId);
        state.timerId = null;
    }
}

function parseCsvLine(line) {
    const out = [];
    let current = "";
    let inQuotes = false;

    for (let i = 0; i < line.length; i += 1) {
        const ch = line[i];
        if (ch === '"') {
            const next = line[i + 1];
            if (inQuotes && next === '"') {
                current += '"';
                i += 1;
            } else {
                inQuotes = !inQuotes;
            }
        } else if (ch === "," && !inQuotes) {
            out.push(current.trim());
            current = "";
        } else {
            current += ch;
        }
    }
    out.push(current.trim());
    return out;
}

function parseCsvToLogs(csvText) {
    const lines = csvText.split(/\r?\n/).filter((line) => line.trim().length > 0);
    if (lines.length <= 1) return [];

    const headers = parseCsvLine(lines[0]).map((header) => header.trim());
    const logs = [];

    for (let i = 1; i < lines.length; i += 1) {
        const values = parseCsvLine(lines[i]).map((value) => value.trim());
        const row = {};
        headers.forEach((header, idx) => {
            row[header] = values[idx] || "";
        });
        if (row.timestamp && row.user && row.event) {
            logs.push({
                timestamp: row.timestamp,
                user: row.user,
                event: row.event,
                source_ip: row.source_ip || row.ip || "",
                status: row.status || undefined
            });
        }
    }
    return logs;
}

async function handleBatchUpload(file) {
    try {
        if (ui.batchBtn) ui.batchBtn.disabled = true;
        const csvText = await file.text();
        const logs = parseCsvToLogs(csvText);
        if (logs.length === 0) {
            setStatus("No valid logs found in CSV. Expected timestamp,user,event columns.");
            return;
        }

        setStatus(`Uploading ${logs.length} logs for analysis...`);
        await postJson(ENDPOINTS.batchPredict, { logs });
        await refreshDashboard();
        setStatus(`Batch upload complete. Processed ${logs.length} logs.`);
    } catch (error) {
        console.error(error);
        setStatus("Batch upload failed. Please verify CSV format and backend availability.");
    } finally {
        if (ui.batchBtn) ui.batchBtn.disabled = false;
    }
}

async function handleReset() {
    try {
        await postJson(ENDPOINTS.reset, {});
        await refreshDashboard();
        setStatus("Dashboard reset complete. Historical logs cleared.");
    } catch (error) {
        console.error(error);
        setStatus("Reset failed. Try again after backend is reachable.");
    }
}

function bindEvents() {
    if (ui.startBtn) {
        ui.startBtn.addEventListener("click", () => {
            if (state.isRunning) {
                stopLiveMode();
                return;
            }
            startLiveMode();
        });
    }

    if (ui.batchBtn && ui.fileInput) {
        ui.batchBtn.addEventListener("click", () => ui.fileInput.click());
        ui.fileInput.addEventListener("change", async (event) => {
            const target = event.target;
            const file = target.files && target.files[0];
            if (file) {
                await handleBatchUpload(file);
            }
            target.value = "";
        });
    }

    if (ui.resetBtn) {
        ui.resetBtn.addEventListener("click", handleReset);
    }

    window.addEventListener("resize", () => drawTimeline(state.timeline));
}

document.addEventListener("DOMContentLoaded", async () => {
    bindEvents();
    setStatus("Connecting to backend and loading dashboard...");
    try {
        await refreshDashboard();
        setStatus("Ready to monitor real-time cloud events.");
    } catch (error) {
        console.error(error);
        setStatus("Unable to load dashboard. Start backend with: uvicorn backend.api.main:app --reload");
    }
});