const API_URL = "http://localhost:8000/predict";
let isRunning = false;
let simulationInterval = null;
let logs = [];
let anomalies = [];
let threatCounts = {};

// Button References
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const batchBtn = document.getElementById('batchBtn');
const fileInput = document.getElementById('fileInput');

if (startBtn) {
    startBtn.addEventListener('click', () => {
        isRunning = true;
        startBtn.style.display = 'none';
        if (stopBtn) stopBtn.style.display = 'block';
        startSimulation();
    });
}

if (stopBtn) {
    stopBtn.addEventListener('click', () => {
        isRunning = false;
        if (startBtn) startBtn.style.display = 'block';
        stopBtn.style.display = 'none';
        clearInterval(simulationInterval);
    });
}

if (batchBtn && fileInput) {
    batchBtn.addEventListener('click', () => fileInput.click());
}

if (fileInput) {
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (event) => processBatch(event.target.result);
        reader.readAsText(file);
    });
}

function randomChoice(arr) { 
    return arr[Math.floor(Math.random() * arr.length)]; 
}

function generateRandomLog() {
    const USERS = ["gohul", "naveen", "dharsan", "kishore", "achu", "akshay"];
    const IPS_CORP = ["10.0.0.1", "10.0.1.5", "10.0.2.10", "10.0.3.20", "172.16.0.50"];
    const IPS_EXT = ["192.168.1.100", "198.51.100.42", "203.0.113.7", "45.77.88.99"];
    const EVENTS_NORMAL = ["login", "logout", "access_resource", "create_backup"];
    const EVENTS_ANOMALOUS = ["failed_login", "access_denied", "delete_policy", "modify_policy", "disable_mfa", "export_data", "delete_user", "delete_config", "modify_config", "create_user"];
    
    const isAnom = Math.random() < 0.20; // 20% probability anomalies
    const now = new Date().toISOString().split('T')[0] + ' ' + new Date().toLocaleTimeString();
    let user = randomChoice(USERS);
    let ip;
    let event_type;
    
    if (isAnom) {
        event_type = randomChoice(EVENTS_ANOMALOUS);
        ip = Math.random() < 0.8 ? randomChoice(IPS_EXT) : randomChoice(IPS_CORP);
        if (Math.random() < 0.7) {
            user = "root";
        }
    } else {
        event_type = randomChoice(EVENTS_NORMAL);
        ip = randomChoice(IPS_CORP);
    }
    
    return {
        timestamp: now,
        user: user,
        event: event_type,
        source_ip: ip
    };
}

async function sendPredict(payload) {
    try {
        const res = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res.ok) return await res.json();
    } catch (e) {
        console.error("API Error", e);
    }
    return null;
}

function updateDashboard(log, prediction) {
    if (!prediction) return;
    
    logs.push({ ...log, ...prediction });
    if (prediction.is_anomaly) {
        anomalies.push({ ...log, ...prediction });
        const type = prediction.threat_type || "Unknown";
        threatCounts[type] = (threatCounts[type] || 0) + 1;
    }
    
    // Update Stats
    const totalLogsEl = document.getElementById('statTotal');
    const anomsEl = document.getElementById('statAnom');
    const rateEl = document.getElementById('statRate');
    
    if (totalLogsEl) totalLogsEl.innerText = logs.length;
    if (anomsEl) anomsEl.innerText = anomalies.length;
    
    const rate = logs.length > 0 ? ((anomalies.length / logs.length) * 100).toFixed(1) : 0;
    if (rateEl) rateEl.innerText = `${rate}%`;
    
    // Update Threat Categories
    const total_threats = Object.values(threatCounts).reduce((a, b) => a + b, 0);
    if (total_threats > 0) {
        ['Unauthorized Access', 'SQL Injection', 'Brute Force', 'DDoS Signature'].forEach((threat, idx) => {
            const threatEl = document.getElementById(`threat${idx + 1}`);
            const threatBar = document.getElementById(`threat${idx + 1}-bar`);
            if (threatEl && threatBar) {
                const count = threatCounts[threat] || 0;
                const percent = total_threats > 0 ? ((count / total_threats) * 100).toFixed(0) : 0;
                threatEl.innerText = `${percent}%`;
                threatBar.style.width = `${percent}%`;
            }
        });
    }

    // Update Table
    const tableBody = document.getElementById('logTableBody');
    if (tableBody) {
        const row = document.createElement('tr');
        row.className = 'hover:bg-white/5 transition-colors group cursor-pointer';
        
        const timestamp = new Date(log.timestamp).toLocaleTimeString();
        const score = prediction.anomaly_score;
        const isAnomaly = prediction.is_anomaly;
        
        row.innerHTML = `
            <td class="px-8 py-4 font-label text-xs text-on-surface-variant">${timestamp}</td>
            <td class="px-8 py-4 font-label text-xs text-on-surface">${log.user}</td>
            <td class="px-8 py-4 font-label text-xs">
                <span class="px-2 py-1 rounded bg-surface-variant text-[10px] font-mono ${isAnomaly ? 'text-error' : 'text-primary-fixed'}">${log.event}</span>
            </td>
            <td class="px-8 py-4 font-label text-xs text-on-surface-variant">${log.source_ip}</td>
            <td class="px-8 py-4 font-label text-xs">
                <div class="flex items-center gap-2">
                    <div class="h-1 w-12 bg-surface-container rounded-full">
                        <div class="h-full ${isAnomaly ? 'bg-error' : 'bg-secondary'}" style="width: ${score}%"></div>
                    </div>
                    <span class="${isAnomaly ? 'text-error' : 'text-secondary'}">${(score / 100).toFixed(2)}</span>
                </div>
            </td>
            <td class="px-8 py-4 text-xs">
                <span class="flex items-center gap-2 ${isAnomaly ? 'text-error' : 'text-secondary'} font-bold">
                    <span class="material-symbols-outlined text-sm">${isAnomaly ? 'cancel' : 'check_circle'}</span>
                    ${isAnomaly ? 'Anomaly' : 'Normal'}
                </span>
            </td>
        `;
        
        tableBody.prepend(row);
        if (tableBody.children.length > 15) tableBody.removeChild(tableBody.lastChild);
    }
}

function startSimulation() {
    simulationInterval = setInterval(async () => {
        if (!isRunning) return;
        const log = generateRandomLog();
        const pred = await sendPredict(log);
        updateDashboard(log, pred);
    }, 2000);
}

async function processBatch(csvText) {
    const lines = csvText.trim().split('\n');
    const headers = lines[0].split(',').map(h => h.trim());
    
    logs = [];
    anomalies = [];
    threatCounts = {};
    const tableBody = document.getElementById('logTableBody');
    if (tableBody) tableBody.innerHTML = '';

    for (let i = 1; i < lines.length; i++) {
        if (lines[i].trim().length === 0) continue;
        const values = lines[i].split(',').map(v => v.trim());
        if (values.length < headers.length) continue;
        
        const payload = {};
        for(let idx = 0; idx < headers.length; idx++) {
            if (values[idx]) {
                payload[headers[idx]] = values[idx];
            }
        }
        
        const pred = await sendPredict(payload);
        if (pred) {
            updateDashboard(payload, pred);
        }
        if (i % 5 === 0) await new Promise(r => setTimeout(r, 50));
    }
}

async function resetSystem() {
    try {
        const res = await fetch("/reset", { method: 'POST' });
        if (res.ok) {
            logs = [];
            anomalies = [];
            threatCounts = {};
            
            const tableBody = document.getElementById('logTableBody');
            if (tableBody) tableBody.innerHTML = '';
            
            const totalEl = document.getElementById('statTotal');
            const anomEl = document.getElementById('statAnom');
            const rateEl = document.getElementById('statRate');
            
            if (totalEl) totalEl.innerText = '0';
            if (anomEl) anomEl.innerText = '0';
            if (rateEl) rateEl.innerText = '0%';
            
            console.log("System Reset Successful");
            alert("System history and state have been cleared.");
        }
    } catch (e) {
        console.error("Reset Failed", e);
    }
}
