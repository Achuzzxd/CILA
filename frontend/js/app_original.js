const API_URL = "/predict";
let isRunning = false;
let simulationInterval = null;
let logs = [];
let anomalies = [];
let threatCounts = {};

// Sidebar Toggle
const sidebar = document.getElementById('sidebar');
const sidebarToggle = document.getElementById('sidebarToggle');

if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener('click', (e) => {
        e.stopPropagation();
        sidebar.classList.toggle('sidebar-closed');
    });
}

// Close sidebar when clicking outside on mobile
document.addEventListener('click', (e) => {
    if (sidebar && !sidebar.contains(e.target) && !sidebarToggle.contains(e.target)) {
        if (window.innerWidth <= 768) {
            sidebar.classList.add('sidebar-closed');
        }
    }
});

// 1. Initialize Charts
const timelineOptions = {
    series: [{ name: 'Anomaly Score', data: [] }],
    chart: { type: 'area', height: 300, toolbar: { show: false }, animations: { enabled: true, easing: 'linear', dynamicAnimation: { speed: 1000 } }},
    colors: ['#3d5afe'],
    fill: { type: 'gradient', gradient: { shadeIntensity: 1, opacityFrom: 0.45, opacityTo: 0.05, stops: [20, 100, 100, 100] }},
    dataLabels: { enabled: false },
    stroke: { curve: 'smooth', width: 3 },
    xaxis: { type: 'datetime', labels: { show: false }, axisBorder: { show: false }, axisTicks: { show: false }},
    yaxis: { min: 0, max: 100, tickAmount: 4, labels: { style: { colors: '#b0b3b8' } }},
    grid: { borderColor: 'rgba(255,255,255,0.05)', strokeDashArray: 4 }
};

const donutOptions = {
    series: [],
    chart: { type: 'donut', height: 300 },
    labels: [],
    colors: ['#ff3d71', '#ffaa00', '#3d5afe', '#00e096', '#7b1fa2'],
    legend: { position: 'bottom', labels: { colors: '#e4e6eb' }},
    plotOptions: { pie: { donut: { size: '65%', labels: { show: true, name: { color: '#e4e6eb' }, value: { color: '#e4e6eb' }, total: { show: true, label: 'Alerts', color: '#b0b3b8' } } } }},
    stroke: { show: false }
};

const timelineChart = new ApexCharts(document.querySelector("#timelineChart"), timelineOptions);
const donutChart = new ApexCharts(document.querySelector("#donutChart"), donutOptions);

timelineChart.render();
donutChart.render();

// 2. Logic & Interactions
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const batchBtn = document.getElementById('batchBtn');
const fileInput = document.getElementById('fileInput');

if (startBtn) {
    startBtn.addEventListener('click', () => {
        isRunning = true;
        startBtn.style.display = 'none';
        stopBtn.style.display = 'block';
        startSimulation();
    });
}

if (stopBtn) {
    stopBtn.addEventListener('click', () => {
        isRunning = false;
        stopBtn.style.display = 'none';
        startBtn.style.display = 'block';
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

function randomChoice(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

function generateRandomLog() {
    const USERS = ["gohul", "naveen", "dharsan", "kishore", "achu", "akshay"];
    const IPS = ["10.0.0.1", "10.0.1.5", "10.0.2.10", "10.0.3.20", "172.16.0.50"];
    const EVENTS_NORMAL = ["login", "logout", "access_resource", "create_backup"];
    const EVENTS_ANOMALOUS = ["failed_login", "access_denied", "delete_policy", "modify_policy", "disable_mfa", "export_data", "delete_user", "delete_config", "modify_config", "create_user"];
    
    const isAnom = Math.random() < 0.20; // 20% probability anomalies
    return {
        timestamp: new Date().toISOString(),
        user: randomChoice(USERS),
        event: isAnom ? randomChoice(EVENTS_ANOMALOUS) : randomChoice(EVENTS_NORMAL),
        source_ip: isAnom ? `198.51.100.${Math.floor(Math.random() * 255)}` : randomChoice(IPS)
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
        const type = prediction.threat_type;
        threatCounts[type] = (threatCounts[type] || 0) + 1;
    }
    
    // Update Stats
    document.getElementById('statTotal').innerText = logs.length;
    document.getElementById('statAnom').innerText = anomalies.length;
    const rate = ((anomalies.length / logs.length) * 100).toFixed(1);
    document.getElementById('statRate').innerText = `${rate}%`;
    
    const riskEl = document.getElementById('riskLevel');
    if (rate > 15) {
        riskEl.innerText = "CRITICAL CONDITION";
        riskEl.style.background = "rgba(255, 61, 113, 0.2)";
        riskEl.style.color = "var(--accent-red)";
    } else if (rate > 5) {
        riskEl.innerText = "ELEVATED RISK";
        riskEl.style.background = "rgba(255, 170, 0, 0.2)";
        riskEl.style.color = "var(--accent-orange)";
    } else {
        riskEl.innerText = "NORMAL RANGE";
        riskEl.style.background = "rgba(0, 224, 150, 0.2)";
        riskEl.style.color = "var(--accent-green)";
    }

    // Update Chart
    const recent = logs.slice(-30);
    const seriesData = recent.map(l => ({ x: new Date(l.timestamp).getTime(), y: l.anomaly_score }));
    timelineChart.updateSeries([{ data: seriesData }]);
    
    // Update Donut
    if (anomalies.length > 0) {
        donutChart.updateOptions({
            labels: Object.keys(threatCounts),
            series: Object.values(threatCounts)
        });
    }

    // Update Table
    const tableBody = document.getElementById('logTableBody');
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${new Date(log.timestamp).toLocaleTimeString()}</td>
        <td>${log.user}</td>
        <td>${log.event}</td>
        <td>${log.source_ip || log.ip}</td>
        <td style="font-weight:700; color: ${prediction.anomaly_score > 50 ? 'var(--accent-red)' : 'var(--text-main)'}">${prediction.anomaly_score}</td>
        <td><span class="badge ${prediction.is_anomaly ? 'badge-anomaly' : 'badge-normal'}">${prediction.is_anomaly ? 'ANOMALY' : 'NORMAL'}</span></td>
    `;
    tableBody.prepend(row);
    if (tableBody.children.length > 15) tableBody.removeChild(tableBody.lastChild);
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
    const headers = lines[0].split(',');
    
    logs = [];
    anomalies = [];
    threatCounts = {};
    document.getElementById('logTableBody').innerHTML = '';

    for (let i = 1; i < lines.length; i++) {
        if (lines[i].trim().length === 0) continue;
        const values = lines[i].split(',');
        if (values.length < headers.length) continue;
        
        const payload = {};
        for(let idx=0; idx < headers.length; idx++) {
            if (values[idx]) {
                payload[headers[idx].trim()] = values[idx].trim();
            }
        }
        
        const pred = await sendPredict(payload);
        if (pred) {
            updateDashboard(payload, pred);
        }
        // Small delay so it feels like it's processing
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
            document.getElementById('logTableBody').innerHTML = '';
            document.getElementById('statTotal').innerText = '0';
            document.getElementById('statAnom').innerText = '0';
            document.getElementById('statRate').innerText = '0%';
            
            // Clear Charts
            timelineChart.updateSeries([{ data: [] }]);
            donutChart.updateOptions({ series: [], labels: [] });
            
            console.log("System Reset Successful");
            alert("System history and state have been cleared.");
        }
    } catch (e) {
        console.error("Reset Failed", e);
    }
}
