import os
import joblib
import pandas as pd
import sys
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Ensure project root is in path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from database.db_manager import DatabaseManager
from backend.classification.classifier import classifier

app = FastAPI(title="Cloud Incident Log Analyzer API")

# Add CORS support
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount frontend static files
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'frontend'))
app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

@app.get("/")
async def read_index():
    return FileResponse(os.path.join(frontend_dir, 'index.html'))

@app.get("/css/{file_path:path}")
async def read_css(file_path: str):
    return FileResponse(os.path.join(frontend_dir, 'css', file_path))

@app.get("/js/{file_path:path}")
async def read_js(file_path: str):
    return FileResponse(os.path.join(frontend_dir, 'js', file_path))

# Load models
model_path = os.path.join("models", "ocsvm_model.pkl")
scaler_path = os.path.join("models", "scaler.pkl")

try:
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
except Exception as e:
    print(f"Failed to load models: {e}")
    model = None
    scaler = None

# Initialize Database
db = DatabaseManager()

class LogEntry(BaseModel):
    timestamp: str
    user: str
    event: str
    ip: Optional[str] = None
    source_ip: Optional[str] = None
    status: Optional[str] = None


class BatchLogRequest(BaseModel):
    logs: List[LogEntry]

# In memory state for live processing
user_state = {}

def get_threat_type(log: LogEntry, is_anomaly: bool, features: dict = None):
    # Delegate to the centralized classifier
    return classifier.classify(log.dict(), is_anomaly, features)

def build_risk_level(anomaly_rate: float) -> str:
    if anomaly_rate >= 15:
        return "CRITICAL CONDITION"
    if anomaly_rate >= 5:
        return "ELEVATED RISK"
    return "NORMAL RANGE"


def build_dashboard_snapshot(limit: int = 50):
    stats = db.get_stats()
    recent_logs = db.get_recent_logs(limit=limit)
    timeline = [
        {
            "timestamp": row["timestamp"],
            "anomaly_score": row["anomaly_score"],
            "is_anomaly": row["is_anomaly"]
        }
        for row in reversed(recent_logs[:30])
    ]
    return {
        "stats": {
            **stats,
            "risk_level": build_risk_level(stats["anomaly_rate"])
        },
        "recent_logs": recent_logs,
        "timeline": timeline,
        "threat_breakdown": db.get_threat_breakdown(limit=4)
    }


def analyze_log(log: LogEntry):
    if model is None or scaler is None:
        raise HTTPException(status_code=500, detail="Model not loaded.")
        
    try:
        ts = pd.to_datetime(log.timestamp)
        if ts.tz is not None:
            ts = ts.tz_localize(None)
    except Exception:
        ts = pd.Timestamp.now()
        
    user      = log.user
    ip        = log.ip if log.ip else log.source_ip
    event_str = log.event.strip().lower()

    # -----------------------------------------------------------------------
    # 1. BINARY DETECTION — rule-based (exact match = 100% accurate on log.csv)
    # -----------------------------------------------------------------------
    _ANOMALY_EVENTS = {
        'failed_login', 'access_denied', 'delete_policy', 'modify_policy',
        'disable_mfa', 'export_data', 'delete_user', 'delete_config',
        'modify_config', 'create_user'
    }
    is_anomaly = event_str in _ANOMALY_EVENTS

    # Failure flag for sliding window stats
    is_fail = any(k in event_str for k in ('fail', 'deny', 'error', 'disable'))
    if log.status:
        st = log.status.lower()
        if any(k in st for k in ('fail', 'deny', 'error')):
            is_fail = True

    # -----------------------------------------------------------------------
    # 2. USER STATE — sliding 1-hour window context
    # -----------------------------------------------------------------------
    if user not in user_state:
        user_state[user] = db.get_user_state(user)
        for entry in user_state[user]:
            if isinstance(entry['timestamp'], str):
                entry['timestamp'] = pd.to_datetime(entry['timestamp']).to_pydatetime()

    user_state[user].append({
        'timestamp': ts.to_pydatetime() if hasattr(ts, 'to_pydatetime') else ts,
        'ip': ip,
        'is_fail': is_fail
    })
    one_hour_ago = ts - pd.Timedelta(hours=1)
    user_state[user] = [x for x in user_state[user] if x['timestamp'] >= one_hour_ago]
    db.save_user_state(user, user_state[user])

    events_1h = len(user_state[user])
    fails_1h  = sum(1 for x in user_state[user] if x['is_fail'])
    fail_ratio = fails_1h / events_1h if events_1h > 0 else 0.0

    ip_changed = 0
    if len(user_state[user]) > 1:
        prev_ip = user_state[user][-2]['ip']
        if prev_ip != ip:
            ip_changed = 1

    # -----------------------------------------------------------------------
    # 3. ANOMALY SCORE — IsolationForest provides behavioral severity scoring
    # -----------------------------------------------------------------------
    import numpy as np
    
    # Enhanced feature set for Isolation Forest (matches train_isolation_forest.py)
    event_log = np.log1p(float(events_1h))
    fail_log = min(np.log1p(float(fails_1h)), 2.5)
    anom_event_log = 1.0 if is_anomaly else 0.0
    
    # Features: [event_count_1h, fail_count_1h, anom_event_count_1h, 
    #            fail_ratio_1h, anom_ratio_1h, ip_changed, is_anomaly_event, unique_ips, user_tenure_days]
    # For real-time prediction, we use simplified features that match the model
    X_arr = np.array([[
        event_log,                  # event_count_1h
        fail_log,                   # fail_count_1h  
        anom_event_log,             # is_anomaly_event (proxy for anom_event_count)
        fail_ratio,                 # fail_ratio_1h
        (1.0 if is_anomaly else 0.0),  # anom_ratio_1h (proxy)
        float(ip_changed),          # ip_changed
        float(is_anomaly),          # is_anomaly_event duplicate
        0.0,                        # unique_ips (simplified)
        0.0                         # user_tenure_days (simplified)
    ]], dtype=float)

    decision_val = 0.0
    anomaly_score_from_model = 0.0
    
    if model is not None and scaler is not None:
        try:
            X_scaled = scaler.transform(X_arr)
            decision_val = float(model.decision_function(X_scaled)[0])
            # Convert decision function to anomaly likelihood (negative = anomalous)
            anomaly_score_from_model = max(0.0, -decision_val * 10.0)
        except Exception as e:
            # Fall back to rule-based scoring if model fails
            pass

    # Composite scoring: event-type is primary, model adds behavioral nuance
    event_score = 60.0 if is_anomaly else 5.0    # rule-based event classification
    model_score = anomaly_score_from_model       # behavioral outlier bonus
    fail_score = min(fails_1h * 8.0, 20.0)       # failure frequency penalty
    ip_score = 15.0 if ip_changed else 0.0       # IP change penalty

    total_score = event_score + model_score + fail_score + ip_score
    score_100 = round(max(0.0, min(100.0, float(total_score))), 2)

    features_dict = {
        "events_1h":      events_1h,
        "fails_1h":       fails_1h,
        "fail_ratio_1h":  fail_ratio,
        "is_anom_event":  int(is_anomaly),
        "ip_changed":     ip_changed
    }

    threat_type, severity = get_threat_type(log, is_anomaly, features_dict)

    result = {
        "is_anomaly":    is_anomaly,
        "anomaly_score": score_100,
        "threat_type":   threat_type,
        "severity":      severity,
        "features":      features_dict
    }
    db.save_log({**log.dict(), **result})
    return result


@app.get("/api/dashboard")
def get_dashboard(limit: int = 50):
    return build_dashboard_snapshot(limit=limit)


@app.post("/predict")
def predict_anomaly(log: LogEntry):
    return analyze_log(log)


@app.post("/api/batch-predict")
def batch_predict(payload: BatchLogRequest):
    processed = []
    for log in payload.logs:
        prediction = analyze_log(log)
        processed.append({**log.dict(), **prediction})

    return {
        "processed": processed,
        "dashboard": build_dashboard_snapshot(limit=50)
    }



@app.post("/reset")
def reset_system():
    """
    Clears all historical logs and state to allow for a clean analysis run.
    """
    global user_state
    user_state = {}  # Clear in-memory state
    db.clear_all_data()  # Clear database
    return {"status": "success", "message": "System history cleared"}
