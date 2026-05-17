import os
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
import json


# Ground truth event sets - must match train_ocsvm.py exactly
ANOMALY_EVENTS = {
    'failed_login', 'access_denied', 'delete_policy', 'modify_policy',
    'disable_mfa', 'export_data', 'delete_user', 'delete_config',
    'modify_config', 'create_user'
}

NORMAL_EVENTS = {
    'login', 'logout', 'access_resource', 'create_backup'
}


def get_gold_labels(df):
    """
    Labels rows as anomalies (1) or normal (0) based on event type.
    This matches the ground truth.
    """
    return np.array([
        1 if str(row['event']).strip().lower() in ANOMALY_EVENTS else 0
        for _, row in df.iterrows()
    ])


def extract_features(df):
    """Extract 8 features matching train_hybrid.py exactly."""
    df = df.copy()
    
    # Normalize IP column
    if 'source_ip' in df.columns and 'ip' not in df.columns:
        df.rename(columns={'source_ip': 'ip'}, inplace=True)
    if 'ip' not in df.columns:
        df['ip'] = '0.0.0.0'
    
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values(by=['user', 'timestamp']).reset_index(drop=True)
    
    # Event classification sets
    ANOMALY_EVENTS = {
        'failed_login', 'access_denied', 'delete_policy', 'modify_policy',
        'disable_mfa', 'export_data', 'delete_user', 'delete_config',
        'modify_config', 'create_user'
    }
    
    ADMIN_EVENTS = {'delete_user', 'delete_policy', 'modify_policy', 'disable_mfa', 
                    'delete_config', 'modify_config', 'create_user', 'export_data'}
    
    user_state = {}
    X_list = []
    
    for _, row in df.iterrows():
        ts = row['timestamp']
        user = row['user']
        ip = str(row.get('ip') or '0.0.0.0')
        event_str = str(row['event']).strip().lower()
        
        # Event type indicators
        is_fail = any(k in event_str for k in ('fail', 'deny', 'error', 'disable'))
        is_admin = event_str in ADMIN_EVENTS
        is_modify = any(k in event_str for k in ('delete', 'modify', 'disable', 'export'))
        
        if user not in user_state:
            user_state[user] = []
        
        user_state[user].append({
            'timestamp': ts, 
            'ip': ip, 
            'is_fail': is_fail,
            'is_admin': is_admin,
            'is_modify': is_modify
        })
        
        # Sliding 1-hour window
        one_hour_ago = ts - pd.Timedelta(hours=1)
        user_state[user] = [x for x in user_state[user] if x['timestamp'] >= one_hour_ago]
        
        events_raw = len(user_state[user])
        fails_raw = sum(1 for x in user_state[user] if x['is_fail'])
        admin_raw = sum(1 for x in user_state[user] if x['is_admin'])
        modify_raw = sum(1 for x in user_state[user] if x['is_modify'])
        
        event_log = np.log1p(float(events_raw))
        fail_log = min(np.log1p(float(fails_raw)), 2.4)
        fail_ratio = fails_raw / events_raw if events_raw > 0 else 0.0
        admin_ratio = admin_raw / events_raw if events_raw > 0 else 0.0
        modify_ratio = modify_raw / events_raw if events_raw > 0 else 0.0
        
        ip_changed = 0
        if len(user_state[user]) > 1:
            prev = user_state[user][-2]
            if prev['ip'] != ip:
                gap = (ts - prev['timestamp']).total_seconds()
                if gap <= 3600:
                    ip_changed = 1
        
        # 8 features matching train_hybrid.py:
        # ['event_count_1h', 'fail_count_1h', 'fail_ratio_1h', 'admin_ratio_1h', 
        #  'modify_ratio_1h', 'ip_changed', 'is_fail_event', 'is_admin_event']
        X_list.append([
            event_log,
            fail_log,
            fail_ratio,
            admin_ratio,
            modify_ratio,
            float(ip_changed),
            float(is_fail),
            float(is_admin)
        ])
    
    return np.array(X_list, dtype=float)


def evaluate_model(model_path, scaler_path, log_path):
    print("=" * 80)
    print("MODEL EVALUATION")
    print("=" * 80)
    
    print(f"\n[LOADING]")
    print(f"  Model:  {model_path}")
    print(f"  Scaler: {scaler_path}")
    print(f"  Data:   {log_path}")
    
    # Load Model and Scaler
    try:
        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        print(f"  Status: ✓ Loaded successfully")
    except Exception as e:
        print(f"  ERROR: {e}")
        return None
    
    # Load Log Data
    try:
        df = pd.read_csv(log_path)
        print(f"\n[DATA]")
        print(f"  Total samples: {len(df)}")
    except Exception as e:
        print(f"  ERROR: {e}")
        return None
    
    # Extract Features
    print(f"\n[FEATURE EXTRACTION]")
    X = extract_features(df)
    print(f"  Features extracted: {X.shape}")
    
    # Scale and Predict
    print(f"\n[PREDICTION]")
    X_scaled = scaler.transform(X)
    y_pred_if = model.predict(X_scaled)  # -1 = anomaly, 1 = normal
    y_pred = (y_pred_if == -1).astype(int)  # Convert to 1 = anomaly, 0 = normal
    
    # Get Ground Truth
    y_true = get_gold_labels(df)
    
    # Metrics
    print(f"\n[METRICS]")
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    
    print(f"  Accuracy:     {acc:.4f} ({int(acc*len(df))}/{len(df)})")
    print(f"  Precision:    {prec:.4f}")
    print(f"  Recall:       {rec:.4f}")
    print(f"  F1 Score:     {f1:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"    TN={int(tn):3d}  FP={int(fp):3d}")
    print(f"    FN={int(fn):3d}  TP={int(tp):3d}")
    print(f"\n  Detection Rate: {int(y_pred.sum())}/{int(y_true.sum())} anomalies")
    
    metrics = {
        "Total Logs": int(len(y_true)),
        "True Anomalies (Ground Truth)": int(sum(y_true)),
        "Detected Anomalies": int(sum(y_pred)),
        "Accuracy": round(acc, 4),
        "Precision": round(prec, 4),
        "Recall": round(rec, 4),
        "F1 Score": round(f1, 4),
        "True Negatives": int(tn),
        "False Positives": int(fp),
        "False Negatives": int(fn),
        "True Positives": int(tp)
    }
    
    return metrics


if __name__ == "__main__":
    m_path = os.path.join("models", "ocsvm_model.pkl")
    s_path = os.path.join("models", "scaler.pkl")
    l_path = "log.csv"
    
    res = evaluate_model(m_path, s_path, l_path)
    if res:
        print("\n" + "=" * 80)
        print("EVALUATION RESULTS")
        print("=" * 80)
        print(json.dumps(res, indent=2))
        
        # Save results
        os.makedirs('models', exist_ok=True)
        with open("models/eval_baseline.json", "w") as f:
            json.dump(res, f, indent=2)
        print(f"\nResults saved to models/eval_baseline.json")

