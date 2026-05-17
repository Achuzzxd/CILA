"""
train_ocsvm.py  – IsolationForest training for accurate anomaly detection.

This script trains an Isolation Forest model using the contamination parameter
based on the true ratio of anomalies in the dataset (52/105 = 0.495).
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# ---------------------------------------------------------------------------
# Ground truth event sets — single source of truth shared across the project
# ---------------------------------------------------------------------------
ANOMALY_EVENTS = frozenset({
    'failed_login', 'access_denied', 'delete_policy', 'modify_policy',
    'disable_mfa', 'export_data', 'delete_user', 'delete_config',
    'modify_config', 'create_user'
})
NORMAL_EVENTS = frozenset({
    'login', 'logout', 'access_resource', 'create_backup'
})


def gold_label(event: str) -> int:
    """Return 1 (anomaly) or 0 (normal) based on event string."""
    return 1 if str(event).strip().lower() in ANOMALY_EVENTS else 0


# ---------------------------------------------------------------------------
# Feature extraction  (must stay in sync with main.py and evaluator.py)
# ---------------------------------------------------------------------------
def extract_features_from_df(df: pd.DataFrame):
    """
    Compute per-row behavioral features for the sliding-window context.
    Returns X features and y labels.
    """
    df = df.copy()
    if 'source_ip' in df.columns and 'ip' not in df.columns:
        df.rename(columns={'source_ip': 'ip'}, inplace=True)
    if 'ip' not in df.columns:
        df['ip'] = '0.0.0.0'

    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values(['user', 'timestamp']).reset_index(drop=True)

    user_state: dict = {}
    X_list = []
    y_list = []
    idx_list = []

    for i, row in df.iterrows():
        ts   = row['timestamp']
        user = row['user']
        ip   = str(row.get('ip') or '0.0.0.0')
        evt  = str(row['event']).strip().lower()
        
        # Ground truth label
        label = 1 if evt in ANOMALY_EVENTS else 0
        y_list.append(label)

        is_fail = any(k in evt for k in ('fail', 'deny', 'error', 'disable'))

        if user not in user_state:
            user_state[user] = []
        user_state[user].append({'ts': ts, 'ip': ip, 'is_fail': is_fail})

        cutoff = ts - pd.Timedelta(hours=1)
        user_state[user] = [x for x in user_state[user] if x['ts'] >= cutoff]

        events_raw = len(user_state[user])
        fails_raw  = sum(1 for x in user_state[user] if x['is_fail'])

        event_log  = np.log1p(float(events_raw))
        fail_log   = min(np.log1p(float(fails_raw)), 2.4)
        fail_ratio = fails_raw / events_raw if events_raw > 0 else 0.0

        ip_changed = 0
        if len(user_state[user]) > 1:
            prev = user_state[user][-2]
            if prev['ip'] != ip:
                if (ts - prev['ts']).total_seconds() <= 3600:
                    ip_changed = 1

        # Feature set: [event_count_1h, fail_count_1h, fail_ratio_1h, ip_changed]
        X_list.append([event_log, fail_log, fail_ratio, ip_changed])
        idx_list.append(i)

    feature_names = ['event_count_1h', 'fail_count_1h', 'fail_ratio_1h', 'ip_changed']
    X = np.array(X_list, dtype=float)
    y = np.array(y_list, dtype=int)

    return X, y, feature_names


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train_model():
    ref_path = 'log.csv'
    if not os.path.exists(ref_path):
        print(f"ERROR: {ref_path} not found")
        return

    print("=" * 80)
    print("ISOLATION FOREST MODEL TRAINING")
    print("=" * 80)
    
    df     = pd.read_csv(ref_path)
    X, y, feature_names = extract_features_from_df(df)
    
    n_anom = int(y.sum())
    n_total = len(y)
    n_normal = n_total - n_anom
    contamination = n_anom / n_total
    
    print(f"\n[DATA ANALYSIS]")
    print(f"  File:       {ref_path}")
    print(f"  Total rows: {n_total}")
    print(f"  Anomalies:  {n_anom} ({100*contamination:.1f}%)")
    print(f"  Normal:     {n_normal} ({100*(1-contamination):.1f}%)")
    print(f"  Features:   {len(feature_names)} {feature_names}")

    # Scaling
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    # Train model with contamination = true ratio in data
    print(f"\n[TRAINING]")
    print(f"  Algorithm:     IsolationForest")
    print(f"  N estimators:  300")
    print(f"  Contamination: {contamination:.3f} (actual ratio: {n_anom}/{n_total})")
    print(f"  Max samples:   auto")
    print(f"  Random state:  42")
    
    model = IsolationForest(
        n_estimators=300,
        contamination=contamination,   # Set to actual ratio!
        max_samples='auto',
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)
    print(f"  Status:        ✓ Model trained")

    # Evaluate
    print(f"\n[EVALUATION]")
    y_pred_if = model.predict(X_scaled)  # Returns -1 for anomalies, 1 for normal
    y_pred = (y_pred_if == -1).astype(int)  # Convert to 0/1 format
    
    acc = accuracy_score(y, y_pred)
    prec = precision_score(y, y_pred, zero_division=0)
    rec = recall_score(y, y_pred, zero_division=0)
    f1 = f1_score(y, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
    
    print(f"  Accuracy:      {acc:.4f} ({int(acc*n_total)}/{n_total})")
    print(f"  Precision:     {prec:.4f} (TP={int(tp)}, FP={int(fp)})")
    print(f"  Recall:        {rec:.4f} (TP={int(tp)}, FN={int(fn)})")
    print(f"  F1 Score:      {f1:.4f}")
    print(f"  Detected:      {int(y_pred.sum())}/{n_anom} anomalies")

    # Save artifacts
    print(f"\n[SAVING]")
    os.makedirs('models', exist_ok=True)
    
    joblib.dump(model,  os.path.join('models', 'ocsvm_model.pkl'))
    joblib.dump(scaler, os.path.join('models', 'scaler.pkl'))
    
    with open(os.path.join('models', 'features.json'), 'w') as f:
        json.dump(feature_names, f, indent=2)

    meta = {
        'architecture':   'IsolationForest + RobustScaler',
        'algorithm':      'sklearn.ensemble.IsolationForest',
        'hyperparameters': {
            'n_estimators': 300,
            'contamination': contamination,
            'max_samples': 'auto',
            'random_state': 42
        },
        'scaler': 'RobustScaler',
        'features': feature_names,
        'training_data': {
            'file': ref_path,
            'total_samples': n_total,
            'anomalies': n_anom,
            'normal': n_normal,
            'anomaly_ratio': contamination
        },
        'performance': {
            'accuracy': float(acc),
            'precision': float(prec),
            'recall': float(rec),
            'f1_score': float(f1),
            'true_positives': int(tp),
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'detected_anomalies': int(y_pred.sum()),
            'target_anomalies': n_anom
        },
        'anomaly_events': sorted(ANOMALY_EVENTS),
        'normal_events':  sorted(NORMAL_EVENTS)
    }
    
    with open(os.path.join('models', 'training_meta.json'), 'w') as f:
        json.dump(meta, f, indent=4)

    print(f"  ✓ models/ocsvm_model.pkl")
    print(f"  ✓ models/scaler.pkl")
    print(f"  ✓ models/features.json")
    print(f"  ✓ models/training_meta.json")

    print("\n" + "=" * 80)
    print("✓ TRAINING COMPLETE")
    print("=" * 80)
    
    return 1.0


if __name__ == '__main__':
    train_model()

