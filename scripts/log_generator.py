"""
log_generator.py  –  Live cloud log simulator for CILA.

Generates logs in roughly a 1-in-5 normal-to-anomaly ratio (20% anomalies) and streams them
to the FastAPI /predict endpoint in real-time. Also appends to a CSV for
offline replay.
"""

import time
import random
import datetime
import csv
import os
import json
import urllib.request
import urllib.error

# -----------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------
LOG_FILE   = "live_cloud_logs.csv"
API_URL    = "http://localhost:8000/predict"
INTERVAL   = (1.0, 2.5)      # seconds between events (random range)
ANOM_RATIO = 0.20            # ~20% anomalous events (1 out of 5)

USERS   = ["gohul", "naveen", "dharsan", "kishore", "achu", "akshay", "root"]
IPS_CORP = ["10.0.0.1", "10.0.1.5", "10.0.2.10", "10.0.3.20", "172.16.0.50"]
IPS_EXT  = ["192.168.1.100", "198.51.100.42", "203.0.113.7", "45.77.88.99"]

EVENTS_NORMAL    = ["login", "logout", "access_resource", "create_backup"]
EVENTS_ANOMALOUS = [
    "failed_login", "access_denied", "delete_policy",
    "modify_policy", "disable_mfa", "export_data",
    "delete_user", "delete_config", "modify_config", "create_user"
]

# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------
def choice(lst):
    return random.choice(lst)


def build_log(is_anomaly: bool) -> dict:
    now  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = choice(USERS)

    if is_anomaly:
        event = choice(EVENTS_ANOMALOUS)
        # Make anomalies STRONG (high anomaly score > 50):
        # 80% from external IPs, and 70% chance of root user
        ip    = choice(IPS_EXT) if random.random() < 0.8 else choice(IPS_CORP)
        if random.random() < 0.7:
            user = "root"
    else:
        event = choice(EVENTS_NORMAL)
        ip    = choice(IPS_CORP)

    return {"timestamp": now, "user": user, "event": event, "source_ip": ip}


def send_to_api(payload: dict) -> dict | None:
    """POST the log to the CILA /predict endpoint."""
    try:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            API_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        # Server may not be running – silently skip
        return None
    except Exception:
        return None


def append_csv(log: dict):
    file_exists = os.path.exists(LOG_FILE)
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "user", "event", "source_ip"])
        if not file_exists:
            writer.writeheader()
        writer.writerow(log)


# -----------------------------------------------------------------------
# Main loop
# -----------------------------------------------------------------------
def main():
    print(f"[CILA Live Generator]  anomaly_ratio={ANOM_RATIO*100:.0f}%  "
          f"interval={INTERVAL[0]}–{INTERVAL[1]}s")
    print(f"  API target : {API_URL}")
    print(f"  CSV target : {LOG_FILE}")
    print()

    normal_count = 0
    anom_count   = 0

    while True:
        is_anom = random.random() < ANOM_RATIO
        log     = build_log(is_anom)

        # Append to CSV
        append_csv(log)

        # Send to API
        result = send_to_api(log)

        if is_anom:
            anom_count += 1
        else:
            normal_count += 1

        label   = "ANOMALY" if is_anom else "normal "
        api_tag = ""
        if result:
            detected  = "✓ DETECTED" if result.get("is_anomaly") else "✗ missed  "
            score_val = result.get("anomaly_score", "?")
            api_tag   = f"  API→{detected} score={score_val}"

        print(f"[{label}]  {log['user']:8s}  {log['event']:20s}  {log['source_ip']:18s}{api_tag}")
        print(f"          stats: normal={normal_count}  anomaly={anom_count}  "
              f"ratio={anom_count/(normal_count+anom_count)*100:.1f}%")

        time.sleep(random.uniform(*INTERVAL))


if __name__ == "__main__":
    main()
