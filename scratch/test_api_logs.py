import pandas as pd
import requests
import json
import time

def test_api_batch():
    url = "http://127.0.0.1:8000/predict"
    df = pd.read_csv("log.csv")
    
    anomalies = 0
    total = 0
    
    # We need to simulate the batch upload (sequential requests)
    for _, row in df.iterrows():
        payload = {
            "timestamp": str(row['timestamp']),
            "user": str(row['user']),
            "event": str(row['event']),
            "source_ip": str(row.get('source_ip') or row.get('ip'))
        }
        
        try:
            res = requests.post(url, json=payload, timeout=5)
            if res.status_code == 200:
                data = res.json()
                total += 1
                if data.get("is_anomaly"):
                    anomalies += 1
            else:
                print(f"Error: {res.status_code} - {res.text}")
        except Exception as e:
            print(f"Request failed: {e}")
            
    print(f"Total Logs sent: {total}")
    print(f"Anomalies detected by API: {anomalies}")

if __name__ == "__main__":
    # Ensure backend is running before running this
    test_api_batch()
