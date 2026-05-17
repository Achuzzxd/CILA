import streamlit as st
import pandas as pd
import plotly.express as px
import sys
import os
import requests
import random
import time
from datetime import datetime

# Ensure project root is in path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database.db_manager import DatabaseManager

# Initialize DB connection for reporting
db = DatabaseManager()

# PAGE CONFIG
st.set_page_config(page_title="Cloud Incident Log Analyzer", page_icon="🛡️", layout="wide")

st.title("🛡️ Cloud Incident Log Analyzer (Live Dashboard)")
st.caption("Monitoring real-time cloud anomalies with One-Class SVM Intelligence")

API_URL = "http://127.0.0.1:8000/predict"

if "logs_processed" not in st.session_state:
    st.session_state.logs_processed = []
if "anomalies" not in st.session_state:
    st.session_state.anomalies = []
if "is_running" not in st.session_state:
    st.session_state.is_running = False

# Layout
col1, col2, col3, col4 = st.columns(4)
metric_logs = col1.empty()
metric_anom = col2.empty()
metric_rate = col3.empty()
metric_risk = col4.empty()

st.divider()

chart_col, details_col = st.columns([2, 1])

with chart_col:
    st.subheader("📈 Anomaly Timeline")
    chart_placeholder = st.empty()

with details_col:
    st.subheader("🚨 Threat Classification")
    pie_placeholder = st.empty()
    st.subheader("Recent Threats")
    threats_placeholder = st.empty()

st.divider()

# Sidebar Controls
st.sidebar.header("Controls")
mode = st.sidebar.radio("Operation Mode", ["Live Simulator", "Batch Upload"])

if mode == "Live Simulator":
    if st.sidebar.button("Start Live Analysis", type="primary"):
        st.session_state.is_running = True
        st.session_state.logs_processed = []
        st.session_state.anomalies = []

    if st.sidebar.button("Stop Analysis"):
        st.session_state.is_running = False
else:
    st.session_state.is_running = False # Turn off live if switched
    uploaded_file = st.sidebar.file_uploader("Upload Batch CSV Logs", type=['csv'])

st.sidebar.markdown("---")
st.sidebar.markdown("**System Details**")
st.sidebar.markdown("- **Model:** One-Class SVM")
st.sidebar.markdown("- **Backend:** FastAPI")
st.sidebar.markdown("- **Frontend:** Streamlit")
st.sidebar.markdown("- **Database:** SQLite (clia.db)")

def update_ui():
    stats = db.get_stats()
    total_logs = stats['total_logs']
    total_anom = stats['total_anomalies']
    anom_rate = stats['anomaly_rate']
    
    risk_level = "🟢 LOW" if anom_rate < 5 else ("🟡 MEDIUM" if anom_rate < 15 else "🔴 HIGH")
    
    metric_logs.metric("Total History (DB)", total_logs)
    metric_anom.metric("Anomalies History", total_anom)
    metric_rate.metric("History Anom Rate", f"{anom_rate:.1f}%")
    metric_risk.metric("System Risk Level", risk_level)
    
    if st.session_state.logs_processed:
        # Create a small dataframe for the chart
        recent = st.session_state.logs_processed[-50:]
        df_chart = pd.DataFrame(recent)
        
        # Timeline chart
        chart_df = df_chart[['timestamp', 'anomaly_score']].copy()
        chart_df['timestamp'] = pd.to_datetime(chart_df['timestamp']).dt.strftime("%H:%M:%S")
        fig = px.line(chart_df, x='timestamp', y='anomaly_score', markers=True)
        fig.update_yaxes(range=[0, 100])
        fig.update_layout(margin=dict(l=0, r=0, t=30, b=0), height=300)
        chart_placeholder.plotly_chart(fig, use_container_width=True)
    
    if st.session_state.anomalies:
        anom_df = pd.DataFrame(st.session_state.anomalies)
        counts = anom_df['threat_type'].value_counts().reset_index()
        counts.columns = ['threat_type', 'count']
        fig_pie = px.pie(counts, values='count', names='threat_type', hole=0.5)
        fig_pie.update_traces(textposition='inside', textinfo='percent')
        fig_pie.update_layout(margin=dict(l=0, r=0, t=0, b=0), height=250, showlegend=True)
        pie_placeholder.plotly_chart(fig_pie, use_container_width=True)
        
        threat_df = anom_df[['timestamp', 'user', 'threat_type']].tail(5)
        threats_placeholder.dataframe(threat_df, use_container_width=True, hide_index=True)
        
st.subheader("📄 Results & Feed")
table_placeholder = st.empty()


def generate_log(is_anomaly=False):
    USERS = ["alice", "bob", "charlie", "dave", "eve", "frank", "root"]
    IPS = ["10.0.0.1", "10.0.1.5", "10.0.2.10", "192.168.1.100", "172.16.0.50"]
    EVENTS_NORMAL = ["login", "logout", "access_resource"]
    EVENTS_ANOMALOUS = ["failed_login", "access_denied", "delete_policy", "modify_config", "disable_mfa"]
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = random.choice(USERS)
    if is_anomaly:
        event = random.choice(EVENTS_ANOMALOUS)
        ip = f"198.51.100.{random.randint(1, 255)}" # Strange unknown IP
        if random.random() > 0.5:
            user = "root"
    else:
        event = random.choice(EVENTS_NORMAL)
        ip = random.choice(IPS)
    
    return {"timestamp": now, "user": user, "event": event, "source_ip": ip}


if mode == "Live Simulator" and st.session_state.is_running:
    is_anom = random.random() < 0.3
    payload = generate_log(is_anom)
    
    try:
        res = requests.post(API_URL, json=payload, timeout=2)
        if res.status_code == 200:
            data = res.json()
            log_entry = {**payload, "is_anomaly": data['is_anomaly'], "anomaly_score": data['anomaly_score'], "threat_type": data['threat_type']}
            st.session_state.logs_processed.append(log_entry)
            if data['is_anomaly']:
                st.session_state.anomalies.append(log_entry)
    except Exception as e:
        st.sidebar.error(f"API Error: {e}")
        
    update_ui()
    if st.session_state.logs_processed:
        tail_logs = pd.DataFrame(st.session_state.logs_processed)[['timestamp', 'user', 'event', 'source_ip', 'is_anomaly', 'threat_type']].tail(15)
        table_placeholder.dataframe(tail_logs.style.apply(lambda x: ['background: #ffcccc' if x['is_anomaly'] else '' for i in x], axis=1), use_container_width=True)
    
    time.sleep(2)
    st.rerun()

elif mode == "Batch Upload":
    if uploaded_file is not None:
        st.info("Processing Batch Upload...")
        df = pd.read_csv(uploaded_file)
        
        batch_results = []
        for idx, row in df.iterrows():
            payload = {
                "timestamp": str(row.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))),
                "user": str(row.get('user', 'unknown')),
                "event": str(row.get('event', 'unknown')),
                "source_ip": str(row.get('source_ip', '0.0.0.0'))
            }
            try:
                res = requests.post(API_URL, json=payload, timeout=2)
                if res.status_code == 200:
                    data = res.json()
                    log_entry = {**payload, "is_anomaly": data['is_anomaly'], "anomaly_score": data['anomaly_score'], "threat_type": data['threat_type']}
                    batch_results.append(log_entry)
            except Exception as e:
                st.error(f"API Error processing row {idx}: {e}")
                
        if batch_results:
            st.session_state.logs_processed = batch_results
            st.session_state.anomalies = [r for r in batch_results if r['is_anomaly']]
            update_ui()
            res_df = pd.DataFrame(batch_results)
            table_placeholder.dataframe(res_df.style.apply(lambda x: ['background: #ffcccc' if x['is_anomaly'] else '' for i in x], axis=1), use_container_width=True)

    if st.session_state.logs_processed:
        tail_logs = pd.DataFrame(st.session_state.logs_processed)[['timestamp', 'user', 'event', 'source_ip', 'is_anomaly', 'threat_type']].tail(15)
        table_placeholder.dataframe(tail_logs.style.apply(lambda x: ['background: #ffcccc' if x['is_anomaly'] else '' for i in x], axis=1), use_container_width=True)

# HISTORICAL ANALYSIS VIEW
st.divider()
st.header("🔍 Historical Anomaly Analysis")
if st.button("Refresh Historical Data"):
    anomalies = db.get_recent_anomalies(limit=50)
    if anomalies:
        df_anom = pd.DataFrame(anomalies)
        st.dataframe(df_anom, use_container_width=True)
    else:
        st.write("No anomalies found in database.")
else:
    st.info("Click 'Refresh' to load historical data from SQLite.")
