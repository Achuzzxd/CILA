import sqlite3
import os
import json
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_path="clia.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Logs Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    user TEXT,
                    event TEXT,
                    source_ip TEXT,
                    is_anomaly INTEGER,
                    anomaly_score REAL,
                    threat_type TEXT,
                    severity TEXT,
                    raw_features TEXT
                )
            ''')
            
            # 2. User State Table (for persistence)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_state (
                    user TEXT PRIMARY KEY,
                    state_json TEXT,
                    last_updated TEXT
                )
            ''')
            
            # 3. System Config/Status Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_status (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            
            conn.commit()

    def save_log(self, log_data):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO logs (timestamp, user, event, source_ip, is_anomaly, anomaly_score, threat_type, severity, raw_features)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_data.get('timestamp'),
                log_data.get('user'),
                log_data.get('event'),
                log_data.get('source_ip') or log_data.get('ip'),
                1 if log_data.get('is_anomaly') else 0,
                log_data.get('anomaly_score'),
                log_data.get('threat_type'),
                log_data.get('severity'),
                json.dumps(log_data.get('features', {}))
            ))
            conn.commit()

    def get_user_state(self, user):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT state_json FROM user_state WHERE user = ?", (user,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return []

    def save_user_state(self, user, state_list):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            state_json = json.dumps(state_list, default=str)
            now = datetime.now().isoformat()
            cursor.execute('''
                INSERT OR REPLACE INTO user_state (user, state_json, last_updated)
                VALUES (?, ?, ?)
            ''', (user, state_json, now))
            conn.commit()

    def get_recent_anomalies(self, limit=100):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT timestamp, user, event, source_ip, anomaly_score, threat_type, severity 
                FROM logs 
                WHERE is_anomaly = 1 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            columns = [column[0] for column in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_recent_logs(self, limit=50):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                SELECT timestamp, user, event, source_ip, is_anomaly, anomaly_score, threat_type, severity
                FROM logs
                ORDER BY id DESC
                LIMIT ?
                ''',
                (limit,)
            )
            columns = [column[0] for column in cursor.description]
            rows = [dict(zip(columns, row)) for row in cursor.fetchall()]

        for row in rows:
            row["is_anomaly"] = bool(row.get("is_anomaly"))
            score = row.get("anomaly_score")
            row["anomaly_score"] = float(score) if score is not None else 0.0
        return rows

    def get_threat_breakdown(self, limit=5):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM logs WHERE is_anomaly = 1")
            total_anomalies = cursor.fetchone()[0] or 0

            cursor.execute(
                '''
                SELECT threat_type, COUNT(*) AS count
                FROM logs
                WHERE is_anomaly = 1 AND threat_type IS NOT NULL AND threat_type != ''
                GROUP BY threat_type
                ORDER BY count DESC, threat_type ASC
                LIMIT ?
                ''',
                (limit,)
            )
            rows = cursor.fetchall()

        breakdown = []
        for threat_type, count in rows:
            percentage = (count / total_anomalies * 100) if total_anomalies else 0.0
            breakdown.append(
                {
                    "threat_type": threat_type,
                    "count": count,
                    "percentage": round(percentage, 1)
                }
            )
        return breakdown

    def get_stats(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM logs")
            total_logs = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM logs WHERE is_anomaly = 1")
            total_anomalies = cursor.fetchone()[0]
            return {
                "total_logs": total_logs,
                "total_anomalies": total_anomalies,
                "anomaly_rate": (total_anomalies / total_logs * 100) if total_logs > 0 else 0
            }

    def clear_all_data(self):
        """
        Wipes all tables to allow for a clean state reset.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM logs")
            cursor.execute("DELETE FROM user_state")
            cursor.execute("DELETE FROM system_status")
            conn.commit()
        return True

if __name__ == "__main__":
    db = DatabaseManager()
    print("Database initialized successfully.")
