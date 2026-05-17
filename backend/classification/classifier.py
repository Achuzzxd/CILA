import re

class ThreatClassifier:
    def __init__(self):
        # Define threat signatures with severity
        self.signatures = [
            {
                "id": "brute_force",
                "patterns": [r"failed", r"fail", r"deny", r"access_denied"],
                "name": "Brute Force / Access Denial",
                "severity": "High",
                "threshold_fails": 5
            },
            {
                "id": "unauthorized_policy",
                "patterns": [r"policy", r"administratoraccess", r"iam", r"delete_policy"],
                "name": "Unauthorized Policy Change",
                "severity": "Critical"
            },
            {
                "id": "privilege_escalation",
                "patterns": [r"sudo", r"root", r"modify_user", r"create_user"],
                "name": "Privilege Escalation Attempt",
                "severity": "Critical"
            },
            {
                "id": "data_exfiltration",
                "patterns": [r"export", r"download", r"copy_data"],
                "name": "Potential Data Exfiltration",
                "severity": "High"
            },
            {
                "id": "reconnaissance",
                "patterns": [r"network", r"scanning", r"describe", r"list_"],
                "name": "Reconnaissance / Enumeration",
                "severity": "Medium"
            },
            {
                "id": "resource_deletion",
                "patterns": [r"delete", r"terminate", r"disable"],
                "name": "Resource Destruction",
                "severity": "High"
            }
        ]

    def classify(self, log_entry, is_anomaly, features=None):
        """
        Classifies a log entry based on its content and AI detection status.
        """
        if not is_anomaly:
            return "Normal Activity", "Low"

        raw_content = f"{log_entry.get('event', '')} {log_entry.get('status', '')} {log_entry.get('user', '')}".lower()
        
        # Check behavioral features if provided
        if features:
            fails_1h = features.get('fails_1h', 0)
            if fails_1h >= 10:
                return "Sustained Brute Force Attack", "Critical"
            
            ip_changed = features.get('ip_changed', 0)
            if ip_changed and is_anomaly:
                return "Session Hijacking / Location Anomaly", "High"

        # Check signatures
        for sig in self.signatures:
            for pattern in sig['patterns']:
                if re.search(pattern, raw_content):
                    return sig['name'], sig['severity']

        # Fallback for generic anomalies
        if is_anomaly:
            return "General Behavioral Anomaly", "Medium"

        return "Normal", "Low"

# Singleton instance
classifier = ThreatClassifier()
