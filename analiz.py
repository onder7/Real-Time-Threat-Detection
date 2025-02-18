import re
import json
import smtplib
import requests
import joblib
import numpy as np
from email.mime.text import MIMEText
from collections import defaultdict
from sklearn.ensemble import IsolationForest

# Konfigürasyonlar
MALICIOUS_IPS = {"192.168.1.100", "203.0.113.45"}  # Bilinen kötü IP'ler örneği
FAILED_LOGIN_THRESHOLD = 5
LOG_FILES = ["/var/log/auth.log", "/var/log/nginx/access.log", "/var/log/firewall.log"]
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
FIREWALL_BLOCK_API = "https://firewall.example.com/api/block"
THREAT_FEED_API = "https://threatintel.example.com/api/latest"

EMAIL_ALERTS = {
    "enabled": True,
    "smtp_server": "smtp.example.com",
    "smtp_port": 587,
    "username": "alert@example.com",
    "password": "password",
    "recipient": "security@example.com"
}

def fetch_threat_intelligence():
    """Fetches latest threat intelligence data."""
    try:
        response = requests.get(THREAT_FEED_API)
        if response.status_code == 200:
            return set(response.json().get("malicious_ips", []))
    except Exception as e:
        print(f"Error fetching threat intelligence: {e}")
    return set()

def parse_logs():
    """Parses logs for failed logins, malicious IPs, and unusual patterns."""
    alerts = defaultdict(list)
    failed_logins = defaultdict(int)
    log_data = []

    for log_file in LOG_FILES:
        try:
            with open(log_file, "r") as f:
                for line in f:
                    if "Failed password" in line or "Invalid user" in line:
                        ip_match = re.search(r'from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
                        if ip_match:
                            ip = ip_match.group(1)
                            failed_logins[ip] += 1
                            if failed_logins[ip] >= FAILED_LOGIN_THRESHOLD:
                                alerts["Brute Force Attempt"].append(ip)

                    if any(ip in line for ip in MALICIOUS_IPS):
                        alerts["Malicious IP Detected"].append(line.strip())

                    log_data.append((len(line), sum(map(str.isdigit, line)), sum(map(str.isalpha, line))))
        except FileNotFoundError:
            print(f"Log file {log_file} not found.")

    return alerts, np.array(log_data)

def train_anomaly_model():
    """Trains an Isolation Forest model for anomaly detection."""
    data = np.random.rand(100, 3)  # Placeholder for real log data
    model = IsolationForest(contamination=0.05)
    model.fit(data)
    joblib.dump(model, "anomaly_model.pkl")

def detect_anomalies(log_data):
    """Detects anomalies using a pre-trained ML model."""
    try:
        model = joblib.load("anomaly_model.pkl")
        anomalies = model.predict(log_data)
        return np.where(anomalies == -1)[0].tolist()
    except Exception as e:
        print(f"Error loading anomaly model: {e}")
        return []

def send_email_alert(subject, message):
    """Sends an email alert."""
    if not EMAIL_ALERTS["enabled"]:
        return

    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ALERTS["username"]
    msg["To"] = EMAIL_ALERTS["recipient"]

    try:
        server = smtplib.SMTP(EMAIL_ALERTS["smtp_server"], EMAIL_ALERTS["smtp_port"])
        server.login(EMAIL_ALERTS["username"], EMAIL_ALERTS["password"])
        server.sendmail(EMAIL_ALERTS["username"], EMAIL_ALERTS["recipient"], msg.as_string())
        print("Email alert sent.")
    except Exception as e:
        print(f"Error sending email: {e}")

def send_slack_alert(message):
    """Sends an alert to Slack."""
    payload = {"text": message}
    try:
        requests.post(SLACK_WEBHOOK_URL, json=payload)
        print("Slack alert sent.")
    except Exception as e:
        print(f"Error sending Slack alert: {e}")

def block_ip(ip):
    """Blocks an IP address via a firewall API."""
    data = {"ip": ip}
    try:
        response = requests.post(FIREWALL_BLOCK_API, json=data)
        if response.status_code == 200:
            print(f"Blocked IP: {ip}")
        else:
            print(f"Failed to block IP {ip}: {response.text}")
    except Exception as e:
        print(f"Error blocking IP: {e}")

def main():
    global MALICIOUS_IPS
    MALICIOUS_IPS.update(fetch_threat_intelligence())
    alerts, log_data = parse_logs()
    anomalies = detect_anomalies(log_data)

    if anomalies:
        alerts["Anomalous Activity Detected"].append(anomalies)

    for alert_type, details in alerts.items():
        message = f"Alert: {alert_type}\nDetails: {json.dumps(details, indent=2)}"
        send_email_alert(alert_type, message)
        send_slack_alert(message)

        if alert_type == "Brute Force Attempt":
            for ip in details:
                block_ip(ip)

if __name__ == "__main__":
    train_anomaly_model()
    main()