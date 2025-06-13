import requests
import smtplib
from email.mime.text import MIMEText
from config import SLACK_WEBHOOK_URL, EMAIL_SETTINGS

def notify_critical_findings(scan):
    criticals = []
    for vuln in scan.get('vulnerabilities', []):
        for cve in vuln.get('cves', []):
            if 'critical' in cve.get('summary', '').lower() or 'high' in cve.get('summary', '').lower():
                criticals.append((vuln, cve))
    if not criticals:
        return
    msg = f"[ASM] Critical findings in scan: {len(criticals)} high/critical vulnerabilities detected.\n"
    for vuln, cve in criticals[:5]:
        msg += f"Host: {vuln['host']} Port: {vuln['port']} CVE: {cve['id']} {cve['summary']}\n"
    if SLACK_WEBHOOK_URL:
        requests.post(SLACK_WEBHOOK_URL, json={"text": msg})
    if EMAIL_SETTINGS['to_email']:
        send_email(EMAIL_SETTINGS['to_email'], 'ASM Alert: Critical Vulnerabilities', msg)

def send_email(to, subject, body):
    if not EMAIL_SETTINGS['smtp_server']:
        return
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SETTINGS['smtp_user']
    msg['To'] = to
    with smtplib.SMTP(EMAIL_SETTINGS['smtp_server'], EMAIL_SETTINGS['smtp_port']) as server:
        server.starttls()
        server.login(EMAIL_SETTINGS['smtp_user'], EMAIL_SETTINGS['smtp_pass'])
        server.sendmail(EMAIL_SETTINGS['smtp_user'], [to], msg.as_string())
