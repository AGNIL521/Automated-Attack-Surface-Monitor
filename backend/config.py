import os
from dotenv import load_dotenv
load_dotenv()

API_TOKEN = os.getenv('API_TOKEN', 'testtoken')
SCANS_DIR = os.environ.get('ASM_SCANS_DIR', '../scans')
SLACK_WEBHOOK_URL = os.environ.get('ASM_SLACK_WEBHOOK', '')
EMAIL_SETTINGS = {
    'smtp_server': os.environ.get('ASM_SMTP_SERVER', ''),
    'smtp_port': int(os.environ.get('ASM_SMTP_PORT', '587')),
    'smtp_user': os.environ.get('ASM_SMTP_USER', ''),
    'smtp_pass': os.environ.get('ASM_SMTP_PASS', ''),
    'to_email': os.environ.get('ASM_ALERT_EMAIL', '')
}
