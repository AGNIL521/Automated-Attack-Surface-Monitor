# ASM Backend API

## Features
- Serve scan data via `/api/scans`, `/api/scan/<filename>`, `/api/latest`
- Trigger new scans via `/api/scan` (POST, JSON: `{ "domain": "example.com" }`)
- Slack/email notifications for critical findings
- Simple Bearer token authentication

## Usage
1. Copy `.env.example` to `.env` and fill in secrets.
2. Install dependencies: `pip install -r requirements.txt`
3. Run: `python app.py`
4. Use the API with header: `Authorization: Bearer <your_token>`
