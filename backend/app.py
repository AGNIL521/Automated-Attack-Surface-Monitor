import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import glob
import json
import subprocess
from flask import Flask, request, jsonify, send_from_directory, abort
from flask_cors import CORS
from config import API_TOKEN, SCANS_DIR, SLACK_WEBHOOK_URL, EMAIL_SETTINGS
from notifications import notify_critical_findings
import threading
from src.main import discover_targets, enumerate_services, fingerprint_vulnerabilities

app = Flask(__name__)
CORS(app)

SCAN_STATUS = {'status': 'idle', 'results': None}

@app.route('/')
def health():
    return jsonify({'status': 'ok', 'message': 'API is running'})

def require_api_token():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer ') or auth.split(' ', 1)[1] != API_TOKEN:
        return False
    return True

@app.route('/api/scan', methods=['POST'])
def launch_scan():
    if not require_api_token():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json() or {}
    domain = data.get('domain')
    if not domain:
        return jsonify({'error': 'Missing domain'}), 400
    def scan_task():
        SCAN_STATUS['status'] = 'running'
        try:
            targets = discover_targets(domain)
            services = enumerate_services(targets)
            vulns = fingerprint_vulnerabilities(services)
            results = {
                'targets': targets,
                'services': services,
                'vulnerabilities': vulns
            }
            SCAN_STATUS['results'] = results
            SCAN_STATUS['status'] = 'complete'
        except Exception as e:
            SCAN_STATUS['status'] = 'error'
            SCAN_STATUS['results'] = {'error': str(e)}
    threading.Thread(target=scan_task, daemon=True).start()
    return jsonify({'status': 'started'})

@app.route('/api/status', methods=['GET'])
def get_status():
    if not require_api_token():
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'status': SCAN_STATUS['status']})

@app.route('/api/results', methods=['GET'])
def get_results():
    if not require_api_token():
        return jsonify({'error': 'Unauthorized'}), 401
    if SCAN_STATUS['results'] is None:
        return jsonify({'error': 'No results yet'}), 404
    return jsonify(SCAN_STATUS['results'])

os.makedirs(SCANS_DIR, exist_ok=True)

def require_auth():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer ') or auth.split(' ', 1)[1] != API_TOKEN:
        abort(401)

@app.route('/api/scans', methods=['GET'])
def list_scans():
    require_auth()
    files = sorted(glob.glob(os.path.join(SCANS_DIR, '*.json')))
    return jsonify([os.path.basename(f) for f in files])

@app.route('/api/scan/<filename>', methods=['GET'])
def get_scan(filename):
    require_auth()
    path = os.path.join(SCANS_DIR, filename)
    if not os.path.exists(path):
        abort(404)
    with open(path) as f:
        data = json.load(f)
    return jsonify(data)

@app.route('/api/latest', methods=['GET'])
def get_latest_scan():
    require_auth()
    files = sorted(glob.glob(os.path.join(SCANS_DIR, '*.json')))
    if not files:
        abort(404)
    with open(files[-1]) as f:
        data = json.load(f)
    return jsonify(data)

@app.route('/api/scan', methods=['POST'])
def trigger_scan():
    require_auth()
    domain = request.json.get('domain')
    if not domain:
        return jsonify({'error': 'No domain specified'}), 400
    out_file = os.path.join(SCANS_DIR, f"{domain}_{int(__import__('time').time())}.json")
    # Run scan as subprocess
    proc = subprocess.run([
        'python', '../src/main.py', domain, '--output', out_file
    ], capture_output=True, text=True)
    if proc.returncode != 0:
        return jsonify({'error': proc.stderr}), 500
    # Notify if critical findings
    with open(out_file) as f:
        scan = json.load(f)
    notify_critical_findings(scan)
    return jsonify({'status': 'scan complete', 'output': os.path.basename(out_file)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
