import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import glob
import json
import subprocess
import logging
from flask import Flask, request, jsonify, send_from_directory, abort
from flask_cors import CORS
from flask_restx import Api, Resource, fields
from config import API_TOKEN, SCANS_DIR, SLACK_WEBHOOK_URL, EMAIL_SETTINGS
from notifications import notify_critical_findings
import threading
from src.main import discover_targets, enumerate_services, fingerprint_vulnerabilities

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')

# Flask app and API
import os
import threading
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_restx import Api, Resource, fields
import json

app = Flask(__name__)

# --- Error Handlers ---
@app.errorhandler(400)
def bad_request(e):
    return jsonify(error=str(e.description if hasattr(e, 'description') else e)), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify(error="Not found"), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify(error="Internal server error"), 500
CORS(app)
api = Api(
    app,
    version='1.0',
    title='Attack Surface Monitor API',
    description='''<b>Automated Attack Surface Monitor</b>\n\nA modern API for launching, managing, and retrieving attack surface scans.\n\n<b>Features:</b>\n- Launch new scans\n- View scan history\n- Fetch detailed results\n- Real-time status\n\n<b>Tip:</b> Authorize with your Bearer token for all endpoints.''',
    doc='/docs',
)

ns = api.namespace('api', description='Attack Surface Scan Operations', path='/api')


scan_result_model = api.model('ScanResult', {
    'targets': fields.Raw(
        title='Targets',
        description='Discovered targets (subdomains, IPs, etc.)',
        example={'subdomains': ['a.example.com', 'b.example.com'], 'ips': ['1.2.3.4']}
    ),
    'services': fields.Raw(
        title='Services',
        description='Enumerated services per target',
        example={'a.example.com': ['http', 'ssh']}
    ),
    'vulnerabilities': fields.Raw(
        title='Vulnerabilities',
        description='Fingerprint vulnerabilities for each service',
        example={'a.example.com': [{'cve': 'CVE-2023-0001', 'severity': 'high', 'summary': 'Example vuln'}]}
    ),
})

error_model = api.model('Error', {
    'error': fields.String(
        title='Error Message',
        description='Description of the error',
        example='Unauthorized'
    )
})


SCAN_STATUS = {'status': 'idle'}

def require_api_token():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer ') or auth.split(' ', 1)[1] != API_TOKEN:
        return False
    return True

@ns.route('/health')
class Health(Resource):
    @api.doc(summary="Health Check", description="Returns API status and a welcome message.")
    @api.response(200, 'API is running', model=api.model('HealthResponse', {
        'status': fields.String(example='ok'),
        'message': fields.String(example='API is running')
    }))
    def get(self):
        """Health check endpoint to verify API is up."""
        return {'status': 'ok', 'message': 'API is running'}

@ns.route('/scan')
class LaunchScan(Resource):
    @api.doc(summary="Trigger a new scan", description="Launch a new attack surface scan for a given domain.")
    @api.expect(api.model('ScanRequest', {
        'domain': fields.String(required=True, description='Domain to scan', example='example.com')
    }))
    @api.response(200, 'Scan started', model=api.model('ScanStarted', {
        'status': fields.String(example='started')
    }))
    @api.response(400, 'Missing domain', error_model)
    @api.response(401, 'Unauthorized', error_model)
    def post(self):
        """Start a new scan for the provided domain."""
        if not require_api_token():
            return {'error': 'Unauthorized'}, 401
        data = request.get_json() or {}
        domain = data.get('domain')
        if not domain:
            return {'error': 'Missing domain'}, 400
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
                import time, os
                filename = f"{domain}_{int(time.time())}.json"
                filepath = os.path.join(SCANS_DIR, filename)
                with open(filepath, 'w') as f:
                    json.dump(results, f, indent=2)
                SCAN_STATUS['status'] = 'complete'
            except Exception as e:
                SCAN_STATUS['status'] = 'error'
                import time, os
                filename = f"{domain}_error_{int(time.time())}.json"
                filepath = os.path.join(SCANS_DIR, filename)
                with open(filepath, 'w') as f:
                    json.dump({'error': str(e)}, f, indent=2)
        threading.Thread(target=scan_task, daemon=True).start()
        return {'status': 'started'}

@ns.route('/status')
class ScanStatus(Resource):
    @api.doc(summary="Get scan status", description="Get the current status of the latest scan (idle, running, complete, error).")
    @api.response(200, 'Current scan status', model=api.model('ScanStatus', {
        'status': fields.String(example='idle')
    }))
    @api.response(401, 'Unauthorized', error_model)
    def get(self):
        """Retrieve the current scan status."""
        if not require_api_token():
            return {'error': 'Unauthorized'}, 401
        return {'status': SCAN_STATUS['status']}

@ns.route('/results')
class GetResults(Resource):
    @api.doc(summary="Get latest scan result", description="Fetch the results of the latest finished scan.")
    @api.response(200, 'Latest scan result', scan_result_model)
    @api.response(401, 'Unauthorized', error_model)
    @api.response(404, 'No results yet', error_model)
    def get(self):
        """Get the most recent scan results as a JSON object."""
        if not require_api_token():
            return {'error': 'Unauthorized'}, 401
        import glob, os
        files = sorted(glob.glob(os.path.join(SCANS_DIR, '*.json')))
        if not files:
            return {'error': 'No results yet'}, 404
        with open(files[-1]) as f:
            data = json.load(f)
        return data

@ns.route('/scans')
class ListScans(Resource):
    @api.doc(summary="List scan history", description="Get a list of all previous scan files.")
    @api.response(200, 'List of scan files', model=api.model('ScanFiles', {
        'files': fields.List(fields.String(example='example_1718390000.json'))
    }))
    @api.response(401, 'Unauthorized', error_model)
    def get(self):
        """List all scan result files available on the server."""
        if not require_api_token():
            return {'error': 'Unauthorized'}, 401
        import glob, os
        files = sorted(glob.glob(os.path.join(SCANS_DIR, '*.json')))
        return {'files': [os.path.basename(f) for f in files]}

@ns.route('/scan/<string:filename>')
@api.doc(params={"filename": "The scan result filename (e.g. example_1718390000.json)"})
class GetScan(Resource):
    @api.doc(summary="Get scan by filename", description="Fetch a specific scan result file by its filename.")
    @api.response(200, 'Scan file content', scan_result_model)
    @api.response(401, 'Unauthorized', error_model)
    @api.response(404, 'Scan not found', error_model)
    def get(self, filename):
        """Retrieve a specific scan result by filename."""
        if not require_api_token():
            return {'error': 'Unauthorized'}, 401
        import os
        path = os.path.join(SCANS_DIR, filename)
        if not os.path.exists(path):
            return {'error': 'Scan not found'}, 404
        with open(path) as f:
            data = json.load(f)
        return data

@ns.route('/latest')
class GetLatestScan(Resource):
    @api.doc(summary="Get latest scan file", description="Fetch the most recent scan result file.")
    @api.response(200, 'Latest scan file content', scan_result_model)
    @api.response(401, 'Unauthorized', error_model)
    @api.response(404, 'No scans found', error_model)
    def get(self):
        """Get the latest scan result file as JSON."""
        if not require_api_token():
            return {'error': 'Unauthorized'}, 401
        import glob, os
        files = sorted(glob.glob(os.path.join(SCANS_DIR, '*.json')))
        if not files:
            return {'error': 'No scans found'}, 404
        with open(files[-1]) as f:
            data = json.load(f)
        return data


@ns.route('/scan')
class LaunchScan(Resource):
    @api.expect(api.model('ScanRequest', {'domain': fields.String(required=True)}))
    @api.response(200, 'Scan started')
    @api.response(400, 'Missing domain', error_model)
    @api.response(401, 'Unauthorized', error_model)
    def post(self):
        if not require_api_token():
            return {'error': 'Unauthorized'}, 401
        data = request.get_json() or {}
        domain = data.get('domain')
        if not domain:
            return {'error': 'Missing domain'}, 400
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
                import time, os
                filename = f"{domain}_{int(time.time())}.json"
                filepath = os.path.join(SCANS_DIR, filename)
                with open(filepath, 'w') as f:
                    json.dump(results, f, indent=2)
                SCAN_STATUS['status'] = 'complete'
            except Exception as e:
                SCAN_STATUS['status'] = 'error'
                import time, os
                filename = f"{domain}_error_{int(time.time())}.json"
                filepath = os.path.join(SCANS_DIR, filename)
                with open(filepath, 'w') as f:
                    json.dump({'error': str(e)}, f, indent=2)
        threading.Thread(target=scan_task, daemon=True).start()
        return {'status': 'started'}

@ns.route('/status')
class ScanStatus(Resource):
    @api.response(200, 'Current scan status')
    @api.response(401, 'Unauthorized', error_model)
    def get(self):
        if not require_api_token():
            return {'error': 'Unauthorized'}, 401
        return {'status': SCAN_STATUS['status']}

@ns.route('/results')
class GetResults(Resource):
    @api.response(200, 'Latest scan result', scan_result_model)
    @api.response(401, 'Unauthorized', error_model)
    @api.response(404, 'No results yet', error_model)
    def get(self):
        if not require_api_token():
            return {'error': 'Unauthorized'}, 401
        import glob, os
        files = sorted(glob.glob(os.path.join(SCANS_DIR, '*.json')))
        if not files:
            return {'error': 'No results yet'}, 404
        with open(files[-1]) as f:
            data = json.load(f)
        return data

@ns.route('/scans')
class ListScans(Resource):
    @api.response(200, 'List of scan files')
    @api.response(401, 'Unauthorized', error_model)
    def get(self):
        if not require_api_token():
            return {'error': 'Unauthorized'}, 401
        import glob, os
        files = sorted(glob.glob(os.path.join(SCANS_DIR, '*.json')))
        return [os.path.basename(f) for f in files]

@ns.route('/scan/<string:filename>')
class GetScan(Resource):
    @api.response(200, 'Scan file content', scan_result_model)
    @api.response(401, 'Unauthorized', error_model)
    @api.response(404, 'Scan not found', error_model)
    def get(self, filename):
        if not require_api_token():
            return {'error': 'Unauthorized'}, 401
        import os
        path = os.path.join(SCANS_DIR, filename)
        if not os.path.exists(path):
            return {'error': 'Scan not found'}, 404
        with open(path) as f:
            data = json.load(f)
        return data

@ns.route('/latest')
class GetLatestScan(Resource):
    @api.response(200, 'Latest scan file content', scan_result_model)
    @api.response(401, 'Unauthorized', error_model)
    @api.response(404, 'No scans found', error_model)
    def get(self):
        if not require_api_token():
            return {'error': 'Unauthorized'}, 401
        import glob, os
        files = sorted(glob.glob(os.path.join(SCANS_DIR, '*.json')))
        if not files:
            return {'error': 'No scans found'}, 404
        with open(files[-1]) as f:
            data = json.load(f)
        return data


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
            # Save results to disk
            import time
            import os
            filename = f"{domain}_{int(time.time())}.json"
            filepath = os.path.join(SCANS_DIR, filename)
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2)
            SCAN_STATUS['status'] = 'complete'
        except Exception as e:
            SCAN_STATUS['status'] = 'error'
            # Save error to disk
            import time
            import os
            filename = f"{domain}_error_{int(time.time())}.json"
            filepath = os.path.join(SCANS_DIR, filename)
            with open(filepath, 'w') as f:
                json.dump({'error': str(e)}, f, indent=2)


@app.route('/api/status', methods=['GET'])
def get_status():
    if not require_api_token():
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'status': SCAN_STATUS['status']})

@app.route('/api/results', methods=['GET'])
def get_results():
    if not require_api_token():
        return jsonify({'error': 'Unauthorized'}), 401
    import glob
    import os
    files = sorted(glob.glob(os.path.join(SCANS_DIR, '*.json')))
    if not files:
        return jsonify({'error': 'No results yet'}), 404
    with open(files[-1]) as f:
        data = json.load(f)
    return jsonify(data)

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
    try:
        return send_from_directory(SCANS_DIR, filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 404

@app.route('/api/latest', methods=['GET'])
def get_latest_scan():
    require_auth()
    files = sorted(glob.glob(os.path.join(SCANS_DIR, '*.json')))
    if not files:
        return jsonify({'error': 'No scans found'}), 404
    with open(files[-1]) as f:
        data = json.load(f)
    return jsonify(data)

@app.route('/api/scan', methods=['POST'])
def launch_scan():
    require_auth()
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'Missing domain'}), 400
    domain = data['domain']
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
