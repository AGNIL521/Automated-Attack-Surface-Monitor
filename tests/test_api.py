import os
import time
import requests

API_URL = "http://127.0.0.1:5000"
API_TOKEN = os.environ.get("API_TOKEN", "testtoken")
HEADERS = {"Authorization": f"Bearer {API_TOKEN}"}

def test_health_check():
    resp = requests.get(f"{API_URL}/")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

def test_scan_and_status():
    # Start a scan
    resp = requests.post(f"{API_URL}/api/scan", json={"domain": "example.com"}, headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json()["status"] == "started"
    # Poll status until complete or timeout
    for _ in range(20):
        status = requests.get(f"{API_URL}/api/status", headers=HEADERS).json()["status"]
        if status == "complete":
            break
        time.sleep(1)
    assert status == "complete"

def test_results():
    resp = requests.get(f"{API_URL}/api/results", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "targets" in data and "services" in data and "vulnerabilities" in data

def test_unauthorized_access():
    client = app.test_client()
    resp = client.get('/api/results')
    assert resp.status_code == 401
    resp = client.post('/api/scan', json={'domain': 'example.com'})
    assert resp.status_code == 401

def test_scan_trigger_and_result(tmp_path, monkeypatch):
    monkeypatch.setattr('backend.app.SCANS_DIR', str(tmp_path))
    client = app.test_client()
    # Trigger scan with no domain
    resp = client.post('/api/scan', headers=auth_header(), json={})
    assert resp.status_code == 400
    # Trigger scan with domain (simulate quick result)
    def fake_discover_targets(domain): return {'subdomains': ['a.example.com']}
    def fake_enumerate_services(targets): return {'a.example.com': ['http']}
    def fake_fingerprint_vulnerabilities(services): return {'a.example.com': []}
    monkeypatch.setattr('backend.app.discover_targets', fake_discover_targets)
    monkeypatch.setattr('backend.app.enumerate_services', fake_enumerate_services)
    monkeypatch.setattr('backend.app.fingerprint_vulnerabilities', fake_fingerprint_vulnerabilities)
    resp = client.post('/api/scan', headers=auth_header(), json={'domain': 'example.com'})
    assert resp.status_code == 200

def test_results_no_scans(tmp_path, monkeypatch):
    monkeypatch.setattr('backend.app.SCANS_DIR', str(tmp_path))
    client = app.test_client()
    resp = client.get('/api/results', headers=auth_header())
    assert resp.status_code == 404

def test_docs_endpoint():
    client = app.test_client()
    resp = client.get('/docs/')
    assert resp.status_code == 200
