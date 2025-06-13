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
