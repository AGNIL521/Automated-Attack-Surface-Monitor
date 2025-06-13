# Handles reporting and database logging
import json
import csv
import sqlite3
import os

def generate_report(targets, services, vulns, json_path='output.json', csv_path='output.csv'):
    report = {
        'targets': targets,
        'services': services,
        'vulnerabilities': vulns
    }
    # Write JSON
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)
    # Write CSV (flat vulnerabilities)
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['host', 'port', 'product', 'version', 'cve_id', 'summary'])
        for vuln in vulns:
            for cve in vuln.get('cves', []):
                writer.writerow([
                    vuln['host'], vuln['port'], vuln['product'], vuln['version'], cve['id'], cve['summary']
                ])
    return json.dumps(report, indent=2)

def save_to_db(targets, services, vulns, db_path='findings.db'):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT, port INTEGER, product TEXT, version TEXT, cve_id TEXT, summary TEXT
    )''')
    for vuln in vulns:
        for cve in vuln.get('cves', []):
            c.execute('''INSERT INTO findings (host, port, product, version, cve_id, summary) VALUES (?, ?, ?, ?, ?, ?)''',
                (vuln['host'], vuln['port'], vuln['product'], vuln['version'], cve['id'], cve['summary']))
    conn.commit()
    conn.close()
