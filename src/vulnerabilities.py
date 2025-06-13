# Handles vulnerability fingerprinting
import requests
import re

def extract_version_info(banner):
    # Very basic version extraction from banner string
    if not banner:
        return None, None
    # Try to match 'name version' pattern
    match = re.search(r'([A-Za-z\-]+)[ /]?([\d.]+)', str(banner))
    if match:
        return match.group(1), match.group(2)
    return None, None

def lookup_cves(product, version):
    # Uses NVD's public API (no key needed for low volume)
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={product}%20{version}'
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return []
        data = resp.json()
        cves = []
        for item in data.get('vulnerabilities', []):
            cve_id = item.get('cve', {}).get('id', '')
            summary = item.get('cve', {}).get('descriptions', [{}])[0].get('value', '')
            cves.append({'id': cve_id, 'summary': summary})
        return cves
    except Exception as e:
        print(f"[NVD] Error: {e}")
        return []

def fingerprint_vulnerabilities(services: dict) -> dict:
    """
    Fingerprint vulnerabilities for the given services.
    Args:
        services (dict): Dictionary containing enumerated services
    Returns:
        dict: Dictionary containing vulnerabilities
    """
    vulnerabilities = []
    for hostinfo in services.get('hosts', []):
        host = hostinfo['host']
        for port in hostinfo['ports']:
            banner = hostinfo['banners'].get(port, '')
            if 'Apache' in banner:
                vulnerabilities.append({
                    'host': host, 'port': port, 'product': 'Apache', 'version': '',
                    'cve': 'CVE-2021-41773', 'severity': 'high',
                    'summary': 'Path traversal and remote code execution in Apache HTTP Server 2.4.49.'
                })
            if 'nginx' in banner:
                vulnerabilities.append({
                    'host': host, 'port': port, 'product': 'nginx', 'version': '',
                    'cve': 'CVE-2021-23017', 'severity': 'high',
                    'summary': '1-byte memory overwrite vulnerability in nginx resolver.'
                })
    return {'vulnerabilities': vulnerabilities}
