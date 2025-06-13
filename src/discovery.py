# Handles subdomain, IP, and endpoint discovery
import requests
import re
import os
from urllib.parse import urlparse

def get_subdomains_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            return []
        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get('name_value','')
            for sub in name.split('\n'):
                if sub.endswith(domain):
                    subdomains.add(sub.strip())
        return list(subdomains)
    except Exception as e:
        print(f"[crt.sh] Error: {e}")
        return []

def get_subdomains_wayback(domain):
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            return []
        urls = resp.text.splitlines()
        subdomains = set()
        for u in urls:
            parsed = urlparse(u)
            hostname = parsed.hostname
            if hostname and hostname.endswith(domain):
                subdomains.add(hostname)
        return list(subdomains)
    except Exception as e:
        print(f"[Wayback] Error: {e}")
        return []

def get_subdomains_virustotal(domain, api_key=None):
    if not api_key:
        api_key = os.environ.get('VT_API_KEY')
    if not api_key:
        print("[VirusTotal] API key not set. Skipping.")
        return []
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            print(f"[VirusTotal] Error: {resp.status_code} {resp.text}")
            return []
        data = resp.json()
        subdomains = [item['id'] for item in data.get('data',[])]
        return subdomains
    except Exception as e:
        print(f"[VirusTotal] Error: {e}")
        return []

def discover_targets(domain, vt_api_key=None):
    print(f"[+] Discovering subdomains for {domain}")
    subdomains = set()
    subdomains.update(get_subdomains_crtsh(domain))
    subdomains.update(get_subdomains_wayback(domain))
    if vt_api_key or os.environ.get('VT_API_KEY'):
        subdomains.update(get_subdomains_virustotal(domain, vt_api_key))
    print(f"[+] Found {len(subdomains)} unique subdomains.")
    # Placeholder for IP ranges and endpoints
    ip_ranges = []
    endpoints = []
    return {'subdomains': list(subdomains), 'ip_ranges': ip_ranges, 'endpoints': endpoints}
