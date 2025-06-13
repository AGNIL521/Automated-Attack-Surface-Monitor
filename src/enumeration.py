# Handles port scanning, banner grabbing, tech detection
import socket
import ssl
import requests

COMMON_PORTS = [80, 443, 21, 22, 25, 53, 110, 143, 3306, 8080, 8443]


def scan_ports(host, ports=COMMON_PORTS, timeout=2):
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append(port)
        except Exception:
            continue
    return open_ports

def get_http_banner(host, port):
    url = f"http://{host}:{port}" if port != 443 else f"https://{host}"
    try:
        if port == 443:
            resp = requests.get(url, timeout=4, verify=False)
        else:
            resp = requests.get(url, timeout=4)
        server = resp.headers.get('Server', '')
        powered_by = resp.headers.get('X-Powered-By', '')
        return {
            'status_code': resp.status_code,
            'server': server,
            'powered_by': powered_by,
            'headers': dict(resp.headers)
        }
    except Exception as e:
        return {'error': str(e)}

def enumerate_services(targets: dict) -> dict:
    """
    Enumerate services for the given targets (basic TCP connect scan and banner grab).
    Args:
        targets (dict): Dictionary containing discovered targets (subdomains, ips)
    Returns:
        dict: Dictionary with hosts, ports, and banners
    """
    common_ports = [22, 80, 443, 8080]
    hosts = []
    for host in set(targets.get('subdomains', []) + targets.get('ips', [])):
        open_ports = []
        banners = {}
        for port in common_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                    try:
                        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        data = s.recv(128)
                        banners[port] = data.decode(errors='ignore')
                    except Exception:
                        banners[port] = ''
                s.close()
            except Exception:
                continue
        if open_ports:
            hosts.append({'host': host, 'ports': open_ports, 'banners': banners})
    return {'hosts': hosts}
