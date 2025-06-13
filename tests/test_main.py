import pytest
from src.main import discover_targets, enumerate_services, fingerprint_vulnerabilities

def test_discover_targets_valid():
    result = discover_targets('example.com')
    assert isinstance(result, dict)
    assert 'subdomains' in result
    assert 'ips' in result

def test_enumerate_services_valid():
    dummy_targets = {'subdomains': ['example.com'], 'ips': ['93.184.216.34']}
    result = enumerate_services(dummy_targets)
    assert isinstance(result, dict)
    assert 'hosts' in result

def test_fingerprint_vulnerabilities_valid():
    dummy_services = {'hosts': [{'host': 'example.com', 'ports': [80]}]}
    result = fingerprint_vulnerabilities(dummy_services)
    assert isinstance(result, dict)
    assert 'vulnerabilities' in result

def test_pipeline():
    targets = discover_targets('example.com')
    services = enumerate_services(targets)
    vulns = fingerprint_vulnerabilities(services)
    assert isinstance(targets, dict)
    assert isinstance(services, dict)
    assert isinstance(vulns, dict)
