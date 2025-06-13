# Automated Attack Surface Monitor

## Overview

This tool automates the discovery and monitoring of an organization’s external attack surface, including subdomains, open ports, exposed services, and potential vulnerabilities. It simulates how red teams or offensive security professionals map targets and identify weaknesses using OSINT techniques.

## Features
- **Target Discovery:** Subdomains, IP ranges, endpoints
- **Service Enumeration:** Open ports, banners, tech detection
- **Vulnerability Fingerprinting:** CVE lookups, outdated software
- **Reporting & Logging:** JSON/CSV output, SQLite DB
- **Containerized Deployment:** Docker & docker-compose

## Usage

```bash
docker-compose run monitor example.com --output output.json
```

Or locally:

```bash
python src/main.py example.com --output output.json
```

## Setup
1. Clone the repo
2. Install dependencies: `pip install -r requirements.txt`
3. Run the tool with a target domain

## Sample Output
See `sample_output/example_scan.json` for example results.

## Documentation
- **src/**: Source code modules
- **requirements.txt**: Python dependencies
- **Dockerfile**: Container build
- **docker-compose.yml**: Multi-service orchestration

## Roadmap
- Add scheduled scanning
- Integrate with Slack/email
- Dashboard for visualization
- Trend analysis and AI/ML prioritization
