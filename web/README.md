# Attack Surface Monitor Dashboard (Web UI)

## Usage

1. Run a scan to generate `output.json` in the project root.
2. Serve the `web/` directory and the scan result (`output.json`) via a simple HTTP server:

   ```bash
   # From project root
   python -m http.server 8080
   ```
   Then, open [http://localhost:8080/web/](http://localhost:8080/web/) in your browser.

3. Click "Reload Latest Scan" to refresh data after new scans.

## Features
- Hosts/services table
- Vulnerabilities table (with CVE links)
- Timeline of scans (current scan time)

---

**Note:** For production, you may want to use a more robust backend and authentication.
