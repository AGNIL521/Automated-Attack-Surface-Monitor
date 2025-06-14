# Attack Surface Monitor Dashboard (Web UI)

A modern, accessible dashboard for visualizing attack surface scans. The dashboard now loads scan data directly from the backend API—no need for static `output.json` files!

---

## 🚀 Usage

1. **Start the backend API:**
   ```sh
   python ../backend/app.py
   ```
   The API docs will be at [http://localhost:5000/docs](http://localhost:5000/docs)

2. **Open the dashboard:**
   - Open `index.html` directly in your browser, or
   - Serve the `web/` directory with a simple HTTP server:
     ```sh
     python -m http.server 8080
     ```
     Then visit [http://localhost:8080](http://localhost:8080)

---

## 🧭 Features
- List, trigger, and view scan results from the backend API
- Search hosts and CVEs
- Accessible: ARIA labels, keyboard navigation, high-contrast styles
- User-friendly error and loading messages

---

## 🛠 Troubleshooting
- **API not reachable?** Make sure the backend is running and accessible at `localhost:5000`.
- **No scan results?** Trigger a scan from the dashboard or `/api/scan` endpoint.
- **Token/auth errors?** Check your `.env` and API token settings.

---

For more details, see the main project [README.md](../README.md).

   Then, open [http://localhost:8080/web/](http://localhost:8080/web/) in your browser.

3. Click "Reload Latest Scan" to refresh data after new scans.

## Features
- Hosts/services table
- Vulnerabilities table (with CVE links)
- Timeline of scans (current scan time)

---

**Note:** For production, you may want to use a more robust backend and authentication.
