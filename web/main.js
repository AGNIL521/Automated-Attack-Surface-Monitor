// === Dashboard Upgrade ===
const scanDir = '../scans/'; // directory for scan files (optional, fallback to ../output.json)
let allScanFiles = [];
let currentScanData = null;

// === Accessibility & UX: Keyboard Shortcuts & Help Modal ===
function openHelpModal() {
    const modal = document.getElementById('help-modal');
    if (modal) {
        modal.style.display = 'flex';
        modal.focus();
    }
}
function closeHelpModal() {
    const modal = document.getElementById('help-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}
document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key.toLowerCase() === 'n') {
        e.preventDefault();
        document.getElementById('trigger-scan-btn').focus();
        document.getElementById('trigger-scan-btn').click();
    }
    if (e.ctrlKey && e.key.toLowerCase() === 'r') {
        e.preventDefault();
        document.getElementById('reload-btn').focus();
        document.getElementById('reload-btn').click();
    }
    if (e.key === '/') {
        e.preventDefault();
        document.getElementById('search-input').focus();
    }
    if (e.ctrlKey && e.key.toLowerCase() === 'h') {
        e.preventDefault();
        openHelpModal();
    }
    if (e.key === 'Escape') {
        closeHelpModal();
    }
});
document.addEventListener('DOMContentLoaded', () => {
    // Sidebar navigation logic
    const sections = ['overview', 'tests', 'scans', 'settings'];
    sections.forEach(sec => {
        const btn = document.getElementById('nav-' + sec);
        if (btn) {
            btn.addEventListener('click', () => {
                sections.forEach(hide => {
                    document.getElementById(hide + '-section').style.display = (hide === sec) ? 'block' : 'none';
                    document.getElementById('nav-' + hide).classList.toggle('active', hide === sec);
                });
            });
        }
    });
    // Help modal open/close
    const helpBtn = document.getElementById('help-btn');
    const closeBtn = document.getElementById('close-help-btn');
    if (helpBtn) helpBtn.addEventListener('click', openHelpModal);
    if (closeBtn) closeBtn.addEventListener('click', closeHelpModal);
    // Trap focus in modal
    const modal = document.getElementById('help-modal');
    if (modal) {
        modal.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                e.preventDefault();
                closeBtn.focus();
            }
        });
    }
    // New Scan
    const triggerBtn = document.getElementById('trigger-scan-btn');
    if (triggerBtn) {
        triggerBtn.addEventListener('click', async () => {
            const domain = prompt('Enter domain to scan:');
            if (domain) {
                await triggerScan(domain);
            }
        });
    }
    // Download JSON
    const downloadBtn = document.getElementById('download-btn');
    if (downloadBtn) {
        downloadBtn.addEventListener('click', async () => {
            const scanSelect = document.getElementById('scan-select');
            if (!scanSelect.value) return;
            const resp = await fetch('/api/scan/' + scanSelect.value, { headers: { 'Authorization': 'Bearer ' + (window.API_TOKEN || 'testtoken') }});
            if (!resp.ok) return alert('Could not fetch scan results.');
            const data = await resp.json();
            const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = scanSelect.value || 'scan.json';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
        });
    }
    // Download CSV
    const downloadCsvBtn = document.getElementById('download-csv-btn');
    if (downloadCsvBtn) {
        downloadCsvBtn.addEventListener('click', async () => {
            const scanSelect = document.getElementById('scan-select');
            if (!scanSelect.value) return;
            const resp = await fetch('/api/scan/' + scanSelect.value, { headers: { 'Authorization': 'Bearer ' + (window.API_TOKEN || 'testtoken') }});
            if (!resp.ok) return alert('Could not fetch scan results.');
            const data = await resp.json();
            // Convert scan result to CSV (hosts/services/vulns)
            let csv = 'Host,Port,Service,Product,Version,CVE,Severity,Summary\n';
            if (data.vulnerabilities) {
                for (const host in data.vulnerabilities) {
                    for (const vuln of data.vulnerabilities[host]) {
                        csv += [
                            host,
                            vuln.port || '',
                            vuln.service || '',
                            vuln.product || '',
                            vuln.version || '',
                            vuln.cve || '',
                            vuln.severity || '',
                            '"' + (vuln.summary || '').replace(/"/g, '""') + '"'
                        ].join(',') + '\n';
                    }
                }
            }
            const blob = new Blob([csv], {type: 'text/csv'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = scanSelect.value.replace(/\.json$/, '.csv') || 'scan.csv';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
        });
    }
});

// Fetch available scan files from backend
async function listScanFiles() {
    const scanSelect = document.getElementById('scan-select');
    const statusMsg = document.getElementById('scan-status-msg');
    if (statusMsg) statusMsg.textContent = 'Loading scan list...';
    if (scanSelect) scanSelect.setAttribute('aria-busy', 'true');
    try {
        const resp = await fetch('/api/scans', { headers: { 'Authorization': 'Bearer ' + (window.API_TOKEN || 'testtoken') }});
        if (!resp.ok) throw new Error('Failed to fetch scan list');
        const files = await resp.json();
        if (statusMsg) statusMsg.textContent = files.length === 0 ? 'No scans found.' : '';
        if (scanSelect) scanSelect.setAttribute('aria-busy', 'false');
        return files.map(f => ({ name: f, path: '/api/scan/' + f }));
    } catch (e) {
        if (statusMsg) statusMsg.textContent = 'Could not load scan history.';
        if (scanSelect) scanSelect.setAttribute('aria-busy', 'false');
        return [];
    }
}


// Fetch scan data from backend by API
async function loadScanData(path) {
    try {
        const resp = await fetch(path, { headers: { 'Authorization': 'Bearer ' + (window.API_TOKEN || 'testtoken') }});
        if (!resp.ok) throw new Error('Could not load scan data!');
        return await resp.json();
    } catch (e) {
        alert('Failed to load: ' + path);
        return null;
    }
}

// Trigger a new scan from the frontend
async function triggerScan(domain) {
    const statusMsg = document.getElementById('scan-status-msg');
    if (statusMsg) statusMsg.textContent = 'Triggering scan...';
    try {
        const resp = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + (window.API_TOKEN || 'testtoken')
            },
            body: JSON.stringify({ domain })
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Scan failed');
        if (statusMsg) statusMsg.textContent = 'Scan started. Waiting for results...';
        if (statusMsg) statusMsg.setAttribute('aria-live', 'polite');
        return data;
    } catch (e) {
        if (statusMsg) statusMsg.textContent = 'Scan failed: ' + e.message;
        if (statusMsg) statusMsg.setAttribute('aria-live', 'assertive');
        return null;
    }
}


// Poll scan status and show progress bar
async function pollScanStatus(onUpdate, interval = 2000) {
    let status = 'running';
    let progress = 0;
    const progressBar = document.getElementById('scan-progress-bar');
    const progressInner = document.getElementById('scan-progress-inner');
    if (progressBar && progressInner) {
        progressBar.style.display = 'block';
        progressInner.style.width = '10%';
    }
    while (status === 'running') {
        try {
            const resp = await fetch('/api/status', { headers: { 'Authorization': 'Bearer ' + (window.API_TOKEN || 'testtoken') }});
            const data = await resp.json();
            status = data.status;
            progress = Math.min(progress + 15, 95); // Fake progress
            if (progressBar && progressInner) {
                progressInner.style.width = progress + '%';
            }
            onUpdate(status);
            if (status !== 'running') break;
        } catch (e) {
            onUpdate('error');
            break;
        }
        await new Promise(res => setTimeout(res, interval));
    }
    if (progressBar && progressInner) {
        progressInner.style.width = '100%';
        setTimeout(() => { progressBar.style.display = 'none'; progressInner.style.width = '0'; }, 1200);
    }
}


async function loadScanData(path) {
    try {
        const response = await fetch(path);
        if (!response.ok) throw new Error('Could not load scan data!');
        return await response.json();
    } catch (e) {
        alert('Failed to load: ' + path);
        return null;
    }
}

function renderHosts(services, search='') {
    const tbody = document.querySelector('#hosts-table tbody');
    tbody.innerHTML = '';
    const filtered = services.filter(host => !search || host.host.includes(search));
    if (filtered.length === 0) {
        const tr = document.createElement('tr');
        tr.innerHTML = '<td colspan="3" style="text-align:center; color:#ffe066;">No hosts found for this scan.</td>';
        tbody.appendChild(tr);
        return;
    }
    filtered.forEach(host => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${host.host}</td>
            <td>${host.ports.join(', ')}</td>
            <td>${host.services.map(s => s.banner.server || '').join('<br>')}</td>
        `;
        tbody.appendChild(tr);
    });
}


function getSeverityBadge(summary) {
    // Try to extract severity from summary or CVE (placeholder logic)
    if (!summary) return '<span class="badge badge-unknown">?</span>';
    if (/critical|high/i.test(summary)) return '<span class="badge badge-high">High</span>';
    if (/medium/i.test(summary)) return '<span class="badge badge-medium">Med</span>';
    if (/low/i.test(summary)) return '<span class="badge badge-low">Low</span>';
    return '<span class="badge badge-unknown">?</span>';
}

function renderVulnerabilities(vulns, search='') {
    const tbody = document.querySelector('#vuln-table tbody');
    tbody.innerHTML = '';
    vulns.filter(vuln => {
        if (!search) return true;
        return vuln.host.includes(search) || vuln.product.includes(search) ||
            vuln.cves.some(cve => cve.id.includes(search) || cve.summary.includes(search));
    }).forEach(vuln => {
        vuln.cves.forEach(cve => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${vuln.host}</td>
                <td>${vuln.port}</td>
                <td>${vuln.product}</td>
                <td>${vuln.version}</td>
                <td><a href="https://nvd.nist.gov/vuln/detail/${cve.id}" target="_blank">${cve.id}</a></td>
                <td>${getSeverityBadge(cve.summary)}</td>
                <td><span title="${cve.summary}">${cve.summary.slice(0, 64)}${cve.summary.length > 64 ? '…' : ''}</span></td>
            `;
            tbody.appendChild(tr);
        });
    });
}

function renderTimeline(report) {
    const ul = document.getElementById('timeline');
    ul.innerHTML = '';
    const li = document.createElement('li');
    li.textContent = 'Scan loaded at ' + new Date().toLocaleString();
    ul.appendChild(li);
}

function renderSubdomainChart(data) {
    const ctx = document.getElementById('subdomainChart').getContext('2d');
    if (window.subdomainChartObj) window.subdomainChartObj.destroy();
    window.subdomainChartObj = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Subdomains'],
            datasets: [{
                label: 'Subdomains',
                data: [data.targets.subdomains ? data.targets.subdomains.length : 0],
                backgroundColor: ['#232946']
            }]
        },
        options: { plugins: { legend: { display: false } } }
    });
}

function renderVulnChart(vulns) {
    const ctx = document.getElementById('vulnChart').getContext('2d');
    if (window.vulnChartObj) window.vulnChartObj.destroy();
    // Count severity (simple logic, real-world would use CVSS)
    let high=0, med=0, low=0, unk=0;
    vulns.forEach(vuln => vuln.cves.forEach(cve => {
        const s = cve.summary.toLowerCase();
        if (s.includes('critical') || s.includes('high')) high++;
        else if (s.includes('medium')) med++;
        else if (s.includes('low')) low++;
        else unk++;
    }));
    window.vulnChartObj = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['High', 'Medium', 'Low', 'Unknown'],
            datasets: [{
                label: 'Vulnerabilities',
                data: [high, med, low, unk],
                backgroundColor: ['#d7263d', '#fbb13c', '#3fc1c9', '#bdbdbd']
            }]
        },
        options: { plugins: { legend: { display: false } } }
    });
}

async function renderDashboard() {
    const scanSelect = document.getElementById('scan-select');
    const searchInput = document.getElementById('search-input');
    if (!allScanFiles.length) allScanFiles = await listScanFiles();
    scanSelect.innerHTML = '';
    allScanFiles.forEach((file, idx) => {
        const opt = document.createElement('option');
        opt.value = file.path;
        opt.textContent = file.name;
        scanSelect.appendChild(opt);
    });
    const selectedPath = scanSelect.value;
    const data = await loadScanData(selectedPath);
    if (!data) return;
    currentScanData = data;
    let search = searchInput.value.trim();
    renderHosts(data.services, search);
    renderVulnerabilities(data.vulnerabilities, search);
    renderTimeline(data);
    renderSubdomainChart(data);
    renderVulnChart(data.vulnerabilities);
}

// --- Sidebar Navigation for Cyber Dashboard ---
const sectionIds = ['overview', 'hosts-services', 'vulnerabilities', 'timeline'];
document.querySelectorAll('.nav-btn').forEach((btn, idx) => {
    btn.addEventListener('click', function() {
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        // Animate scroll to dashboard section
        if (sectionIds[idx]) {
            const section = document.getElementById(sectionIds[idx]);
            if (section) {
                section.classList.add('section-animate');
                section.scrollIntoView({ behavior: 'smooth', block: 'start' });
                setTimeout(() => section.classList.remove('section-animate'), 400);
            }
        }
    });
    btn.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' || e.key === ' ') btn.click();
    });
});

// --- Section Fade-In Animation (Professional) ---
document.querySelectorAll('section').forEach(section => {
    section.style.opacity = 0;
    section.style.transform = 'translateY(16px)';
    setTimeout(() => {
        section.style.transition = 'opacity 0.5s, transform 0.5s';
        section.style.opacity = 1;
        section.style.transform = 'none';
    }, 100);
});

// --- Advanced Filtering for Hosts & Vulnerabilities ---
function parseQuery(query) {
    // host:xxx, cve:xxx, product:xxx, port:xxx, severity:xxx
    const parts = query.split(/\s+/);
    const filters = {};
    parts.forEach(part => {
        let [k, ...v] = part.split(':');
        if (v.length) filters[k] = v.join(':');
    });
    return filters;
}
function matchesCyber(row, filters) {
    const text = row.innerText.toLowerCase();
    if (Object.keys(filters).length === 0) return true;
    let match = true;
    if (filters.host) match = match && text.includes(filters.host);
    if (filters.cve) match = match && text.includes(filters.cve);
    if (filters.product) match = match && text.includes(filters.product);
    if (filters.port) match = match && text.includes(filters.port);
    if (filters.severity) match = match && text.includes(filters.severity);
    return match;
}
function filterTables(query) {
    const filters = parseQuery(query.trim().toLowerCase());
    // Hosts Table
    document.querySelectorAll('#hosts-table tbody tr').forEach(row => {
        row.style.display = matchesCyber(row, filters) ? '' : 'none';
    });
    // Vulnerabilities Table
    document.querySelectorAll('#vuln-table tbody tr').forEach(row => {
        row.style.display = matchesCyber(row, filters) ? '' : 'none';
    });
}

// --- Mirror Search Bars (No Infinite Loop) ---
const searchInputs = [
    document.getElementById('search-input'),
    document.querySelector('.search-bar')
].filter(Boolean);
let searchSyncing = false;
searchInputs.forEach(input => {
    input.addEventListener('input', e => {
        if (searchSyncing) return;
        searchSyncing = true;
        searchInputs.forEach(other => { if (other !== input) other.value = e.target.value; });
        filterTables(e.target.value);
        setTimeout(() => { searchSyncing = false; }, 0);
    });
});

document.getElementById('reload-btn').addEventListener('click', renderDashboard);
document.getElementById('scan-select').addEventListener('change', renderDashboard);
// Remove old search-input event, handled above
// document.getElementById('search-input').addEventListener('input', renderDashboard);

window.onload = renderDashboard;
