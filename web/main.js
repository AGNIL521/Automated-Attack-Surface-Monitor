// === Dashboard Upgrade ===
const scanDir = '../scans/'; // directory for scan files (optional, fallback to ../output.json)
let allScanFiles = [];
let currentScanData = null;

async function listScanFiles() {
    // Try to fetch a list of files from scanDir (requires backend support). Fallback to output.json.
    // For now, just use output.json and example_scan.json
    return [
        { name: 'Latest (output.json)', path: '../output.json' },
        { name: 'Sample (example_scan.json)', path: '../sample_output/example_scan.json' }
    ];
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
    services.filter(host => !search || host.host.includes(search)).forEach(host => {
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
