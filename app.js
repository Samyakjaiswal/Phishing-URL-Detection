document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scan-btn');
    const urlInput = document.getElementById('url-input');
    const resultsSection = document.getElementById('results-section');
    const loader = document.getElementById('loader');
    const themeToggle = document.getElementById('theme-toggle');

    // Theme Toggle
    themeToggle.addEventListener('click', () => {
        document.body.classList.toggle('dark-mode');
        const icon = themeToggle.querySelector('i');
        icon.classList.toggle('fa-moon');
        icon.classList.toggle('fa-sun');
    });

    // Scan URL
    scanBtn.addEventListener('click', async () => {
        const url = urlInput.value.trim();
        if (!url) return alert('Please enter a URL');

        loader.classList.remove('hidden');
        resultsSection.classList.add('hidden');

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            const data = await response.json();
            if (data.error) throw new Error(data.error);

            displayResults(data);
            updateStats();
            updateHistory();
        } catch (error) {
            alert('Scan failed: ' + error.message);
        } finally {
            loader.classList.add('hidden');
        }
    });

    function displayResults(data) {
        resultsSection.classList.remove('hidden');
        document.getElementById('risk-score').textContent = data.riskScore;
        const badge = document.getElementById('risk-badge');
        badge.textContent = data.status;
        badge.className = `badge ${data.status}`;

        const checkList = document.getElementById('check-list');
        checkList.innerHTML = (data.checks || []).map(check => `
            <div class="check-item">
                <span><strong>${check.name}</strong>: ${check.detail}</span>
                <span class="badge ${check.status}">${check.status}</span>
            </div>
        `).join('');

        const whoisInfo = document.getElementById('whois-info');
        if (data.whois && data.whois.status === 'loading') {
            whoisInfo.innerHTML = '<p><em>WHOIS data is loading in background...</em></p>';
        } else if (data.whois) {
            whoisInfo.innerHTML = `
                <p><strong>Registrar:</strong> ${data.whois.registrar || 'N/A'}</p>
                <p><strong>Created:</strong> ${data.whois.creationDate || 'N/A'}</p>
                <p><strong>Expiry:</strong> ${data.whois.expiryDate || 'N/A'}</p>
            `;
        } else {
            whoisInfo.innerHTML = '<p>No WHOIS data available</p>';
        }

        const dnsInfo = document.getElementById('dns-info');
        if (data.dns && data.dns.status === 'loading') {
            dnsInfo.innerHTML = '<p><em>DNS data is loading in background...</em></p>';
        } else if (data.dns) {
            const aRecords = Array.isArray(data.dns.A) ? data.dns.A.join(', ') : 'None';
            const mxRecords = Array.isArray(data.dns.MX) ? data.dns.MX.join(', ') : 'None';
            dnsInfo.innerHTML = `
                <p><strong>A Records:</strong> ${aRecords}</p>
                <p><strong>MX Records:</strong> ${mxRecords}</p>
            `;
        } else {
            dnsInfo.innerHTML = '<p>No DNS data available</p>';
        }
    }

    async function updateStats() {
        try {
            const response = await fetch('/api/stats');
            const stats = await response.json();
            document.getElementById('stat-total').textContent = stats.total_scans || 0;
            document.getElementById('stat-high-risk').textContent = stats.high_risk_count || 0;
            document.getElementById('stat-avg').textContent = Math.round(stats.avg_risk || 0);
        } catch (e) { console.error('Stats update failed', e); }
    }

    async function updateHistory() {
        try {
            const response = await fetch('/api/history');
            const history = await response.json();
            const body = document.getElementById('history-body');
            body.innerHTML = (history || []).map(row => `
                <tr>
                    <td>${row.url}</td>
                    <td>${row.risk_score}</td>
                    <td><span class="badge ${row.status}">${row.status}</span></td>
                    <td>${new Date(row.created_at).toLocaleDateString()}</td>
                </tr>
            `).join('');
        } catch (e) { console.error('History update failed', e); }
    }

    // Export Buttons
    document.getElementById('export-csv').addEventListener('click', () => {
        window.location.href = '/api/export/csv';
    });

    document.getElementById('export-json').addEventListener('click', () => {
        window.location.href = '/api/export/json';
    });

    // Initial Load
    updateStats();
    updateHistory();
});
