require('dotenv').config();
const express = require('express');
const path = require('path');
const { analyzeURL } = require('./scanner');
const { saveScan, getHistory, getStats } = require('./database');
const { lookupWhois } = require('./whois');
const { lookupDns } = require('./dns');
const { generateReport } = require('./reports');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));

app.post('/api/scan', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    try {
        const scanResults = analyzeURL(url);
        const domain = new URL(url).hostname;
        
        // Respond with basic results immediately
        const initialResponse = { 
            url, 
            ...scanResults, 
            status: scanResults.riskScore > 70 ? 'Danger' : (scanResults.riskScore > 30 ? 'Warning' : 'Safe'),
            whois: { status: 'loading' },
            dns: { status: 'loading' }
        };
        
        res.json(initialResponse);

        // Background: Heavy lookups and DB save
        setImmediate(async () => {
            try {
                const [whoisData, dnsData] = await Promise.all([
                    lookupWhois(domain).catch(() => ({ registrar: 'Error' })),
                    lookupDns(domain).catch(() => ({ A: [] }))
                ]);
                
                const finalResults = { ...scanResults, whois: whoisData, dns: dnsData };
                await saveScan({
                    url,
                    risk_score: scanResults.riskScore,
                    status: initialResponse.status,
                    details: finalResults
                });
            } catch (err) {
                console.error('Background task failed:', err);
            }
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/history', async (req, res) => {
    try {
        const history = await getHistory();
        res.json(history);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        const stats = await getStats();
        res.json(stats || { total_scans: 0, avg_risk: 0, high_risk_count: 0 });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/export/csv', async (req, res) => {
    try {
        const history = await getHistory();
        const csvPath = await generateReport(history, 'csv');
        res.download(csvPath);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/export/json', async (req, res) => {
    try {
        const history = await getHistory();
        res.json(history);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
