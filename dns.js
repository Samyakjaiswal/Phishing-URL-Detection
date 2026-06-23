const dns = require('dns').promises;

async function lookupDns(domain) {
    const results = { A: [], MX: [], TXT: [] };
    try {
        const timeout = (promise, ms) => Promise.race([
            promise,
            new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), ms))
        ]);

        results.A = await timeout(dns.resolve4(domain), 3000).catch(() => []);
        results.MX = await timeout(dns.resolveMx(domain), 3000).catch(() => []);
        results.MX = results.MX.map(r => r.exchange || r);
        results.TXT = await timeout(dns.resolveTxt(domain), 3000).catch(() => []);
        results.TXT = results.TXT.flat();
        
        return results;
    } catch (error) {
        console.error('DNS Error:', error.message);
        return results;
    }
}

module.exports = { lookupDns };
