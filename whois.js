const whois = require('whois-json');

async function lookupWhois(domain) {
    try {
        // Simple timeout wrapper
        const timeout = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('WHOIS timeout')), 5000)
        );
        
        const results = await Promise.race([whois(domain), timeout]);
        
        return {
            registrar: results.registrar || 'Unknown',
            creationDate: results.creationDate || results.createdDate || 'Unknown',
            expiryDate: results.expiryDate || results.expirationDate || 'Unknown',
            registrant: results.registrant || 'Private'
        };
    } catch (error) {
        console.error('WHOIS Error:', error.message);
        return { 
            registrar: 'Lookup Failed',
            creationDate: 'N/A',
            expiryDate: 'N/A',
            registrant: 'N/A'
        };
    }
}

module.exports = { lookupWhois };
