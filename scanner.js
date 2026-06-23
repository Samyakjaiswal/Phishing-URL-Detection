const punycode = require('punycode/');
const { URL } = require('url');

const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'account', 'update', 'secure', 'banking', 'wallet', 'crypto', 'support', 'billing'];
const SUSPICIOUS_TLDS = ['.xyz', '.top', '.pw', '.loan', '.win', '.bid', '.gq', '.ga', '.cf', '.ml'];
const SHORTENERS = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly'];

function analyzeURL(urlInput) {
    let url;
    try {
        // Ensure protocol exists
        let formattedUrl = urlInput;
        if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
            formattedUrl = 'http://' + formattedUrl;
        }
        url = new URL(formattedUrl);
    } catch (e) {
        throw new Error('Invalid URL format: ' + e.message);
    }

    const hostname = url.hostname;
    const results = {
        checks: [],
        riskScore: 0
    };

    // 1. HTTPS Check
    const isHttps = url.protocol === 'https:';
    results.checks.push({
        name: 'HTTPS Verification',
        status: isHttps ? 'Safe' : 'Suspicious',
        score: isHttps ? 0 : 15,
        detail: isHttps ? 'Connection is secure' : 'Insecure HTTP connection'
    });

    // 2. Suspicious Keywords
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => url.href.toLowerCase().includes(kw));
    results.checks.push({
        name: 'Keyword Detection',
        status: foundKeywords.length > 0 ? 'Suspicious' : 'Safe',
        score: foundKeywords.length * 10,
        detail: foundKeywords.length > 0 ? `Found: ${foundKeywords.join(', ')}` : 'No suspicious keywords'
    });

    // 3. IP-based URL
    const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname);
    results.checks.push({
        name: 'IP-based URL',
        status: isIp ? 'Suspicious' : 'Safe',
        score: isIp ? 25 : 0,
        detail: isIp ? 'Uses IP address instead of domain name' : 'Uses domain name'
    });

    // 4. Excessive Subdomains
    const subdomainCount = hostname.split('.').length - 2;
    results.checks.push({
        name: 'Subdomain Analysis',
        status: subdomainCount > 3 ? 'Suspicious' : 'Safe',
        score: subdomainCount > 3 ? 15 : 0,
        detail: `Subdomain count: ${subdomainCount}`
    });

    // 5. URL Shortener Detection
    const isShortened = SHORTENERS.some(s => hostname.includes(s));
    results.checks.push({
        name: 'URL Shortener',
        status: isShortened ? 'Warning' : 'Safe',
        score: isShortened ? 10 : 0,
        detail: isShortened ? 'URL uses a shortening service' : 'Not a known shortener'
    });

    // 6. Suspicious TLD
    const hasSuspiciousTld = SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));
    results.checks.push({
        name: 'TLD Analysis',
        status: hasSuspiciousTld ? 'Suspicious' : 'Safe',
        score: hasSuspiciousTld ? 20 : 0,
        detail: hasSuspiciousTld ? 'Domain uses a suspicious TLD' : 'Common TLD'
    });

    // 7. Homograph/Punycode Detection
    const isPunycode = hostname.startsWith('xn--');
    results.checks.push({
        name: 'Homograph Attack',
        status: isPunycode ? 'Danger' : 'Safe',
        score: isPunycode ? 40 : 0,
        detail: isPunycode ? 'Punycode detected (potential homograph attack)' : 'No punycode detected'
    });

    // 8. Typosquatting
    const commonBrands = ['google', 'facebook', 'microsoft', 'apple', 'amazon', 'paypal'];
    const brandMatch = commonBrands.find(brand => 
        hostname.includes(brand) && !hostname.endsWith(`${brand}.com`) && !hostname.endsWith(`${brand}.net`)
    );
    results.checks.push({
        name: 'Typosquatting',
        status: brandMatch ? 'Suspicious' : 'Safe',
        score: brandMatch ? 30 : 0,
        detail: brandMatch ? `Potential typosquatting of ${brandMatch}` : 'No common brand spoofing detected'
    });

    // Calculate total score (max 100)
    results.riskScore = Math.min(100, results.checks.reduce((acc, curr) => acc + curr.score, 0));
    
    return results;
}

module.exports = { analyzeURL };
