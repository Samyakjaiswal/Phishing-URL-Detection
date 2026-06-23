const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const dbPath = process.env.DB_PATH || path.join(__dirname, 'database.sqlite');

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
    } else {
        console.log('Connected to SQLite database.');
        initializeDatabase();
    }
});

function initializeDatabase() {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            risk_score INTEGER,
            status TEXT,
            details TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL
        )`);

        // Seed some common domains
        const commonDomains = ['google.com', 'microsoft.com', 'apple.com', 'github.com', 'amazon.com'];
        const stmt = db.prepare("INSERT OR IGNORE INTO whitelist (domain) VALUES (?)");
        commonDomains.forEach(domain => stmt.run(domain));
        stmt.finalize();
    });
}

module.exports = {
    db,
    saveScan: (data) => {
        return new Promise((resolve, reject) => {
            const { url, risk_score, status, details } = data;
            db.run(
                `INSERT INTO scans (url, risk_score, status, details) VALUES (?, ?, ?, ?)`,
                [url, risk_score, status, JSON.stringify(details)],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });
    },
    getHistory: () => {
        return new Promise((resolve, reject) => {
            db.all(`SELECT * FROM scans ORDER BY created_at DESC LIMIT 50`, [], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    },
    getStats: () => {
        return new Promise((resolve, reject) => {
            db.get(`
                SELECT 
                    COUNT(*) as total_scans,
                    AVG(risk_score) as avg_risk,
                    SUM(CASE WHEN risk_score > 70 THEN 1 ELSE 0 END) as high_risk_count
                FROM scans
            `, [], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    }
};
