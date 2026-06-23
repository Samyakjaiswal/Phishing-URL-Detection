const { createObjectCsvWriter } = require('csv-writer');
const path = require('path');
const fs = require('fs');

async function generateReport(data, format) {
    if (format === 'csv') {
        const filePath = path.join(__dirname, 'scan_report.csv');
        const csvWriter = createObjectCsvWriter({
            path: filePath,
            header: [
                { id: 'id', title: 'ID' },
                { id: 'url', title: 'URL' },
                { id: 'risk_score', title: 'Risk Score' },
                { id: 'status', title: 'Status' },
                { id: 'created_at', title: 'Date' }
            ]
        });

        await csvWriter.writeRecords(data);
        return filePath;
    }
    return null;
}

module.exports = { generateReport };
