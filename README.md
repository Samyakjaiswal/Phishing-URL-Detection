Advanced Phishing URL Detection Platform
Project Description
This project is a comprehensive cybersecurity portfolio piece designed to detect and analyze potential phishing URLs. It provides a robust set of features for scanning URLs, assessing their risk, and generating detailed reports. The platform aims to offer a practical demonstration of various cybersecurity techniques and web development skills.
Features
URL Scanning: Input any URL for a detailed security analysis.
Risk Scoring System: A calculated score indicating the likelihood of a URL being malicious.
Suspicious Keyword Detection: Identifies keywords commonly found in phishing attempts (e.g., "login", "verify", "account").
IP-based URL Detection: Flags URLs that use IP addresses instead of domain names, a common phishing tactic.
Excessive Subdomain Detection: Identifies URLs with an unusually high number of subdomains, which can indicate malicious intent.
URL Shortener Detection: Detects the use of URL shortening services, often used to obscure malicious links.
Suspicious TLD Detection: Flags top-level domains (TLDs) frequently associated with phishing activities.
HTTPS Verification: Checks if the URL uses a secure HTTPS connection.
WHOIS Lookup: Retrieves domain registration information, including registrar, creation date, and registrant details.
DNS Lookup: Performs DNS record lookups (A, MX, TXT records) to gather more information about the domain.
Redirect Chain Analysis: (Planned for future enhancement) Analyzes URL redirection paths.
Typosquatting Detection: Identifies potential typosquatting attempts by checking for common brand misspellings.
Homograph Attack Detection: Detects Punycode usage, which can indicate homograph attacks.
Blacklist Checking: (Planned for future enhancement) Checks the URL against known blacklists.
Whitelist Support: Allows users to define trusted domains.
Scan History: Keeps a record of all scanned URLs and their results.
SQLite Database: Stores scan history and other relevant data.
Dashboard with Statistics: Provides an overview of scan activities and threat statistics.
Threat Reports: Generates detailed reports of scan results.
CSV Export: Export scan history and reports in CSV format.
JSON Export: Export scan history and reports in JSON format.
REST API Endpoint: Provides an API for programmatic URL scanning.
Logging System: (Planned for future enhancement) Records application events and errors.
Error Handling: Robust error handling for a smooth user experience.
Responsive Design: User interface adapts to various screen sizes.
Dark Mode: Provides a dark theme option for improved readability.
Tech Stack
Frontend: HTML, CSS, Vanilla JavaScript
Backend: Node.js, Express.js
Database: SQLite
Libraries: dotenv, axios, whois-json, punycode, csv-writer
Installation and Setup
Clone the repository:
git clone https://github.com/your-username/advanced-phishing-url-detection-platform.git
cd advanced-phishing-url-detection-platform
Install dependencies:
npm install
Environment Variables: Create a .env file in the root directory based on .env.example:
PORT=3000
DB_PATH=./database.sqlite
LOG_FILE=./app.log
Run the application:
npm start
Access the application: Open your web browser and navigate to http://localhost:3000.
API Endpoints
POST /api/scan: Scans a URL. Request body: { "url": "<your-url>" }
GET /api/history: Retrieves scan history.
GET /api/stats: Retrieves scan statistics.
GET /api/export/csv: Downloads scan history as a CSV file.
GET /api/export/json: Retrieves scan history as a JSON array.
Contributing
Contributions are welcome! Please feel free to submit pull requests or open issues to improve the project.
License
This project is licensed under the MIT License.