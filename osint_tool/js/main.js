/**
 * Main Application Controller
 */

let osintEngine;
let reportGenerator;
let currentReportData = null;

document.addEventListener('DOMContentLoaded', () => {
    osintEngine = new OSINTEngine();
    reportGenerator = new ReportGenerator();

    const generateBtn = document.getElementById('generateReport');
    const companyInput = document.getElementById('companyName');
    const loadingIndicator = document.getElementById('loadingIndicator');
    const reportContainer = document.getElementById('reportContainer');
    const errorContainer = document.getElementById('errorContainer');

    // Enter key support
    companyInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            generateBtn.click();
        }
    });

    generateBtn.addEventListener('click', async () => {
        const companyName = companyInput.value.trim();
        
        if (!companyName) {
            showError('Please enter a company name or domain');
            return;
        }

        // Get API keys
        const apiKeys = {
            shodan: document.getElementById('shodanKey')?.value.trim() || null,
            virustotal: document.getElementById('virustotalKey')?.value.trim() || null,
            hunter: document.getElementById('hunterKey')?.value.trim() || null
        };

        // Reset UI
        hideError();
        showLoading();
        hideReport();

        // Update progress
        updateProgress('Initializing OSINT collection...');

        try {
            // Collect data with progress updates
            const progressSteps = [
                'Collecting WHOIS data...',
                'Fetching DNS records from APIs...',
                'Discovering subdomains from Certificate Transparency...',
                'Analyzing SSL certificates (fetching data)...',
                'Searching URLScan.io for domain scans...',
                'Fetching ThreatCrowd intelligence...',
                'Collecting BGP/ASN network information...',
                'Detecting technology stack...',
                'Searching social media...',
                'Checking data breaches...',
                'Scanning dark web sources...',
                'Finding code repositories...',
                'Fetching IP geolocation data...',
                'Loading SpiderFoot sources...'
            ];

            let stepIndex = 0;
            const progressInterval = setInterval(() => {
                if (stepIndex < progressSteps.length) {
                    updateProgress(progressSteps[stepIndex]);
                    stepIndex++;
                } else {
                    clearInterval(progressInterval);
                }
            }, 1000);

            // Collect all OSINT data
            const reportData = await osintEngine.collectAllData(companyName, apiKeys);
            currentReportData = reportData;

            clearInterval(progressInterval);
            updateProgress('Generating report...');

            // Generate and display report
            setTimeout(() => {
                reportGenerator.generateReport(reportData);
                hideLoading();
                showReport();
            }, 500);

        } catch (error) {
            console.error('OSINT collection error:', error);
            showError(`Error collecting OSINT data: ${error.message}`);
            hideLoading();
        }
    });

    // Export handlers
    document.getElementById('exportJSON')?.addEventListener('click', () => {
        if (currentReportData) {
            reportGenerator.exportToJSON(currentReportData);
        }
    });

    document.getElementById('exportPDF')?.addEventListener('click', () => {
        if (currentReportData) {
            reportGenerator.exportToPDF(currentReportData);
        }
    });

    document.getElementById('newReport')?.addEventListener('click', () => {
        companyInput.value = '';
        hideReport();
        hideError();
    });
});

function showLoading() {
    document.getElementById('loadingIndicator').classList.remove('hidden');
}

function hideLoading() {
    document.getElementById('loadingIndicator').classList.add('hidden');
}

function showReport() {
    document.getElementById('reportContainer').classList.remove('hidden');
    // Scroll to report
    document.getElementById('reportContainer').scrollIntoView({ behavior: 'smooth' });
}

function hideReport() {
    document.getElementById('reportContainer').classList.add('hidden');
}

function showError(message) {
    const errorContainer = document.getElementById('errorContainer');
    errorContainer.textContent = message;
    errorContainer.classList.remove('hidden');
}

function hideError() {
    document.getElementById('errorContainer').classList.add('hidden');
}

function updateProgress(message) {
    const progressSteps = document.querySelector('.progress-steps');
    if (progressSteps) {
        progressSteps.textContent = message;
    }
}

