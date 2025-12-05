// Secure application logic for da signature parser
class SIEMRulesApp {
    constructor() {
        this.parser = new SIEMRuleParser();
        this.converter = new SIEMRuleConverter();
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setupEventListeners());
        } else {
            this.setupEventListeners();
        }
    }

    setupEventListeners() {
        // Auto-detect rule type as user types
        const inputTextarea = document.getElementById('inputRules');
        if (inputTextarea) {
            inputTextarea.addEventListener('input', () => {
                this.updateRuleTypeIndicator();
            });
        }
    }

    convertToSnort() {
        try {
            const input = document.getElementById('inputRules').value;
            if (!input.trim()) {
                this.showErrorMessage('Please enter some rules to convert');
                return;
            }

            // Sanitize input
            const sanitizedInput = SecurityUtils.sanitizeInput(input);
            
            if (!SecurityUtils.validateRuleContent(sanitizedInput)) {
                this.showErrorMessage('Input contains potentially dangerous content. Please check your rules.');
                return;
            }

            // Perform conversion
            const converted = this.converter.convertToSnort(sanitizedInput);
            
            // Display result
            const output = document.getElementById('outputRules');
            if (output) {
                output.value = SecurityUtils.sanitizeForDisplay(converted);
            }
            
            // Update log
            this.updateConversionLog(this.converter.getConversionLog());
            this.showSuccessMessage('Successfully converted to Snort format');
            
        } catch (error) {
            console.error('Conversion error:', error);
            this.showErrorMessage('Error during conversion: ' + error.message);
        }
    }

    convertToSuricata() {
        try {
            const input = document.getElementById('inputRules').value;
            if (!input.trim()) {
                this.showErrorMessage('Please enter some rules to convert');
                return;
            }

            // Sanitize input
            const sanitizedInput = SecurityUtils.sanitizeInput(input);
            
            if (!SecurityUtils.validateRuleContent(sanitizedInput)) {
                this.showErrorMessage('Input contains potentially dangerous content. Please check your rules.');
                return;
            }

            // Perform conversion
            const converted = this.converter.convertToSuricata(sanitizedInput);
            
            // Display result
            const output = document.getElementById('outputRules');
            if (output) {
                output.value = SecurityUtils.sanitizeForDisplay(converted);
            }
            
            // Update log
            this.updateConversionLog(this.converter.getConversionLog());
            this.showSuccessMessage('Successfully converted to Suricata format');
            
        } catch (error) {
            console.error('Conversion error:', error);
            this.showErrorMessage('Error during conversion: ' + error.message);
        }
    }

    analyzeRules() {
        try {
            const input = document.getElementById('inputRules').value;
            if (!input.trim()) {
                this.showErrorMessage('Please enter some rules to analyze');
                return;
            }

            // Sanitize input
            const sanitizedInput = SecurityUtils.sanitizeInput(input);
            
            if (!SecurityUtils.validateRuleContent(sanitizedInput)) {
                this.showErrorMessage('Input contains potentially dangerous content. Please check your rules.');
                return;
            }

            // Parse and analyze rules
            const rules = this.parser.parseRules(sanitizedInput);
            this.displayAnalysisResults(rules);
            this.showSuccessMessage('Analysis completed successfully');
            
        } catch (error) {
            console.error('Analysis error:', error);
            this.showErrorMessage('Error during analysis: ' + error.message);
        }
    }

    clearInput() {
        const input = document.getElementById('inputRules');
        if (input) {
            input.value = '';
            this.updateRuleTypeIndicator();
        }
    }

    copyOutput() {
        const output = document.getElementById('outputRules');
        if (output && output.value.trim()) {
            const sanitizedContent = SecurityUtils.sanitizeForDisplay(output.value);
            
            navigator.clipboard.writeText(sanitizedContent).then(() => {
                this.showSuccessMessage('Output copied to clipboard');
            }).catch(err => {
                console.error('Failed to copy: ', err);
                this.showErrorMessage('Failed to copy to clipboard');
            });
        } else {
            this.showErrorMessage('No output to copy');
        }
    }

    clearLog() {
        const logDiv = document.getElementById('conversionLog');
        if (logDiv) {
            logDiv.innerHTML = '<p>Conversion details will appear here</p>';
        }
    }

    updateRuleTypeIndicator() {
        const input = document.getElementById('inputRules');
        if (!input || !input.value.trim()) return;

        try {
            const detectedType = this.parser.detectRuleType(input.value);
            console.log('Detected rule type:', detectedType);
        } catch (error) {
            console.error('Error detecting rule type:', error);
        }
    }

    updateConversionLog(logEntries) {
        const logDiv = document.getElementById('conversionLog');
        if (!logDiv) return;

        let logHTML = '';
        logEntries.forEach(entry => {
            const sanitizedMessage = SecurityUtils.sanitizeOutput(entry.message);
            logHTML += `<div class="log-entry log-${entry.type}">`;
            logHTML += `<span class="log-time">${new Date().toLocaleTimeString()}</span>`;
            logHTML += `<span class="log-type">[${entry.type.toUpperCase()}]</span>`;
            logHTML += `<span class="log-message">${sanitizedMessage}</span>`;
            logHTML += '</div>';
        });
        
        logDiv.innerHTML = logHTML;
    }

    displayAnalysisResults(rules) {
        const resultsDiv = document.getElementById('analysisResults');
        if (!resultsDiv) return;

        let analysisHTML = '';
        
        analysisHTML += `<div class="analysis-summary">`;
        analysisHTML += `<h4>Analysis Summary</h4>`;
        analysisHTML += `<p>Total Rules: ${rules.length}</p>`;
        
        if (rules.length > 0) {
            const firstRule = rules[0];
            const detectedType = this.parser.detectRuleType(rules[0].raw);
            analysisHTML += `<p>Detected Format: ${SecurityUtils.sanitizeOutput(detectedType)}</p>`;
            analysisHTML += `<p>First Rule SID: ${SecurityUtils.sanitizeOutput(firstRule.sid || 'N/A')}</p>`;
            
            // Count rule types
            const snortCount = rules.filter(r => r.type === 'snort').length;
            const suricataCount = rules.filter(r => r.type === 'suricata').length;
            
            analysisHTML += `<p>Snort Rules: ${snortCount}</p>`;
            analysisHTML += `<p>Suricata Rules: ${suricataCount}</p>`;
        }
        
        analysisHTML += `</div>`;
        
        resultsDiv.innerHTML = analysisHTML;
    }

    showSuccessMessage(message) {
        this.showMessage(message, 'success');
    }

    showErrorMessage(message) {
        this.showMessage(message, 'error');
    }

    showMessage(message, type) {
        // Create a temporary message element
        const messageDiv = document.createElement('div');
        messageDiv.className = `message message-${type}`;
        messageDiv.textContent = message;
        
        // Add to the top of the container
        const container = document.querySelector('.container');
        if (container) {
            container.insertBefore(messageDiv, container.firstChild);
            
            // Remove after 3 seconds
            setTimeout(() => {
                if (messageDiv.parentNode) {
                    messageDiv.parentNode.removeChild(messageDiv);
                }
            }, 3000);
        }
    }
}

// Initialize the application when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Initialize the app
    window.siemApp = new SIEMRulesApp();
    
    // Make functions globally available for onclick handlers
    window.convertToSnort = () => window.siemApp.convertToSnort();
    window.convertToSuricata = () => window.siemApp.convertToSuricata();
    window.analyzeRules = () => window.siemApp.analyzeRules();
    window.clearInput = () => window.siemApp.clearInput();
    window.copyOutput = () => window.siemApp.copyOutput();
    window.clearLog = () => window.siemApp.clearLog();
});