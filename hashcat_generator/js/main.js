/**
 * Main Controller - Coordinates all modules and handles UI interactions
 */

class HashcatGeneratorApp {
    constructor() {
        this.ai = new PasswordPatternAI();
        this.patternAnalyzer = new PatternAnalyzer();
        this.wordlistBuilder = new WordlistBuilder();
        this.maskGenerator = new MaskGenerator();
        this.cliGenerator = new HashcatCLIGenerator();
        this.geolocator = new GeolocationDetector();
        
        this.currentWordlist = [];
        this.currentMasks = [];
        this.currentCommands = [];
        
        this.initializeEventListeners();
        this.initializeTabs();
        this.autoDetectLocation();
        this.loadLearnedPatterns();
    }

    /**
     * Initialize event listeners
     */
    initializeEventListeners() {
        // Generate button
        document.getElementById('generateBtn').addEventListener('click', () => {
            this.handleGenerate();
        });

        // File preview handlers
        document.getElementById('usersFile').addEventListener('change', (e) => {
            this.previewFile(e.target.files[0], 'usersPreview');
        });

        // Cracked passwords file handler
        document.getElementById('crackedPasswordsFile').addEventListener('change', async (e) => {
            if (e.target.files[0]) {
                await this.analyzeCrackedPasswords(e.target.files[0]);
            }
        });

        // Location detection button
        document.getElementById('detectLocationBtn').addEventListener('click', () => {
            this.detectLocation();
        });

        // Security Insights toggle
        const securityInsightsToggle = document.getElementById('securityInsightsToggle');
        const securityInsightsContent = document.getElementById('securityInsightsContent');
        if (securityInsightsToggle && securityInsightsContent) {
            securityInsightsToggle.addEventListener('click', () => {
                const isExpanded = securityInsightsContent.style.display !== 'none';
                securityInsightsContent.style.display = isExpanded ? 'none' : 'block';
                securityInsightsToggle.classList.toggle('expanded', !isExpanded);
            });
        }

        // Download buttons
        document.getElementById('downloadWordlist').addEventListener('click', () => {
            this.downloadWordlist();
        });

        document.getElementById('copyWordlist').addEventListener('click', () => {
            this.copyToClipboard(this.currentWordlist.join('\n'), 'Wordlist copied!');
        });

        // Individual copy buttons for commands are handled in displayCommands()
    }

    /**
     * Initialize tab functionality
     */
    initializeTabs() {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tabName = e.target.dataset.tab;
                this.switchTab(tabName);
            });
        });
    }

    /**
     * Switch between tabs
     */
    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
            if (btn.dataset.tab === tabName) {
                btn.classList.add('active');
            }
        });

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });

        const activeTab = document.getElementById(`${tabName}Tab`);
        if (activeTab) {
            activeTab.classList.add('active');
        }
    }

    /**
     * Preview uploaded file contents
     */
    async previewFile(file, previewElementId) {
        if (!file) return;

        try {
            const text = await this.readFileAsText(file);
            const lines = text.split('\n').slice(0, 10); // Show first 10 lines
            const preview = document.getElementById(previewElementId);
            
            if (lines.length > 0) {
                preview.innerHTML = `<strong>Preview (first ${Math.min(10, lines.length)} lines):</strong><br>` +
                    lines.join('<br>') +
                    (text.split('\n').length > 10 ? '<br><em>... and more</em>' : '');
            }
        } catch (error) {
            console.error('Error reading file:', error);
        }
    }

    /**
     * Read file as text
     */
    readFileAsText(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = reject;
            reader.readAsText(file);
        });
    }

    /**
     * Main generation handler
     */
    async handleGenerate() {
        const btn = document.getElementById('generateBtn');
        const btnText = document.getElementById('generateBtnText');
        const btnLoader = document.getElementById('generateBtnLoader');
        const outputSection = document.getElementById('outputSection');

        try {
            // Show loading state
            btn.disabled = true;
            btnText.style.display = 'none';
            btnLoader.style.display = 'inline-block';
            outputSection.style.display = 'none';

            // Collect form data
            const formData = this.collectFormData();

            // Initialize AI if needed
            await this.ai.initialize();

            // Build wordlist
            const wordlist = await this.wordlistBuilder.buildWordlist(formData);
            this.currentWordlist = wordlist;

            // Analyze patterns and generate masks
            const aiSuggestions = this.ai.analyzePatterns(formData);
            let masks = this.maskGenerator.generateMasks(aiSuggestions, formData);
            
            // Enhance masks with AI-learned patterns
            masks = this.patternAnalyzer.getImprovedMasks(masks);
            this.currentMasks = masks;

            // Generate CLI commands
            const commandData = {
                masks: masks,
                hashFile: 'hashes.txt',
                wordlistFile: 'generated_wordlist.txt',
                hashType: '0', // MD5
                workload: 3
            };
            const commands = this.cliGenerator.generateCommandSet(commandData);
            this.currentCommands = commands;

            // Display results
            this.displayResults(wordlist, masks, commands);

            // Show output section
            outputSection.style.display = 'block';
            outputSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

        } catch (error) {
            console.error('Error generating:', error);
            alert('Error generating wordlist and masks: ' + error.message);
        } finally {
            // Reset button state
            btn.disabled = false;
            btnText.style.display = 'inline';
            btnLoader.style.display = 'none';
        }
    }

    /**
     * Collect data from form
     */
    collectFormData() {
        return {
            location: document.getElementById('location').value.trim(),
            companyName: document.getElementById('companyName').value.trim(),
            usersFile: document.getElementById('usersFile').files[0],
            year: parseInt(document.getElementById('year').value) || new Date().getFullYear(),
            wordlistFile: document.getElementById('wordlistFile').files[0],
            customFile: document.getElementById('customFile').files[0],
            includeSeasonal: document.getElementById('includeSeasonal').checked,
            includeCompanyVariations: document.getElementById('includeCompanyVariations').checked,
            includeLocationVariations: document.getElementById('includeLocationVariations').checked
        };
    }

    /**
     * Display results in UI
     */
    displayResults(wordlist, masks, commands) {
        // Display wordlist
        this.displayWordlist(wordlist);

        // Display masks
        this.displayMasks(masks);

        // Display commands
        this.displayCommands(commands);
    }

    /**
     * Display wordlist
     */
    displayWordlist(wordlist) {
        const output = document.getElementById('wordlistOutput');
        const stats = document.getElementById('wordlistStats');
        const preview = wordlist.slice(0, 500).join('\n');
        const remaining = wordlist.length > 500 ? `\n\n... and ${wordlist.length - 500} more entries` : '';

        output.textContent = preview + remaining;
        stats.textContent = `${wordlist.length.toLocaleString()} entries`;
    }

    /**
     * Display masks
     */
    displayMasks(masks) {
        const maskContainer = document.getElementById('maskOutput');
        const insightsContainer = document.getElementById('aiInsights');
        if (!maskContainer) {
            console.error('Mask container not found');
            return;
        }

        maskContainer.innerHTML = '';

        // Show AI insights if available
        if (this.patternAnalyzer.analysisCount > 0) {
            const insights = this.patternAnalyzer.getCharacterFrequencyInsights();
            const patternInsights = this.patternAnalyzer.getPatternInsights();
            
            insightsContainer.style.display = 'block';
            insightsContainer.innerHTML = `
                <div class="insight-card">
                    <strong>🧠 AI Insights (from ${insights.totalAnalyzed} analyzed passwords):</strong><br>
                    <span>Top Characters: ${insights.topCharacters.slice(0, 5).map(c => `<strong>${c.char}</strong> ${c.frequency}`).join(', ')}</span><br>
                    <span>Top Patterns: ${patternInsights.topPatterns.slice(0, 3).map(p => `<strong>${p.pattern}</strong> ${p.frequency}`).join(', ')}</span>
                </div>
            `;
        } else {
            insightsContainer.style.display = 'none';
        }

        masks.forEach((maskData, index) => {
            const card = document.createElement('div');
            card.className = 'mask-card';

            const examplesHtml = maskData.examples && maskData.examples.length > 0
                ? `<div class="mask-example">Examples: ${maskData.examples.slice(0, 3).join(', ')}</div>`
                : '';

            const aiBadge = maskData.aiEnhanced 
                ? `<span style="background:#667eea; color:white; padding:2px 8px; border-radius:4px; font-size:11px; margin-left:5px;">🤖 AI-Enhanced</span>`
                : '';
            
            const customCharsetInfo = maskData.customCharset
                ? `<div style="margin-top:5px; font-size:11px; color:#667eea;">
                    <strong>Optimized Charset:</strong> ${this.escapeHtml(maskData.customCharset.substring(0, 30))}${maskData.customCharset.length > 30 ? '...' : ''}
                   </div>`
                : '';

            card.innerHTML = `
                <h3>Mask #${index + 1} <span style="font-size:12px; color:#999;">(${Math.round(maskData.confidence * 100)}% confidence)</span>${aiBadge}</h3>
                <div class="mask-pattern">${maskData.mask}</div>
                <div class="mask-description">${maskData.description}</div>
                ${customCharsetInfo}
                ${examplesHtml}
                <div style="margin-top:10px; font-size:11px; color:#999;">
                    Pattern: ${maskData.pattern}
                </div>
            `;

            maskContainer.appendChild(card);
        });
    }

    /**
     * Display CLI commands in individual panels
     */
    displayCommands(commands) {
        const container = document.getElementById('hashcatCommandsContainer');
        if (!container) return;
        
        container.innerHTML = '';
        
        // Group commands by category
        const categories = {};
        commands.forEach(cmd => {
            if (!categories[cmd.category]) {
                categories[cmd.category] = [];
            }
            categories[cmd.category].push(cmd);
        });
        
        // Create panels for each command
        Object.entries(categories).forEach(([category, cmds]) => {
            cmds.forEach((cmd, index) => {
                const panel = document.createElement('div');
                panel.className = 'command-panel';
                panel.dataset.commandIndex = `${category}_${index}`;
                
                const categoryLabel = category.replace(/_/g, ' ').toUpperCase();
                
                panel.innerHTML = `
                    <div class="command-panel-category">${categoryLabel}</div>
                    <div class="command-panel-header">
                        <div class="command-panel-title">
                            <h3>${cmd.title}</h3>
                            <p>${cmd.description}</p>
                        </div>
                        <button class="command-panel-copy" data-command="${this.escapeHtml(cmd.command)}">
                            📋 Copy Command
                        </button>
                    </div>
                    <div class="command-panel-body">${this.escapeHtml(cmd.command)}</div>
                `;
                
                // Add copy button event listener
                const copyBtn = panel.querySelector('.command-panel-copy');
                copyBtn.addEventListener('click', () => {
                    this.copyCommandToClipboard(cmd.command, copyBtn);
                });
                
                container.appendChild(panel);
            });
        });
        
        // Add notes panel at the end
        const notesPanel = document.createElement('div');
        notesPanel.className = 'command-panel';
        notesPanel.style.background = '#f8f9fa';
        notesPanel.style.borderColor = '#dee2e6';
        notesPanel.innerHTML = `
            <div class="command-panel-header">
                <div class="command-panel-title">
                    <h3>📝 Notes</h3>
                    <ul style="margin: 10px 0 0 0; padding-left: 20px; color: #666; font-size: 0.9em;">
                        <li>Replace "hashes.txt" with your actual hash file</li>
                        <li>Replace hash type (-m) if not using MD5</li>
                        <li>Adjust -w workload (1-4) based on your system</li>
                        <li>Use --show to display already cracked hashes</li>
                        <li>Use --status to see progress</li>
                    </ul>
                </div>
            </div>
        `;
        container.appendChild(notesPanel);
    }
    
    /**
     * Copy individual command to clipboard
     */
    async copyCommandToClipboard(command, button) {
        try {
            await this.copyToClipboard(command, 'Command copied!');
            
            // Visual feedback
            const originalText = button.innerHTML;
            button.innerHTML = '✓ Copied!';
            button.classList.add('copied');
            
            setTimeout(() => {
                button.innerHTML = originalText;
                button.classList.remove('copied');
            }, 2000);
        } catch (error) {
            console.error('Failed to copy command:', error);
        }
    }
    
    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Download wordlist as file
     */
    downloadWordlist() {
        const blob = new Blob([this.currentWordlist.join('\n')], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `hashcat_wordlist_${Date.now()}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    /**
     * Auto-detect location on page load (with user permission)
     */
    async autoDetectLocation() {
        // Only auto-detect if location field is empty
        const locationInput = document.getElementById('location');
        if (locationInput.value.trim() !== '') {
            return; // User already has a location
        }

        // Check if geolocation is available
        if (!GeolocationDetector.isAvailable()) {
            this.updateLocationStatus('Geolocation not available in your browser.', 'info');
            return;
        }

        // Show that we're attempting auto-detection
        this.updateLocationStatus('Auto-detecting your location... (browser may ask for permission)', 'info');

        // Try to detect location (will prompt for permission if not granted)
        try {
            const locationName = await this.geolocator.detectLocation();
            if (locationName) {
                locationInput.value = locationName;
                this.updateLocationStatus(`✓ Location auto-detected: ${locationName}`, 'success');
                
                // Get city name for additional context
                const cityName = this.geolocator.getCityName();
                if (cityName && cityName !== locationName) {
                    // Optionally add city to wordlist variations
                    console.log('Detected city:', cityName);
                }
            }
        } catch (error) {
            // Silent fail - don't show error on auto-detect, user can click button if they want
            console.log('Auto-location detection:', error.message);
            
            // Update status to indicate manual option is available
            if (error.message.includes('Permission denied')) {
                this.updateLocationStatus('Location access denied. Click "Auto-detect" to allow location access.', 'info');
            } else {
                this.updateLocationStatus('Auto-detection unavailable. Click "Auto-detect" to try manually.', 'info');
            }
        }
    }

    /**
     * Detect location manually (button click)
     */
    async detectLocation() {
        const btn = document.getElementById('detectLocationBtn');
        const btnText = document.getElementById('detectLocationBtnText');
        const btnLoader = document.getElementById('detectLocationBtnLoader');
        const locationInput = document.getElementById('location');

        // Check if geolocation is available
        if (!GeolocationDetector.isAvailable()) {
            this.updateLocationStatus('Geolocation is not supported by your browser.', 'error');
            return;
        }

        try {
            // Show loading state
            btn.disabled = true;
            btnText.style.display = 'none';
            btnLoader.style.display = 'inline-block';
            this.updateLocationStatus('Detecting your location...', 'info');

            // Detect location
            const locationName = await this.geolocator.detectLocation();
            
            if (locationName) {
                locationInput.value = locationName;
                this.updateLocationStatus(`✓ Location detected successfully: ${locationName}`, 'success');
            } else {
                throw new Error('Could not determine location name');
            }

        } catch (error) {
            console.error('Location detection error:', error);
            this.updateLocationStatus(`✗ ${error.message}`, 'error');
        } finally {
            // Reset button state
            btn.disabled = false;
            btnText.style.display = 'inline';
            btnLoader.style.display = 'none';
        }
    }

    /**
     * Update location status message
     */
    updateLocationStatus(message, type = 'info') {
        const statusElement = document.getElementById('locationStatus');
        if (!statusElement) return;

        // Remove previous status classes
        statusElement.classList.remove('status-success', 'status-error', 'status-warning', 'status-info');
        
        // Add new status class
        statusElement.classList.add(`status-${type}`);
        
        // Update message
        const icon = {
            'success': '✓',
            'error': '✗',
            'warning': '⚠',
            'info': 'ℹ'
        }[type] || '';
        
        statusElement.textContent = `${icon} ${message}`;
    }

    /**
     * Copy text to clipboard
     */
    async copyToClipboard(text, successMessage) {
        try {
            await navigator.clipboard.writeText(text);
            alert(successMessage || 'Copied to clipboard!');
        } catch (error) {
            console.error('Failed to copy:', error);
            // Fallback method
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
            alert(successMessage || 'Copied to clipboard!');
        }
    }

    /**
     * Analyze cracked passwords file for AI learning
     */
    async analyzeCrackedPasswords(file) {
        try {
            const text = await this.readFileAsText(file);
            const passwords = text.split('\n')
                .map(line => line.trim())
                .filter(line => line.length > 0);
            
            if (passwords.length === 0) {
                alert('No passwords found in file');
                return;
            }

            // Analyze passwords
            this.patternAnalyzer.analyzeCrackedPasswords(passwords);
            
            // Update preview
            const preview = document.getElementById('crackedPasswordsPreview');
            const insights = this.patternAnalyzer.getCharacterFrequencyInsights();
            const patternInsights = this.patternAnalyzer.getPatternInsights();
            
            preview.innerHTML = `
                <strong>✅ Analyzed ${passwords.length} passwords</strong><br>
                <strong>Top Characters:</strong> ${insights.topCharacters.slice(0, 5).map(c => `${c.char} (${c.frequency})`).join(', ')}<br>
                <strong>Top Patterns:</strong> ${patternInsights.topPatterns.slice(0, 3).map(p => `${p.pattern} (${p.frequency})`).join(', ')}<br>
                <div style="background:#e8f5e9; padding:10px; margin-top:10px; border-radius:5px; border-left:3px solid #4caf50;">
                    <strong>💡 Next Step:</strong> Click "Generate Mask & Wordlist" to see AI-enhanced masks using these learned patterns!
                </div>
            `;
            
            // Save learned patterns to localStorage
            this.saveLearnedPatterns();
            
            console.log('AI Pattern Analysis:', {
                characterFrequency: insights,
                patterns: patternInsights,
                learnedMasks: this.patternAnalyzer.learnedMasks.length
            });
            
        } catch (error) {
            console.error('Error analyzing cracked passwords:', error);
            alert('Error analyzing passwords: ' + error.message);
        }
    }

    /**
     * Save learned patterns to localStorage
     */
    saveLearnedPatterns() {
        try {
            const patterns = this.patternAnalyzer.exportPatterns();
            localStorage.setItem('hashcat_learned_patterns', JSON.stringify(patterns));
        } catch (error) {
            console.warn('Could not save patterns to localStorage:', error);
        }
    }

    /**
     * Load learned patterns from localStorage
     */
    loadLearnedPatterns() {
        try {
            const saved = localStorage.getItem('hashcat_learned_patterns');
            if (saved) {
                const patterns = JSON.parse(saved);
                this.patternAnalyzer.importPatterns(patterns);
                console.log(`Loaded ${patterns.analysisCount || 0} previously analyzed passwords`);
            }
        } catch (error) {
            console.warn('Could not load patterns from localStorage:', error);
        }
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.app = new HashcatGeneratorApp();
    console.log('HashCat Mask Generator initialized');
});
