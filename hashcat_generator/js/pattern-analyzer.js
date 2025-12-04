/**
 * Pattern Analyzer - AI-powered analysis of successful password cracks
 * Learns patterns from cracked passwords to improve mask suggestions
 */

class PatternAnalyzer {
    constructor() {
        this.patterns = {
            characterFrequency: {},
            positionFrequency: {}, // Character frequency by position
            commonPatterns: [], // Common patterns like "word123", "Word!", etc.
            lengthDistribution: {},
            characterPairs: {}, // Common character pairs/sequences
            wordPatterns: {} // Patterns like "word+number", "word+special", etc.
        };
        
        this.learnedMasks = [];
        this.analysisCount = 0;
        
        // Initialize with common knowledge
        this._initializeCommonPatterns();
    }

    /**
     * Initialize with common password patterns
     */
    _initializeCommonPatterns() {
        // Common character frequency (English)
        this.patterns.characterFrequency = {
            'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
            'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
            'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4, 'w': 2.4,
            'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5,
            'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07
        };
        
        // Common patterns
        this.patterns.commonPatterns = [
            { pattern: 'word+number', frequency: 0.35 },
            { pattern: 'word+special', frequency: 0.15 },
            { pattern: 'word+number+special', frequency: 0.20 },
            { pattern: 'number+word', frequency: 0.10 },
            { pattern: 'capitalized+number', frequency: 0.12 },
            { pattern: 'word+year', frequency: 0.18 }
        ];
    }

    /**
     * Analyze a set of successfully cracked passwords
     * @param {Array<string>} crackedPasswords - Array of successfully cracked passwords
     */
    analyzeCrackedPasswords(crackedPasswords) {
        if (!crackedPasswords || crackedPasswords.length === 0) {
            return;
        }

        this.analysisCount += crackedPasswords.length;
        
        // Analyze each password
        crackedPasswords.forEach(password => {
            if (!password || typeof password !== 'string') return;
            
            this._analyzeCharacterFrequency(password);
            this._analyzePositionFrequency(password);
            this._analyzePatterns(password);
            this._analyzeCharacterPairs(password);
            this._analyzeLength(password);
        });

        // Update learned patterns
        this._updateLearnedPatterns();
        this._generateLearnedMasks();
    }

    /**
     * Analyze character frequency across all passwords
     */
    _analyzeCharacterFrequency(password) {
        const lower = password.toLowerCase();
        for (let char of lower) {
            if (/[a-z]/.test(char)) {
                this.patterns.characterFrequency[char] = 
                    (this.patterns.characterFrequency[char] || 0) + 1;
            }
        }
    }

    /**
     * Analyze character frequency by position
     */
    _analyzePositionFrequency(password) {
        if (!this.patterns.positionFrequency) {
            this.patterns.positionFrequency = {};
        }

        for (let i = 0; i < password.length; i++) {
            const pos = i;
            const char = password[i].toLowerCase();
            
            if (!this.patterns.positionFrequency[pos]) {
                this.patterns.positionFrequency[pos] = {};
            }
            
            if (/[a-z]/.test(char)) {
                this.patterns.positionFrequency[pos][char] = 
                    (this.patterns.positionFrequency[pos][char] || 0) + 1;
            } else if (/[A-Z]/.test(password[i])) {
                // Track uppercase preference at position
                if (!this.patterns.positionFrequency[pos]._uppercase) {
                    this.patterns.positionFrequency[pos]._uppercase = 0;
                }
                this.patterns.positionFrequency[pos]._uppercase++;
            } else if (/[0-9]/.test(char)) {
                if (!this.patterns.positionFrequency[pos]._digit) {
                    this.patterns.positionFrequency[pos]._digit = 0;
                }
                this.patterns.positionFrequency[pos]._digit++;
            } else {
                if (!this.patterns.positionFrequency[pos]._special) {
                    this.patterns.positionFrequency[pos]._special = 0;
                }
                this.patterns.positionFrequency[pos]._special++;
            }
        }
    }

    /**
     * Analyze common patterns in passwords
     */
    _analyzePatterns(password) {
        // Detect pattern types
        const hasWord = /[a-zA-Z]{3,}/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSpecial = /[^a-zA-Z0-9]/.test(password);
        const hasCapital = /[A-Z]/.test(password);
        const startsCapital = /^[A-Z]/.test(password);
        const endsNumber = /[0-9]$/.test(password);
        const endsSpecial = /[^a-zA-Z0-9]$/.test(password);

        // Identify pattern
        let patternType = 'unknown';
        if (hasWord && hasNumber && !hasSpecial) {
            patternType = startsCapital ? 'CapitalizedWord+Number' : 'word+number';
        } else if (hasWord && hasSpecial && !hasNumber) {
            patternType = 'word+special';
        } else if (hasWord && hasNumber && hasSpecial) {
            patternType = 'word+number+special';
        } else if (hasNumber && hasWord) {
            patternType = 'number+word';
        } else if (hasWord && endsNumber) {
            patternType = 'word+endingNumber';
        }

        // Update pattern frequency
        const existing = this.patterns.commonPatterns.find(p => p.pattern === patternType);
        if (existing) {
            existing.frequency = (existing.frequency || 0) + 1;
        } else if (patternType !== 'unknown') {
            this.patterns.commonPatterns.push({ pattern: patternType, frequency: 1 });
        }
    }

    /**
     * Analyze character pairs and sequences
     */
    _analyzeCharacterPairs(password) {
        const lower = password.toLowerCase();
        for (let i = 0; i < lower.length - 1; i++) {
            const pair = lower.substring(i, i + 2);
            if (/[a-z]{2}/.test(pair)) {
                this.patterns.characterPairs[pair] = 
                    (this.patterns.characterPairs[pair] || 0) + 1;
            }
        }
    }

    /**
     * Analyze password length distribution
     */
    _analyzeLength(password) {
        const len = password.length;
        this.patterns.lengthDistribution[len] = 
            (this.patterns.lengthDistribution[len] || 0) + 1;
    }

    /**
     * Update learned patterns based on analysis
     */
    _updateLearnedPatterns() {
        // Normalize character frequencies
        if (this.analysisCount > 0) {
            const total = Object.values(this.patterns.characterFrequency).reduce((a, b) => a + b, 0);
            if (total > 0) {
                Object.keys(this.patterns.characterFrequency).forEach(char => {
                    this.patterns.characterFrequency[char] = 
                        (this.patterns.characterFrequency[char] / total) * 100;
                });
            }
        }

        // Normalize pattern frequencies
        const patternTotal = this.patterns.commonPatterns.reduce((sum, p) => sum + (p.frequency || 0), 0);
        if (patternTotal > 0) {
            this.patterns.commonPatterns.forEach(p => {
                p.frequency = (p.frequency / patternTotal) * 100;
            });
        }
    }

    /**
     * Generate learned masks based on analyzed patterns
     */
    _generateLearnedMasks() {
        this.learnedMasks = [];

        // Get top patterns by frequency
        const topPatterns = this.patterns.commonPatterns
            .sort((a, b) => (b.frequency || 0) - (a.frequency || 0))
            .slice(0, 5);

        // Get most common lengths (at least 10% of passwords)
        const commonLengths = Object.entries(this.patterns.lengthDistribution)
            .filter(([len, count]) => (count / this.analysisCount) >= 0.05) // At least 5% frequency
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([len]) => parseInt(len));

        // Generate masks based on learned patterns
        topPatterns.forEach(patternData => {
            const pattern = patternData.pattern;
            const frequency = patternData.frequency || 0;

            // Generate mask based on pattern type
            let mask = '';
            let description = `Learned from ${(frequency * 100).toFixed(1)}% of passwords`;

            if (pattern === 'word+number' || pattern === 'word+endingNumber') {
                // Most common: word followed by numbers
                mask = '?l?l?l?l?l?l?l?d?d?d?d'; // 7 letters + 4 digits (year)
                description += ' - Word + 4 digits';
                
                // Add variations for common lengths
                commonLengths.forEach(len => {
                    if (len >= 8 && len <= 12) {
                        const letterCount = len - 4;
                        const letterMask = '?l'.repeat(letterCount);
                        this.learnedMasks.push({
                            mask: `${letterMask}?d?d?d?d`,
                            confidence: frequency * 0.9,
                            length: len,
                            basedOn: `${(frequency * 100).toFixed(1)}% pattern frequency`,
                            description: `${description} (${len} chars)`
                        });
                    }
                });
            } else if (pattern === 'CapitalizedWord+Number') {
                mask = '?u?l?l?l?l?l?d?d?d?d'; // Capitalized + 4 digits
                description += ' - Capitalized word + 4 digits';
                this.learnedMasks.push({
                    mask: mask,
                    confidence: frequency * 0.95,
                    length: mask.match(/\?[ludsa]/g).length,
                    basedOn: `${(frequency * 100).toFixed(1)}% pattern frequency`,
                    description: description
                });
            } else if (pattern === 'word+number+special') {
                mask = '?l?l?l?l?l?l?l?d?d?d?d?s'; // Word + year + special
                description += ' - Word + 4 digits + special char';
                this.learnedMasks.push({
                    mask: mask,
                    confidence: frequency * 0.9,
                    length: mask.match(/\?[ludsa]/g).length,
                    basedOn: `${(frequency * 100).toFixed(1)}% pattern frequency`,
                    description: description
                });
            } else if (pattern === 'word+special') {
                mask = '?l?l?l?l?l?l?l?l?s'; // Word + special
                description += ' - Word + special char';
                this.learnedMasks.push({
                    mask: mask,
                    confidence: frequency * 0.85,
                    length: mask.match(/\?[ludsa]/g).length,
                    basedOn: `${(frequency * 100).toFixed(1)}% pattern frequency`,
                    description: description
                });
            }
        });

        // Generate masks based on most common lengths with position analysis
        commonLengths.forEach(length => {
            const lengthCount = this.patterns.lengthDistribution[length];
            const lengthFrequency = lengthCount / this.analysisCount;

            // Generate mask based on position frequency for this length
            let mask = '';
            let hasValidData = false;

            for (let i = 0; i < length; i++) {
                const posData = this.patterns.positionFrequency[i];
                if (!posData || Object.keys(posData).length === 0) {
                    mask += '?l'; // Default to lowercase if no data
                    continue;
                }

                hasValidData = true;
                const total = Object.values(posData).reduce((a, b) => a + b, 0);
                const digitRatio = (posData._digit || 0) / total;
                const specialRatio = (posData._special || 0) / total;
                const upperRatio = (posData._uppercase || 0) / total;

                if (digitRatio > 0.5) {
                    mask += '?d';
                } else if (specialRatio > 0.3) {
                    mask += '?s';
                } else if (upperRatio > 0.4 && i === 0) {
                    mask += '?u'; // Uppercase only at start
                } else {
                    mask += '?l'; // Default to lowercase
                }
            }

            if (mask.length > 0 && hasValidData && lengthFrequency >= 0.05) {
                // Get top characters for custom charset
                const topChars = Object.entries(this.patterns.characterFrequency)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 13)
                    .map(([char]) => char)
                    .join('');

                this.learnedMasks.push({
                    mask: mask,
                    confidence: lengthFrequency * 0.85,
                    length: length,
                    basedOn: `${lengthCount} passwords (${(lengthFrequency * 100).toFixed(1)}%)`,
                    description: `Position-based mask for ${length}-char passwords`,
                    customCharset: topChars
                });
            }
        });

        // Remove duplicates
        const seen = new Set();
        this.learnedMasks = this.learnedMasks.filter(m => {
            const key = m.mask;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });

        // Sort by confidence
        this.learnedMasks.sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
    }

    /**
     * Get improved mask suggestions based on learned patterns
     * Actually ENHANCES existing masks based on learned data
     */
    getImprovedMasks(baseMasks = []) {
        // Only enhance if we have learned patterns
        if (this.analysisCount === 0) {
            return baseMasks; // Return original if no learning yet
        }

        const improved = [];
        
        // Get learned insights
        const charInsights = this.getCharacterFrequencyInsights();
        const patternInsights = this.getPatternInsights();
        const topPatterns = patternInsights.topPatterns.map(p => p.pattern);
        const topChars = charInsights.topCharacters.slice(0, 13).map(c => c.char).join('');

        // Enhance each base mask with learned knowledge
        baseMasks.forEach(baseMask => {
            let enhancedMask = { ...baseMask };
            let confidenceBoost = 0;
            let descriptionAdditions = [];

            // Boost confidence if mask matches learned patterns
            const maskPattern = enhancedMask.pattern || '';
            if (topPatterns.some(pattern => maskPattern.includes(pattern.toLowerCase()))) {
                confidenceBoost += 0.15; // Boost for matching learned patterns
                descriptionAdditions.push('matches learned patterns');
            }

            // Boost confidence based on learned character frequency
            if (topChars.length > 0) {
                confidenceBoost += 0.10;
                descriptionAdditions.push('uses learned character frequencies');
                
                // Add custom charset based on learned frequencies
                if (!enhancedMask.customCharset) {
                    enhancedMask.customCharset = topChars.toLowerCase();
                }
            }

            // Boost if mask length matches learned length distribution
            const maskLength = (enhancedMask.mask.match(/\?[ludsa]/g) || []).length;
            if (this.patterns.lengthDistribution[maskLength]) {
                const lengthFrequency = this.patterns.lengthDistribution[maskLength] / this.analysisCount;
                if (lengthFrequency > 0.1) { // If >10% of passwords had this length
                    confidenceBoost += 0.08;
                    descriptionAdditions.push(`matches common length (${(lengthFrequency * 100).toFixed(1)}%)`);
                }
            }

            // Apply confidence boost
            enhancedMask.confidence = Math.min(0.95, (enhancedMask.confidence || 0.5) + confidenceBoost);

            // Update description with learned insights
            if (descriptionAdditions.length > 0) {
                enhancedMask.description += ` - AI-enhanced: ${descriptionAdditions.join(', ')}`;
            }

            // Mark as AI-enhanced
            enhancedMask.aiEnhanced = true;
            enhancedMask.learnedData = {
                topCharacters: topChars,
                topPatterns: topPatterns,
                analyzedCount: this.analysisCount
            };

            improved.push(enhancedMask);
        });

        // Add learned masks (high priority)
        this.learnedMasks.forEach(learned => {
            improved.push({
                mask: learned.mask,
                description: `🤖 AI-learned pattern (${learned.basedOn}) - Length ${learned.length} - Directly from ${this.analysisCount} analyzed passwords`,
                confidence: Math.min(0.95, learned.confidence * 1.1), // Higher confidence for learned
                pattern: 'ai_learned',
                examples: [],
                aiEnhanced: true,
                learnedData: {
                    topCharacters: topChars,
                    analyzedCount: this.analysisCount
                }
            });
        });

        // Sort by confidence (highest first)
        improved.sort((a, b) => (b.confidence || 0) - (a.confidence || 0));

        // Prioritize AI-enhanced masks at the top
        improved.sort((a, b) => {
            if (a.pattern === 'ai_learned' && b.pattern !== 'ai_learned') return -1;
            if (a.pattern !== 'ai_learned' && b.pattern === 'ai_learned') return 1;
            return (b.confidence || 0) - (a.confidence || 0);
        });

        return improved;
    }

    /**
     * Get character frequency insights
     */
    getCharacterFrequencyInsights() {
        const sorted = Object.entries(this.patterns.characterFrequency)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10);

        return {
            topCharacters: sorted.map(([char, freq]) => ({ char, frequency: freq.toFixed(2) + '%' })),
            totalAnalyzed: this.analysisCount
        };
    }

    /**
     * Get pattern insights
     */
    getPatternInsights() {
        const sorted = this.patterns.commonPatterns
            .sort((a, b) => (b.frequency || 0) - (a.frequency || 0))
            .slice(0, 5);

        return {
            topPatterns: sorted.map(p => ({
                pattern: p.pattern,
                frequency: p.frequency.toFixed(2) + '%'
            })),
            totalAnalyzed: this.analysisCount
        };
    }

    /**
     * Export learned patterns (for persistence)
     */
    exportPatterns() {
        return {
            patterns: this.patterns,
            learnedMasks: this.learnedMasks,
            analysisCount: this.analysisCount,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Import learned patterns (for persistence)
     */
    importPatterns(data) {
        if (data.patterns) {
            this.patterns = { ...this.patterns, ...data.patterns };
        }
        if (data.learnedMasks) {
            this.learnedMasks = data.learnedMasks;
        }
        if (data.analysisCount) {
            this.analysisCount = data.analysisCount;
        }
    }
}

// Export for use in other modules
window.PatternAnalyzer = PatternAnalyzer;
