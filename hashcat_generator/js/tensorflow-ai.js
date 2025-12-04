/**
 * TensorFlow.js AI Model for Password Pattern Recognition
 * Analyzes user inputs to suggest optimal mask patterns
 */

class PasswordPatternAI {
    constructor() {
        this.model = null;
        this.initialized = false;
    }

    /**
     * Initialize the AI model (using a simple neural network)
     */
    async initialize() {
        if (this.initialized) return;

        try {
            // Create a simple model for pattern recognition
            this.model = tf.sequential({
                layers: [
                    tf.layers.dense({ inputShape: [10], units: 16, activation: 'relu' }),
                    tf.layers.dense({ units: 8, activation: 'relu' }),
                    tf.layers.dense({ units: 4, activation: 'sigmoid' })
                ]
            });

            this.initialized = true;
            console.log('TensorFlow.js model initialized');
        } catch (error) {
            console.warn('TensorFlow.js initialization failed, using rule-based fallback:', error);
            this.initialized = false;
        }
    }

    /**
     * Extract features from user inputs
     */
    extractFeatures(data) {
        const features = {
            companyLength: data.companyName ? data.companyName.length : 0,
            locationLength: data.location ? data.location.length : 0,
            userCount: data.users ? data.users.length : 0,
            hasYear: data.year ? 1 : 0,
            hasSeasonal: data.includeSeasonal ? 1 : 0,
            totalWords: (data.companyName?.split(' ').length || 0) + (data.location?.split(' ').length || 0),
            hasNumbers: /\d/.test(data.companyName || '') || /\d/.test(data.location || '') ? 1 : 0,
            hasSpecialChars: /[!@#$%^&*(),.?":{}|<>]/.test(data.companyName || '') || /[!@#$%^&*(),.?":{}|<>]/.test(data.location || '') ? 1 : 0,
            averageUserLength: data.users && data.users.length > 0 
                ? data.users.reduce((sum, u) => sum + u.length, 0) / data.users.length 
                : 0,
            complexity: 0
        };

        // Calculate complexity score
        features.complexity = (
            (features.companyLength > 0 ? 1 : 0) +
            (features.locationLength > 0 ? 1 : 0) +
            (features.userCount > 0 ? 1 : 0) +
            features.hasYear +
            features.hasSeasonal +
            (features.hasNumbers ? 1 : 0) +
            (features.hasSpecialChars ? 1 : 0)
        ) / 7;

        return features;
    }

    /**
     * Analyze patterns and suggest mask structures
     */
    analyzePatterns(data) {
        const features = this.extractFeatures(data);
        const suggestions = [];

        // Rule-based pattern suggestions (works even without TensorFlow)
        const company = data.companyName || '';
        const location = data.location || '';
        const year = data.year || '';
        const users = data.users || [];

        // Pattern 1: Company + Year variations
        if (company) {
            suggestions.push({
                mask: '?l?l?l?l?d?d?d?d',
                description: '4 lowercase letters + 4 digits (Company + Year pattern)',
                examples: [`${company.toLowerCase().substring(0,4)}${year}`, `${company.toLowerCase()}2024`],
                confidence: 0.85,
                pattern: 'company_year'
            });
        }

        // Pattern 2: Location + Year
        if (location) {
            const locShort = location.toLowerCase().replace(/\s+/g, '').substring(0, 6);
            suggestions.push({
                mask: '?l?l?l?l?l?l?d?d?d?d',
                description: '6 lowercase letters + 4 digits (Location + Year)',
                examples: [`${locShort}${year}`, `${location.toLowerCase().substring(0,6)}2024`],
                confidence: 0.80,
                pattern: 'location_year'
            });
        }

        // Pattern 3: User + Company variations
        if (users.length > 0 && company) {
            suggestions.push({
                mask: '?l?l?l?l?l?l?d?d',
                description: '6 lowercase + 2 digits (User + Company pattern)',
                examples: users.slice(0, 2).map(u => `${u.toLowerCase().substring(0,4)}${company.toLowerCase().substring(0,2)}12`),
                confidence: 0.75,
                pattern: 'user_company'
            });
        }

        // Pattern 4: Seasonal words
        if (data.includeSeasonal) {
            const seasons = ['winter', 'spring', 'summer', 'fall'];
            suggestions.push({
                mask: '?l?l?l?l?l?l?d?d?d?d',
                description: '6 lowercase + 4 digits (Seasonal + Year)',
                examples: seasons.map(s => `${s}${year}`),
                confidence: 0.70,
                pattern: 'seasonal_year'
            });
        }

        // Pattern 5: Company + Special chars
        if (company) {
            suggestions.push({
                mask: '?l?l?l?l?l?d?d?d?d?s',
                description: '5 lowercase + 4 digits + 1 special char',
                examples: [`${company.toLowerCase().substring(0,5)}${year}!`, `${company.toLowerCase()}2024@`],
                confidence: 0.65,
                pattern: 'company_year_special'
            });
        }

        // Pattern 6: Mixed case + numbers
        suggestions.push({
            mask: '?l?u?l?l?l?d?d?d?d',
            description: 'Mixed case + 4 digits (Capitalized word + Year)',
            examples: [
                company ? `${company.charAt(0).toUpperCase()}${company.toLowerCase().substring(1,4)}${year}` : 'Pass2024',
                location ? `${location.charAt(0).toUpperCase()}${location.toLowerCase().substring(1,4)}${year}` : 'City2024'
            ],
            confidence: 0.60,
            pattern: 'mixed_year'
        });

        // Pattern 7: Short passwords (common pattern)
        suggestions.push({
            mask: '?l?l?l?l?d?d?d',
            description: '4 lowercase + 3 digits (Short password pattern)',
            examples: ['pass123', 'user456', 'test789'],
            confidence: 0.55,
            pattern: 'short'
        });

        // Pattern 8: Long passwords with mixed content
        suggestions.push({
            mask: '?l?l?l?l?l?l?l?l?d?d?d?d',
            description: '8 lowercase + 4 digits (Long password pattern)',
            examples: ['password2024', 'username1234', 'company2024'],
            confidence: 0.50,
            pattern: 'long'
        });

        // Sort by confidence
        suggestions.sort((a, b) => b.confidence - a.confidence);

        return suggestions;
    }

    /**
     * Predict optimal mask length based on patterns
     */
    predictOptimalLength(data) {
        const features = this.extractFeatures(data);
        
        // Rule-based length prediction
        if (features.complexity > 0.7) {
            return { min: 8, max: 12, recommended: 10 };
        } else if (features.complexity > 0.4) {
            return { min: 6, max: 10, recommended: 8 };
        } else {
            return { min: 4, max: 8, recommended: 6 };
        }
    }

    /**
     * Generate mask variations based on input analysis
     */
    generateMaskVariations(baseMask, data) {
        const variations = [baseMask];
        const features = this.extractFeatures(data);

        // Add variations based on features
        if (features.hasNumbers) {
            variations.push(baseMask.replace('?d', '?d?d'));
        }

        if (features.hasSpecialChars || features.complexity > 0.6) {
            variations.push(baseMask + '?s');
            variations.push('?s' + baseMask);
        }

        // Add increment variations
        variations.push(baseMask + '?1');
        variations.push('?1' + baseMask);

        return [...new Set(variations)]; // Remove duplicates
    }
}

// Export for use in other modules
window.PasswordPatternAI = PasswordPatternAI;
