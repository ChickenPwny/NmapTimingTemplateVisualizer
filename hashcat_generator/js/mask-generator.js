/**
 * Mask Generator - Creates HashCat mask patterns
 */

class MaskGenerator {
    constructor() {
        this.maskCharsets = {
            '?l': 'abcdefghijklmnopqrstuvwxyz',
            '?u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            '?d': '0123456789',
            '?s': ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~',
            '?a': '?l?u?d?s',
            '?b': '0x00 - 0xff'
        };
    }

    /**
     * Generate mask patterns based on AI analysis
     */
    generateMasks(aiSuggestions, data) {
        const masks = [];
        
        // Convert AI suggestions to mask cards
        aiSuggestions.forEach((suggestion, index) => {
            masks.push({
                id: index + 1,
                mask: suggestion.mask,
                description: suggestion.description,
                examples: suggestion.examples || [],
                confidence: suggestion.confidence,
                pattern: suggestion.pattern,
                charsets: this.analyzeMaskCharsets(suggestion.mask)
            });
        });
        
        // Add custom masks based on input analysis
        const customMasks = this.generateCustomMasks(data);
        masks.push(...customMasks);
        
        // Remove duplicates
        const uniqueMasks = [];
        const seenMasks = new Set();
        masks.forEach(mask => {
            if (!seenMasks.has(mask.mask)) {
                seenMasks.add(mask.mask);
                uniqueMasks.push(mask);
            }
        });
        
        return uniqueMasks;
    }

    /**
     * Analyze mask and return charsets used
     */
    analyzeMaskCharsets(mask) {
        const charsets = [];
        const matches = mask.match(/\?[ludsa]/g) || [];
        matches.forEach(char => {
            if (!charsets.includes(char)) {
                charsets.push(char);
            }
        });
        return charsets;
    }

    /**
     * Generate custom masks based on input data
     */
    generateCustomMasks(data) {
        const masks = [];
        
        // Analyze input lengths
        const companyLength = data.companyName ? data.companyName.length : 0;
        const locationLength = data.location ? data.location.length : 0;
        const yearLength = data.year ? data.year.toString().length : 4;
        
        // Mask 1: Short pattern (4-6 chars)
        masks.push({
            id: 'custom1',
            mask: '?l?l?l?l?d?d',
            description: '4 lowercase + 2 digits (Short password pattern)',
            examples: ['pass12', 'user34', 'test56'],
            confidence: 0.60,
            pattern: 'short_pattern'
        });
        
        // Mask 2: Medium pattern (6-8 chars)
        masks.push({
            id: 'custom2',
            mask: '?l?l?l?l?l?l?d?d',
            description: '6 lowercase + 2 digits (Medium password pattern)',
            examples: ['password12', 'username34'],
            confidence: 0.55,
            pattern: 'medium_pattern'
        });
        
        // Mask 3: Year-based pattern
        if (data.year) {
            masks.push({
                id: 'custom3',
                mask: '?l?l?l?l?l?d?d?d?d',
                description: '5 lowercase + 4 digits (Word + Year pattern)',
                examples: [`${data.companyName?.toLowerCase().substring(0,5) || 'company'}${data.year}`],
                confidence: 0.70,
                pattern: 'year_pattern'
            });
        }
        
        // Mask 4: Mixed case pattern
        masks.push({
            id: 'custom4',
            mask: '?u?l?l?l?l?l?d?d?d',
            description: 'Capitalized word + 3 digits (Capitalized pattern)',
            examples: ['Company123', 'Location456'],
            confidence: 0.65,
            pattern: 'mixed_case'
        });
        
        // Mask 5: With special characters
        masks.push({
            id: 'custom5',
            mask: '?l?l?l?l?l?l?d?d?d?d?s',
            description: '6 lowercase + 4 digits + 1 special char',
            examples: ['password2024!', 'username2023@'],
            confidence: 0.50,
            pattern: 'with_special'
        });
        
        // Mask 6: Increment patterns
        masks.push({
            id: 'custom6',
            mask: '?l?l?l?l?d?d?d?d?i',
            description: '4 lowercase + 4 digits with increment',
            examples: ['pass1234', 'pass1235', 'pass1236'],
            confidence: 0.45,
            pattern: 'increment'
        });
        
        return masks;
    }

    /**
     * Generate maskprocessor command for a mask
     */
    generateMaskprocessorCommand(mask, options = {}) {
        let cmd = 'mp64.bin';
        const parts = [];
        
        // Add custom charsets if needed
        if (options.customCharsets) {
            Object.entries(options.customCharsets).forEach(([num, charset], index) => {
                parts.push(`-${num + 1} "${charset}"`);
            });
        }
        
        // Add increment if specified
        if (options.increment) {
            parts.push(`-i ${options.increment.start}:${options.increment.stop}`);
        }
        
        // Add output file
        if (options.outputFile) {
            parts.push(`-o "${options.outputFile}"`);
        }
        
        // Add the mask
        parts.push(`"${mask}"`);
        
        return `${cmd} ${parts.join(' ')}`;
    }

    /**
     * Calculate combinations for a mask
     */
    calculateCombinations(mask) {
        let combinations = 1;
        const charsetCounts = {
            '?l': 26,
            '?u': 26,
            '?d': 10,
            '?s': 33,
            '?a': 95,
            '?b': 256
        };
        
        const matches = mask.match(/\?[ludsa]/g) || [];
        matches.forEach(char => {
            if (charsetCounts[char]) {
                combinations *= charsetCounts[char];
            }
        });
        
        // Handle increment
        if (mask.includes('?i')) {
            combinations *= 100; // Rough estimate
        }
        
        return combinations;
    }

    /**
     * Format mask for display
     */
    formatMask(mask) {
        return mask
            .replace(/\?l/g, '<span class="mask-char">?l</span>')
            .replace(/\?u/g, '<span class="mask-char">?u</span>')
            .replace(/\?d/g, '<span class="mask-char">?d</span>')
            .replace(/\?s/g, '<span class="mask-char">?s</span>')
            .replace(/\?a/g, '<span class="mask-char">?a</span>');
    }
}

// Export for use in other modules
window.MaskGenerator = MaskGenerator;
