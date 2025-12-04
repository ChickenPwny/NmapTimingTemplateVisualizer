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
        
        // Character frequency knowledge for optimized charsets
        // 'e' is most common (12.7%), 't' is 9.1%, etc.
        this.characterFrequency = {
            'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
            'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
            'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4, 'w': 2.4,
            'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5,
            'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07
        };
        
        // Most common characters (top 13 = ~90% of usage)
        this.commonChars = 'etaoinshrdlcu';
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
                charsets: this.analyzeMaskCharsets(suggestion.mask),
                customCharset: suggestion.customCharset || null // Preserve custom charset info
            });
        });
        
        // Add custom masks based on input analysis (with improved character frequency logic)
        const customMasks = this.generateCustomMasks(data);
        masks.push(...customMasks);
        
        // Sort by confidence (highest first) to prioritize optimized masks
        masks.sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
        
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
     * Generate optimized charset based on character frequency
     * Uses knowledge that 'e' is most common (12.7%), 't' is 9.1%, etc.
     */
    generateOptimizedCharset(type = 'common') {
        if (type === 'common') {
            return this.commonChars; // Top 13 most common letters (~90% usage)
        } else if (type === 'vowels') {
            return 'aeiou'; // Vowels
        } else if (type === 'consonants') {
            return 'bcdfghjklmnpqrstvwxyz'; // Consonants
        }
        return 'abcdefghijklmnopqrstuvwxyz'; // Full set
    }

    /**
     * Generate custom masks based on input data with improved character selection
     */
    generateCustomMasks(data) {
        const masks = [];
        
        // Analyze input lengths
        const companyLength = data.companyName ? data.companyName.replace(/\s+/g, '').length : 0;
        const locationLength = data.location ? data.location.replace(/[\s,]+/g, '').length : 0;
        const yearLength = data.year ? data.year.toString().length : 4;
        
        // Mask 1: Short pattern (4-6 chars) - uses common character knowledge
        masks.push({
            id: 'custom1',
            mask: '?l?l?l?l?d?d',
            description: '4 lowercase + 2 digits (Short password pattern) - Optimized with common letters',
            examples: ['pass12', 'user34', 'test56'],
            confidence: 0.65, // Higher with frequency knowledge
            pattern: 'short_pattern',
            customCharset: this.generateOptimizedCharset('common')
        });
        
        // Mask 2: Medium pattern (6-8 chars) - most common length
        masks.push({
            id: 'custom2',
            mask: '?l?l?l?l?l?l?d?d',
            description: '6 lowercase + 2 digits (Medium password pattern) - Uses common letter frequency',
            examples: ['password12', 'username34'],
            confidence: 0.70, // Higher confidence
            pattern: 'medium_pattern',
            customCharset: this.generateOptimizedCharset('common')
        });
        
        // Mask 3: Year-based pattern with optimized chars
        if (data.year) {
            masks.push({
                id: 'custom3',
                mask: '?l?l?l?l?l?d?d?d?d',
                description: '5 lowercase + 4 digits (Word + Year pattern) - Prioritizes common letters (e,t,a,o,i)',
                examples: [`${data.companyName?.toLowerCase().replace(/\s+/g, '').substring(0,5) || 'company'}${data.year}`],
                confidence: 0.75,
                pattern: 'year_pattern',
                customCharset: this.generateOptimizedCharset('common')
            });
        }
        
        // Mask 4: Mixed case pattern - 40% of passwords start with uppercase
        masks.push({
            id: 'custom4',
            mask: '?u?l?l?l?l?l?d?d?d',
            description: 'Capitalized word + 3 digits (40% uppercase first letter pattern)',
            examples: ['Company123', 'Location456'],
            confidence: 0.72, // Higher with pattern knowledge
            pattern: 'mixed_case'
        });
        
        // Mask 5: With special characters (15% of passwords)
        masks.push({
            id: 'custom5',
            mask: '?l?l?l?l?l?l?d?d?d?d?s',
            description: '6 lowercase + 4 digits + 1 special char (15% pattern frequency)',
            examples: ['password2024!', 'username2023@'],
            confidence: 0.68,
            pattern: 'with_special'
        });
        
        // Mask 6: Optimized with most common characters
        // Uses knowledge: e(12.7%), t(9.1%), a(8.2%), o(7.5%), i(7.0%) are top 5
        masks.push({
            id: 'custom6',
            mask: '?1?1?1?1?1?1?1?d?d?d?d',
            description: '7 chars from most common letters (etaoinshrdlcu) + 4 digits - Highest success rate',
            examples: ['password2024', 'company2024'],
            confidence: 0.80, // Highest confidence with frequency optimization
            pattern: 'optimized_frequency',
            customCharset: this.generateOptimizedCharset('common')
        });
        
        // Mask 7: Common 8-char pattern (most common password length)
        masks.push({
            id: 'custom7',
            mask: '?l?l?l?l?l?l?l?l',
            description: '8 lowercase letters (most common password length - 8 chars)',
            examples: ['password', 'username'],
            confidence: 0.75,
            pattern: 'common_length_8'
        });
        
        // Mask 8: Vowel-consonant patterns (natural word patterns)
        masks.push({
            id: 'custom8',
            mask: '?l?l?l?l?l?l?d?d',
            description: '6 lowercase (vowel-consonant patterns) + 2 digits',
            examples: ['hello12', 'world34'],
            confidence: 0.70,
            pattern: 'vowel_consonant'
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
