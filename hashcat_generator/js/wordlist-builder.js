/**
 * Wordlist Builder - Generates comprehensive wordlists from user inputs
 */

class WordlistBuilder {
    constructor() {
        this.seasons = ['winter', 'spring', 'summer', 'fall', 'autumn'];
        this.commonSeparators = ['', '-', '_', '.', '@'];
        this.commonSuffixes = ['123', '2024', '2023', '2022', '2021', '2020', '!', '@', '#', '1', '12', '1234'];
    }

    /**
     * Sanitize input to prevent XSS while allowing special characters for passwords
     * Removes potentially dangerous characters but keeps password-relevant special chars
     */
    sanitizeInput(input) {
        if (!input) return '';
        
        // Convert to string and trim
        let sanitized = String(input).trim();
        
        // Remove HTML tags and script content (XSS prevention)
        sanitized = sanitized.replace(/<[^>]*>/g, '');
        sanitized = sanitized.replace(/javascript:/gi, '');
        sanitized = sanitized.replace(/on\w+\s*=/gi, '');
        
        // Escape HTML entities
        const div = document.createElement('div');
        div.textContent = sanitized;
        sanitized = div.textContent || div.innerText || '';
        
        return sanitized;
    }

    /**
     * Parse location: remove spaces and commas
     * "Gwinnett County, Georgia" -> "gwinnettcountygeorgia"
     */
    parseLocation(location) {
        if (!location) return '';
        
        // Sanitize first
        let parsed = this.sanitizeInput(location);
        
        // Remove spaces and commas
        parsed = parsed.replace(/[\s,]+/g, '');
        
        return parsed;
    }

    /**
     * Parse location keeping parts separate (for variations)
     * "Gwinnett County, Georgia" -> ["gwinnett", "county", "georgia"]
     */
    parseLocationParts(location) {
        if (!location) return [];
        
        // Sanitize first
        let parsed = this.sanitizeInput(location);
        
        // Split by spaces and commas, filter empty, lowercase
        return parsed
            .split(/[\s,]+/)
            .filter(part => part.length > 0)
            .map(part => part.toLowerCase());
    }

    /**
     * Parse company name: remove spaces, handle special characters
     * "polito inc" -> "politoinc"
     */
    parseCompanyName(companyName) {
        if (!companyName) return '';
        
        // Sanitize first
        let parsed = this.sanitizeInput(companyName);
        
        // Remove spaces
        parsed = parsed.replace(/\s+/g, '');
        
        return parsed;
    }

    /**
     * Parse company name keeping parts separate (for variations)
     * "polito inc" -> ["polito", "inc"]
     */
    parseCompanyNameParts(companyName) {
        if (!companyName) return [];
        
        // Sanitize first
        let parsed = this.sanitizeInput(companyName);
        
        // Split by spaces, filter empty, lowercase
        return parsed
            .split(/\s+/)
            .filter(part => part.length > 0)
            .map(part => part.toLowerCase());
    }

    /**
     * Process uploaded file and return lines
     */
    async processFile(file) {
        return new Promise((resolve, reject) => {
            if (!file) {
                resolve([]);
                return;
            }

            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const text = e.target.result;
                    const lines = text.split('\n')
                        .map(line => line.trim())
                        .filter(line => line.length > 0);
                    resolve(lines);
                } catch (error) {
                    reject(error);
                }
            };
            reader.onerror = reject;
            reader.readAsText(file);
        });
    }

    /**
     * Generate variations of a word (assumes word is already parsed - no spaces, no commas)
     */
    generateVariations(word, options = {}) {
        if (!word) return [];
        
        const variations = new Set();
        const lower = word.toLowerCase();
        const upper = word.toUpperCase();
        const capitalized = word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
        
        variations.add(lower);
        variations.add(upper);
        variations.add(capitalized);
        
        // Add with numbers
        if (options.includeNumbers) {
            [options.year, '123', '1234', '1', '12'].forEach(num => {
                if (num) {
                    variations.add(lower + num);
                    variations.add(lower + num.toString());
                    variations.add(capitalized + num);
                }
            });
        }
        
        return Array.from(variations);
    }

    /**
     * Generate seasonal word combinations
     */
    generateSeasonalCombinations(year, companyName, location) {
        const combinations = new Set();
        
        // Parse inputs
        const company = companyName ? this.parseCompanyName(companyName).toLowerCase() : '';
        const loc = location ? this.parseLocation(location).toLowerCase() : '';
        
        this.seasons.forEach(season => {
            // Season + Year
            combinations.add(season + year);
            combinations.add(season + year.toString().slice(-2)); // Last 2 digits
            
            // Season + Company
            if (company) {
                combinations.add(season + company);
                combinations.add(company + season);
            }
            
            // Season + Location
            if (loc) {
                combinations.add(season + loc);
                combinations.add(loc + season);
            }
            
            // Season + Year + Company
            if (company && year) {
                combinations.add(season + year + company);
                combinations.add(company + season + year);
            }
        });
        
        return Array.from(combinations);
    }

    /**
     * Generate user-based combinations
     */
    generateUserCombinations(users, companyName, location, year) {
        const combinations = new Set();
        
        // Parse inputs
        const company = companyName ? this.parseCompanyName(companyName).toLowerCase() : '';
        const loc = location ? this.parseLocation(location).toLowerCase() : '';
        
        users.forEach(user => {
            // Sanitize user input
            const sanitizedUser = this.sanitizeInput(user);
            const userLower = sanitizedUser.toLowerCase();
            const userUpper = sanitizedUser.toUpperCase();
            const userCap = sanitizedUser.charAt(0).toUpperCase() + sanitizedUser.slice(1).toLowerCase();
            
            // User + Year
            if (year) {
                combinations.add(userLower + year);
                combinations.add(userLower + year.toString().slice(-2));
                combinations.add(userCap + year);
            }
            
            // User + Company
            if (company) {
                combinations.add(userLower + company);
                combinations.add(company + userLower);
                combinations.add(userCap + company);
            }
            
            // User + Location
            if (loc) {
                combinations.add(userLower + loc);
                combinations.add(loc + userLower);
            }
            
            // User + Company + Year
            if (company && year) {
                combinations.add(userLower + company + year);
                combinations.add(userCap + company + year);
            }
            
            // User + Common suffixes
            this.commonSuffixes.forEach(suffix => {
                combinations.add(userLower + suffix);
                combinations.add(userCap + suffix);
            });
        });
        
        return Array.from(combinations);
    }

    /**
     * Generate company name variations
     */
    generateCompanyVariations(companyName, year, location) {
        if (!companyName) return [];
        
        // Sanitize and parse
        const sanitized = this.sanitizeInput(companyName);
        const company = this.parseCompanyName(sanitized).toLowerCase();
        const companyParts = this.parseCompanyNameParts(sanitized);
        
        const variations = new Set();
        
        // Full company name variations (with spaces removed) - ONLY parsed version
        this.generateVariations(company, { includeNumbers: true, year }).forEach(v => variations.add(v));
        
        // Individual parts variations
        companyParts.forEach(part => {
            this.generateVariations(part, { includeNumbers: true, year }).forEach(v => variations.add(v));
        });
        
        // First word of company
        if (companyParts.length > 0) {
            this.generateVariations(companyParts[0], { includeNumbers: true, year }).forEach(v => variations.add(v));
        }
        
        // Company + Year
        if (year) {
            variations.add(company + year);
            variations.add(company + year.toString().slice(-2));
            if (companyParts.length > 0) {
                variations.add(companyParts[0] + year);
            }
        }
        
        // Company + Location
        if (location) {
            const loc = this.parseLocation(location).toLowerCase();
            variations.add(company + loc);
            variations.add(loc + company);
        }
        
        // Acronyms
        if (companyParts.length > 1) {
            const acronym = companyParts.map(p => p.charAt(0).toUpperCase()).join('');
            variations.add(acronym.toLowerCase());
            variations.add(acronym);
            if (year) {
                variations.add(acronym.toLowerCase() + year);
                variations.add(acronym + year);
            }
        }
        
        return Array.from(variations);
    }

    /**
     * Generate location variations
     */
    generateLocationVariations(location, year, companyName) {
        if (!location) return [];
        
        // Sanitize and parse
        const sanitized = this.sanitizeInput(location);
        const loc = this.parseLocation(sanitized).toLowerCase();
        const locParts = this.parseLocationParts(sanitized);
        
        const variations = new Set();
        
        // Full location variations (with spaces and commas removed) - ONLY parsed version
        this.generateVariations(loc, { includeNumbers: true, year }).forEach(v => variations.add(v));
        
        // Individual parts variations
        locParts.forEach(part => {
            this.generateVariations(part, { includeNumbers: true, year }).forEach(v => variations.add(v));
        });
        
        // Location + Year
        if (year) {
            variations.add(loc + year);
            variations.add(loc + year.toString().slice(-2));
            if (locParts.length > 0) {
                variations.add(locParts[0] + year);
            }
        }
        
        // Location + Company
        if (companyName) {
            const company = this.parseCompanyName(companyName).toLowerCase();
            variations.add(loc + company);
            variations.add(company + loc);
        }
        
        // City name only (first part)
        if (locParts.length > 0) {
            variations.add(locParts[0]);
            if (year) {
                variations.add(locParts[0] + year);
            }
        }
        
        return Array.from(variations);
    }

    /**
     * Build complete wordlist from all inputs
     */
    async buildWordlist(data) {
        const wordlist = new Set();
        
        // Process uploaded files
        let users = [];
        if (data.usersFile) {
            users = await this.processFile(data.usersFile);
        }
        
        let customWordlist = [];
        if (data.wordlistFile) {
            customWordlist = await this.processFile(data.wordlistFile);
            // Parse custom wordlist entries - remove spaces and commas
            customWordlist.forEach(word => {
                const sanitized = this.sanitizeInput(word);
                const parsed = sanitized.replace(/[\s,]+/g, '');
                if (parsed.length > 0) {
                    wordlist.add(parsed);
                }
            });
        }
        
        let customUsers = [];
        if (data.customFile) {
            customUsers = await this.processFile(data.customFile);
            users = [...users, ...customUsers];
        }
        
        // Add company variations
        if (data.includeCompanyVariations) {
            const companyVars = this.generateCompanyVariations(
                data.companyName,
                data.year,
                data.location
            );
            companyVars.forEach(word => wordlist.add(word));
        }
        
        // Add location variations
        if (data.includeLocationVariations) {
            const locationVars = this.generateLocationVariations(
                data.location,
                data.year,
                data.companyName
            );
            locationVars.forEach(word => wordlist.add(word));
        }
        
        // Add seasonal combinations
        if (data.includeSeasonal) {
            const seasonal = this.generateSeasonalCombinations(
                data.year,
                data.companyName,
                data.location
            );
            seasonal.forEach(word => wordlist.add(word));
        }
        
        // Add user-based combinations
        if (users.length > 0) {
            const userCombo = this.generateUserCombinations(
                users,
                data.companyName,
                data.location,
                data.year
            );
            userCombo.forEach(word => wordlist.add(word));
        }
        
        // Add direct inputs (ONLY parsed versions - no spaces, no commas)
        if (data.companyName) {
            const sanitized = this.sanitizeInput(data.companyName);
            const parsed = this.parseCompanyName(sanitized);
            const parts = this.parseCompanyNameParts(sanitized);
            
            // Add parsed (no spaces) - variations
            wordlist.add(parsed.toLowerCase());
            wordlist.add(parsed);
            wordlist.add(parsed.charAt(0).toUpperCase() + parsed.slice(1));
            wordlist.add(parsed.toUpperCase());
            
            // Add individual parts
            parts.forEach(part => {
                wordlist.add(part);
                wordlist.add(part.charAt(0).toUpperCase() + part.slice(1));
            });
        }
        
        if (data.location) {
            const sanitized = this.sanitizeInput(data.location);
            const parsed = this.parseLocation(sanitized);
            const parts = this.parseLocationParts(sanitized);
            
            // Add parsed (no spaces, no commas) - variations
            wordlist.add(parsed.toLowerCase());
            wordlist.add(parsed);
            wordlist.add(parsed.charAt(0).toUpperCase() + parsed.slice(1));
            wordlist.add(parsed.toUpperCase());
            
            // Add individual parts
            parts.forEach(part => {
                wordlist.add(part);
                wordlist.add(part.charAt(0).toUpperCase() + part.slice(1));
            });
        }
        
        // Add users (sanitized and parsed - no spaces)
        users.forEach(user => {
            const sanitized = this.sanitizeInput(user);
            const parsed = sanitized.replace(/\s+/g, '');
            if (parsed.length > 0) {
                wordlist.add(parsed);
                wordlist.add(parsed.toLowerCase());
                wordlist.add(parsed.charAt(0).toUpperCase() + parsed.slice(1).toLowerCase());
            }
        });
        
        // Convert to sorted array and filter out any entries with spaces or commas
        return Array.from(wordlist)
            .filter(word => {
                // Remove entries with spaces or commas
                if (!word || word.length === 0) return false;
                if (word.includes(' ') || word.includes(',')) return false;
                return true;
            })
            .sort((a, b) => {
                // Sort by length first, then alphabetically
                if (a.length !== b.length) {
                    return a.length - b.length;
                }
                return a.localeCompare(b);
            });
    }
}

// Export for use in other modules
window.WordlistBuilder = WordlistBuilder;
