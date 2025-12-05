class SIEMRuleParser {
    constructor() {
        this.snortPatterns = {
            // Snort-specific options
            flow: /flow:\s*([^;]+)/gi,
            flowbits: /flowbits:\s*([^;]+)/gi,
            fast_pattern: /fast_pattern/gi,
            openappid: /appid:\s*([^;]+)/gi,
            metadata: /metadata:\s*([^;]+)/gi,
            reference: /reference:\s*([^;]+)/gi,
            http_content: /http\.content/gi,
            http_method: /http\.method/gi,
            http_uri: /http\.uri/gi,
            http_header: /http\.header/gi,
            urilen: /urilen:\s*([^;]+)/gi,
            appid: /appid:\s*([^;]+)/gi,
            // Common options
            msg: /msg:\s*"([^"]+)"/gi,
            sid: /sid:\s*(\d+)/gi,
            rev: /rev:\s*(\d+)/gi,
            classtype: /classtype:\s*([^;]+)/gi,
            content: /content:\s*"([^"]+)"(?:\s*([^;]*))?/gi,
            pcre: /pcre:\s*"([^"]+)"/gi,
            nocase: /nocase/gi,
            isdataat: /isdataat:\s*([^;]+)/gi
        };

        this.suricataPatterns = {
            // Suricata-specific options
            http_uri: /http\.uri/gi,
            http_user_agent: /http\.user_agent/gi,
            http_cookie: /http\.cookie/gi,
            http_header: /http\.header/gi,
            http_request_body: /http\.request_body/gi,
            http_method: /http\.method/gi,
            tls_cert_subject: /tls\.cert_subject/gi,
            tls_fingerprint: /tls\.fingerprint/gi,
            tls_version: /tls\.version/gi,
            file_data: /file_data/gi,
            file_ext: /file_ext/gi,
            dns_query: /dns\.query/gi,
            bsize: /bsize:\s*(\d+)/gi,
            urilen: /urilen:\s*([^;]+)/gi,
            filestore: /filestore/gi,
            fileext: /fileext/gi,
            filemagic: /filemagic/gi,
            filemd5: /filemd5/gi,
            filesha1: /filesha1/gi,
            filesha256: /filesha256/gi,
            tls_subject: /tls\.subject/gi,
            tls_issuerdn: /tls\.issuerdn/gi,
            // Common options (same as Snort)
            msg: /msg:\s*"([^"]+)"/gi,
            sid: /sid:\s*(\d+)/gi,
            rev: /rev:\s*(\d+)/gi,
            classtype: /classtype:\s*([^;]+)/gi,
            content: /content:\s*"([^"]+)"(?:\s*([^;]*))?/gi,
            pcre: /pcre:\s*"([^"]+)"/gi,
            flow: /flow:\s*([^;]+)/gi,
            flowbits: /flowbits:\s*([^;]+)/gi,
            nocase: /nocase/gi,
            isdataat: /isdataat:\s*([^;]+)/gi
        };
    }

    detectRuleType(rules) {
        const lines = rules.split('\n').filter(line => line.trim());
        let snortScore = 0;
        let suricataScore = 0;

        for (const line of lines) {
            if (this.isValidRule(line)) {
                // Check for Snort-specific patterns
                if (line.includes('fast_pattern') || line.includes('openappid') || line.includes('appid:')) {
                    snortScore += 3;
                }
                if (line.includes('http.content') || line.includes('http.method')) {
                    snortScore += 2;
                }
                if (line.includes('metadata:') && !line.includes('http.') && !line.includes('tls.')) {
                    snortScore += 2;
                }
                // Check for Snort 3 specific features
                if (line.includes('urilen:') || line.includes('!0,relative')) {
                    snortScore += 1;
                }

                // Check for Suricata-specific patterns
                if (line.includes('http.request_body') || line.includes('http.user_agent') || line.includes('dns.query')) {
                    suricataScore += 3;
                }
                if (line.includes('bsize:') || line.includes('tls.') || line.includes('file_')) {
                    suricataScore += 2;
                }
                // Check for Suricata-specific advanced features
                if (line.includes('filestore') || line.includes('fileext') || line.includes('filemagic') || 
                    line.includes('filemd5') || line.includes('filesha1') || line.includes('filesha256')) {
                    suricataScore += 3;
                }
                if (line.includes('!1,relative') || line.includes('tls.subject') || line.includes('tls.issuerdn')) {
                    suricataScore += 1;
                }

                // Check protocol detection patterns
                if (line.match(/alert\s+(http|tls|dns|smtp|ftp)\s+/i)) {
                    suricataScore += 2;
                }
            }
        }

        if (snortScore > suricataScore) return 'snort';
        if (suricataScore > snortScore) return 'suricata';
        return 'unknown';
    }

    isValidRule(line) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) return false;
        
        // Basic rule structure check - more flexible to handle various formats
        // Allow for more complex source/destination patterns
        const rulePattern = /^(alert|log|pass|drop|reject|sdrop)\s+\w+\s+.*(->|<>).*\(.*\)$/;
        return rulePattern.test(trimmed);
    }

    parseRule(ruleLine) {
        const rule = {
            action: '',
            protocol: '',
            source: '',
            destination: '',
            direction: '',
            options: {},
            raw: ruleLine.trim()
        };

        // Extract action and protocol
        const headerMatch = ruleLine.match(/^(alert|log|pass|drop|reject|sdrop)\s+(\w+)\s+(.+)/);
        if (headerMatch) {
            rule.action = headerMatch[1];
            rule.protocol = headerMatch[2];
            
            const rest = headerMatch[3];
            const directionMatch = rest.match(/^(.+?)\s*(->|<>)\s*(.+?)\s*\((.+)\)$/);
            if (directionMatch) {
                rule.source = directionMatch[1].trim();
                rule.direction = directionMatch[2];
                rule.destination = directionMatch[3].trim();
                rule.options = this.parseOptions(directionMatch[4]);
            }
        }

        return rule;
    }

    parseOptions(optionsString) {
        const options = {};
        
        // Split by semicolon and process each option, but be careful with quoted content
        const optionParts = this.splitOptions(optionsString);
        
        for (const part of optionParts) {
            // Handle options with colons (key:value)
            if (part.includes(':')) {
                const colonIndex = part.indexOf(':');
                const key = part.substring(0, colonIndex).trim().toLowerCase();
                const value = part.substring(colonIndex + 1).trim();
                
                // Handle quoted values
                if (value.startsWith('"') && value.endsWith('"')) {
                    options[key] = value.slice(1, -1);
                } else {
                    options[key] = value;
                }
            } else {
                // Handle options without values (like fast_pattern, nocase)
                const key = part.trim().toLowerCase();
                if (key) {
                    options[key] = 'true';
                }
            }
        }

        return options;
    }

    splitOptions(optionsString) {
        const parts = [];
        let current = '';
        let inQuotes = false;
        let quoteChar = '';
        
        for (let i = 0; i < optionsString.length; i++) {
            const char = optionsString[i];
            
            if ((char === '"' || char === "'") && !inQuotes) {
                inQuotes = true;
                quoteChar = char;
                current += char;
            } else if (char === quoteChar && inQuotes) {
                inQuotes = false;
                quoteChar = '';
                current += char;
            } else if (char === ';' && !inQuotes) {
                if (current.trim()) {
                    parts.push(current.trim());
                }
                current = '';
            } else {
                current += char;
            }
        }
        
        if (current.trim()) {
            parts.push(current.trim());
        }
        
        return parts;
    }

    parseRules(rulesText) {
        const lines = rulesText.split('\n');
        const parsedRules = [];

        for (const line of lines) {
            if (this.isValidRule(line)) {
                parsedRules.push(this.parseRule(line));
            }
        }

        return parsedRules;
    }

    formatRule(rule) {
        const options = [];
        
        for (const [key, value] of Object.entries(rule.options)) {
            if (value === 'true') {
                // Options without values (like fast_pattern, nocase)
                options.push(key);
            } else if (typeof value === 'string' && (value.includes(' ') || value.includes('|'))) {
                // Values with spaces or special characters need quotes
                options.push(`${key}:"${value}"`);
            } else {
                // Simple values
                options.push(`${key}:${value}`);
            }
        }

        const optionsString = options.join('; ');
        return `${rule.action} ${rule.protocol} ${rule.source} ${rule.direction} ${rule.destination} (${optionsString};)`;
    }
}
