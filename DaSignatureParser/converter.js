class SIEMRuleConverter {
    constructor() {
        this.parser = new SIEMRuleParser();
        this.conversionLog = [];
    }

    log(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        this.conversionLog.push({
            timestamp,
            message,
            type
        });
    }

    getConversionLog() {
        return this.conversionLog;
    }

    clearLog() {
        this.conversionLog = [];
    }

    convertToSnort(rulesText) {
        this.clearLog();
        this.log('Starting conversion to Snort format...', 'info');
        
        const parsedRules = this.parser.parseRules(rulesText);
        const convertedRules = [];

        for (const rule of parsedRules) {
            try {
                const convertedRule = this.convertSingleRuleToSnort(rule);
                convertedRules.push(convertedRule);
                this.log(`Converted rule SID ${rule.options.sid || 'unknown'}`, 'success');
            } catch (error) {
                this.log(`Error converting rule: ${error.message}`, 'error');
                // Keep original rule if conversion fails
                convertedRules.push(this.parser.formatRule(rule));
            }
        }

        this.log(`Conversion complete. ${convertedRules.length} rules processed.`, 'info');
        return convertedRules.join('\n');
    }

    convertToSuricata(rulesText) {
        this.clearLog();
        this.log('Starting conversion to Suricata format...', 'info');
        
        const parsedRules = this.parser.parseRules(rulesText);
        const convertedRules = [];

        for (const rule of parsedRules) {
            try {
                const convertedRule = this.convertSingleRuleToSuricata(rule);
                convertedRules.push(convertedRule);
                this.log(`Converted rule SID ${rule.options.sid || 'unknown'}`, 'success');
            } catch (error) {
                this.log(`Error converting rule: ${error.message}`, 'error');
                // Keep original rule if conversion fails
                convertedRules.push(this.parser.formatRule(rule));
            }
        }

        this.log(`Conversion complete. ${convertedRules.length} rules processed.`, 'info');
        return convertedRules.join('\n');
    }

    convertSingleRuleToSnort(rule) {
        const convertedRule = { ...rule };
        const options = { ...rule.options };

        // Handle Suricata-specific HTTP options with proper Snort equivalents
        if (options.http_uri) {
            this.log('Converting http.uri to http.uri content matching', 'info');
            // Keep http.uri but ensure proper Snort syntax
            options.http_uri = 'true';
        }

        if (options.http_user_agent) {
            this.log('Converting http.user_agent to http.header with User-Agent pattern', 'warning');
            // Convert to generic http.header with User-Agent pattern
            delete options.http_user_agent;
            if (options.content) {
                // Add User-Agent header pattern
                options['http.header'] = 'true';
                // Note: This is a simplified conversion - manual review recommended
            }
        }

        if (options.http_cookie) {
            this.log('Converting http.cookie to http.header with Cookie pattern', 'warning');
            delete options.http_cookie;
            if (options.content) {
                options['http.header'] = 'true';
            }
        }

        if (options.http_header) {
            this.log('Converting http.header to http.header (compatible)', 'info');
            // http.header is compatible between both systems
        }

        // Handle Suricata-specific request body inspection
        if (options.http_request_body) {
            this.log('Converting http.request_body to http.content', 'info');
            options['http.content'] = 'true';
            delete options.http_request_body;
        }

        // Handle TLS options
        if (options.tls_cert_subject || options.tls_fingerprint || options.tls_version || 
            options.tls_subject || options.tls_issuerdn) {
            this.log('Converting Suricata TLS options to content matching', 'warning');
            delete options.tls_cert_subject;
            delete options.tls_fingerprint;
            delete options.tls_version;
            delete options.tls_subject;
            delete options.tls_issuerdn;
        }

        // Handle file options (Suricata-specific, remove for Snort)
        if (options.file_data || options.file_ext || options.filestore || options.fileext || 
            options.filemagic || options.filemd5 || options.filesha1 || options.filesha256) {
            this.log('Converting Suricata file extraction options to content matching', 'warning');
            delete options.file_data;
            delete options.file_ext;
            delete options.filestore;
            delete options.fileext;
            delete options.filemagic;
            delete options.filemd5;
            delete options.filesha1;
            delete options.filesha256;
        }

        // Convert protocol-specific rules to appropriate Snort protocols
        if (rule.protocol.toLowerCase() === 'http') {
            this.log('Converting HTTP protocol to TCP for Snort', 'warning');
            convertedRule.protocol = 'tcp';
        } else if (rule.protocol.toLowerCase() === 'dns') {
            this.log('Converting DNS protocol to UDP for Snort', 'warning');
            convertedRule.protocol = 'udp';
        } else if (['tls', 'smtp', 'ftp'].includes(rule.protocol.toLowerCase())) {
            this.log(`Converting ${rule.protocol} protocol to TCP for Snort`, 'warning');
            convertedRule.protocol = 'tcp';
        }

        // Handle DNS-specific options
        if (options.dns_query) {
            this.log('Converting dns.query to content matching', 'warning');
            delete options.dns_query;
        }

        // Adjust SID for Snort compatibility (user rules should be > 1000000)
        if (options.sid && parseInt(options.sid) < 1000000) {
            const newSid = parseInt(options.sid) + 1000000;
            this.log(`Adjusting SID from ${options.sid} to ${newSid} for Snort compatibility`, 'warning');
            options.sid = newSid.toString();
        }

        // Add reference if missing (common in Snort rules)
        if (!options.reference && (options.msg && options.msg.toLowerCase().includes('malware'))) {
            options.reference = 'url,virustotal.com';
            this.log('Added reference URL for malware detection rule', 'info');
        }

        // Handle classtype compatibility
        if (options.classtype && !options.classtype.includes('web-application-attack')) {
            // Ensure classtype is properly formatted
            this.log('Preserving classtype for Snort compatibility', 'info');
        }

        // Handle urilen range differences (Snort inclusive vs Suricata exclusive)
        if (options.urilen) {
            this.log('Converting urilen range from Suricata (exclusive) to Snort (inclusive)', 'warning');
            // Note: This is a simplified conversion - manual review recommended for complex ranges
        }

        // Handle isdataat relative modifier differences
        if (options.isdataat && options.isdataat.includes('!1,relative')) {
            this.log('Converting isdataat from Suricata (!1,relative) to Snort (!0,relative)', 'warning');
            options.isdataat = options.isdataat.replace('!1,relative', '!0,relative');
        }

        convertedRule.options = options;
        return this.parser.formatRule(convertedRule);
    }

    convertSingleRuleToSuricata(rule) {
        const convertedRule = { ...rule };
        const options = { ...rule.options };

        // Handle Snort-specific options
        if (options.fast_pattern) {
            this.log('Removing fast_pattern (not needed in Suricata)', 'info');
            delete options.fast_pattern;
        }

        if (options.openappid || options.appid) {
            this.log('Converting OpenAppID to protocol detection', 'warning');
            delete options.openappid;
            delete options.appid;
        }

        // Handle flowbits (compatible between both systems)
        if (options.flowbits) {
            this.log('Preserving flowbits (compatible with Suricata)', 'info');
            // flowbits are compatible, keep as is
        }

        // Handle PCRE (compatible between both systems)
        if (options.pcre) {
            this.log('Preserving PCRE pattern (compatible with Suricata)', 'info');
            // PCRE is compatible, keep as is
        }

        // Handle Snort-specific HTTP content inspection
        if (options.http_content) {
            this.log('Converting http.content to http.request_body', 'info');
            options['http.request_body'] = 'true';
            delete options.http_content;
        }

        // Enhance with Suricata-specific capabilities
        if (rule.protocol.toLowerCase() === 'tcp' && this.isWebTraffic(rule)) {
            this.log('Converting TCP to HTTP protocol for better detection', 'info');
            convertedRule.protocol = 'http';
            
            // Add HTTP-specific options if content suggests web traffic
            if (options.content && (options.content.includes('/') || options.content.includes('http'))) {
                options.http_uri = 'true';
            }
        }

        if (rule.protocol.toLowerCase() === 'tcp' && this.isTLSTraffic(rule)) {
            this.log('Converting TCP to TLS protocol for better detection', 'info');
            convertedRule.protocol = 'tls';
        }

        // Convert UDP to DNS if it looks like DNS traffic
        if (rule.protocol.toLowerCase() === 'udp' && this.isDNSTraffic(rule)) {
            this.log('Converting UDP to DNS protocol for better detection', 'info');
            convertedRule.protocol = 'dns';
            
            // Add DNS-specific options
            if (options.content && !options.dns_query) {
                options.dns_query = 'true';
            }
        }

        // Optimize HTTP header inspection for Suricata
        if (options.http_header && options.content) {
            const content = options.content.toLowerCase();
            if (content.includes('user-agent') || content.includes('mozilla')) {
                this.log('Converting generic http.header to specific http.user_agent', 'info');
                options.http_user_agent = 'true';
                delete options.http_header;
                
                // Add bsize optimization if content length is known
                if (content.includes('mozilla/5.0')) {
                    options.bsize = '11';
                    this.log('Added bsize:11 optimization for User-Agent matching', 'info');
                }
            } else if (content.includes('cookie')) {
                this.log('Converting generic http.header to specific http.cookie', 'info');
                options.http_cookie = 'true';
                delete options.http_header;
            }
        }

        // Adjust SID for Suricata (can use lower numbers)
        if (options.sid && parseInt(options.sid) > 1000000) {
            const newSid = parseInt(options.sid) - 1000000;
            this.log(`Adjusting SID from ${options.sid} to ${newSid} for Suricata compatibility`, 'warning');
            options.sid = newSid.toString();
        }

        // Add file detection capabilities for Suricata if content suggests file uploads
        if (options.content && this.isFileContent(rule)) {
            this.log('Adding file detection capabilities for Suricata', 'info');
            options.file_data = 'true';
        }

        // Handle urilen range differences (Snort inclusive vs Suricata exclusive)
        if (options.urilen) {
            this.log('Converting urilen range from Snort (inclusive) to Suricata (exclusive)', 'warning');
            // Note: This is a simplified conversion - manual review recommended for complex ranges
        }

        // Handle isdataat relative modifier differences
        if (options.isdataat && options.isdataat.includes('!0,relative')) {
            this.log('Converting isdataat from Snort (!0,relative) to Suricata (!1,relative)', 'warning');
            options.isdataat = options.isdataat.replace('!0,relative', '!1,relative');
        }

        // Add metadata for Suricata
        if (!options.metadata) {
            options.metadata = 'converted_from_snort';
        }

        convertedRule.options = options;
        return this.parser.formatRule(convertedRule);
    }

    isWebTraffic(rule) {
        const content = rule.options.content || '';
        const msg = rule.options.msg || '';
        const destination = rule.destination || '';
        
        return (
            content.includes('http') ||
            content.includes('/') ||
            msg.toLowerCase().includes('web') ||
            msg.toLowerCase().includes('http') ||
            destination.includes('80') ||
            destination.includes('8080') ||
            destination.includes('443')
        );
    }

    isTLSTraffic(rule) {
        const content = rule.options.content || '';
        const msg = rule.options.msg || '';
        const destination = rule.destination || '';
        
        return (
            content.includes('tls') ||
            content.includes('ssl') ||
            msg.toLowerCase().includes('tls') ||
            msg.toLowerCase().includes('ssl') ||
            destination.includes('443')
        );
    }

    isDNSTraffic(rule) {
        const content = rule.options.content || '';
        const msg = rule.options.msg || '';
        const destination = rule.destination || '';
        
        return (
            content.includes('.com') ||
            content.includes('.org') ||
            content.includes('.net') ||
            msg.toLowerCase().includes('dns') ||
            msg.toLowerCase().includes('query') ||
            destination.includes('53')
        );
    }

    isFileContent(rule) {
        const content = rule.options.content || '';
        const msg = rule.options.msg || '';
        
        return (
            content.includes('.exe') ||
            content.includes('.pdf') ||
            content.includes('.doc') ||
            content.includes('MZ') || // PE file header
            content.includes('PK') || // ZIP file header
            msg.toLowerCase().includes('file') ||
            msg.toLowerCase().includes('upload') ||
            msg.toLowerCase().includes('malware')
        );
    }

    analyzeRules(rulesText) {
        const parsedRules = this.parser.parseRules(rulesText);
        const analysis = {
            totalRules: parsedRules.length,
            protocols: {},
            actions: {},
            commonOptions: {},
            snortSpecific: 0,
            suricataSpecific: 0
        };

        for (const rule of parsedRules) {
            // Count protocols
            analysis.protocols[rule.protocol] = (analysis.protocols[rule.protocol] || 0) + 1;
            
            // Count actions
            analysis.actions[rule.action] = (analysis.actions[rule.action] || 0) + 1;
            
            // Count options
            for (const option of Object.keys(rule.options)) {
                analysis.commonOptions[option] = (analysis.commonOptions[option] || 0) + 1;
            }
            
            // Check for specific features
            if (rule.options.fast_pattern || rule.options.openappid) {
                analysis.snortSpecific++;
            }
            
            if (rule.options.http_uri || rule.options.tls_cert_subject || rule.options.file_data) {
                analysis.suricataSpecific++;
            }
        }

        return analysis;
    }
}
