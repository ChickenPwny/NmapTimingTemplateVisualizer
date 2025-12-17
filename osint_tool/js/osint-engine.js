/**
 * OSINT Data Collection Engine
 * Queries multiple free OSINT sources and aggregates results
 * Includes SpiderFoot free API sources
 */

class OSINTEngine {
    constructor() {
        this.results = {
            domain: null,
            companyName: null,
            whois: [],
            dns: [],
            subdomains: [],
            certificates: [],
            socialMedia: [],
            dataBreaches: [],
            darkWeb: [],
            repositories: [],
            ipAddresses: [],
            shodan: [],
            virustotal: [],
            emails: [],
            metadata: [],
            spiderfootSources: [],
            urlscan: [],
            threatCrowd: [],
            bgpInfo: [],
            cohosted: [],
            technologies: [],
            webAnalytics: []
        };
        this.spiderfootSources = null;
    }

    async loadSpiderFootSources() {
        if (this.spiderfootSources) {
            return this.spiderfootSources;
        }

        try {
            const response = await fetch('js/spiderfoot-sources.json');
            if (response.ok) {
                this.spiderfootSources = await response.json();
                return this.spiderfootSources;
            }
        } catch (error) {
            console.warn('Could not load SpiderFoot sources:', error);
        }
        return [];
    }

    categorizeSpiderFootSource(source) {
        const name = source.name.toLowerCase();
        const summary = source.summary.toLowerCase();
        const desc = source.description.toLowerCase();

        if (name.includes('dark') || name.includes('torch') || name.includes('onion') || name.includes('ahmia')) {
            return 'darkWeb';
        }
        if (name.includes('breach') || name.includes('pwned') || name.includes('leak') || name.includes('dehashed')) {
            return 'dataBreaches';
        }
        if (name.includes('dns') || name.includes('subdomain') || name.includes('domain')) {
            return 'subdomains';
        }
        if (name.includes('whois') || name.includes('whois')) {
            return 'whois';
        }
        if (name.includes('certificate') || name.includes('ssl') || name.includes('tls') || name.includes('crt')) {
            return 'certificates';
        }
        if (name.includes('ip') || name.includes('address') || name.includes('netblock')) {
            return 'ipAddresses';
        }
        if (name.includes('email') || name.includes('mail')) {
            return 'emails';
        }
        if (name.includes('social') || name.includes('twitter') || name.includes('github') || name.includes('linkedin')) {
            return 'socialMedia';
        }
        if (name.includes('malicious') || name.includes('threat') || name.includes('abuse') || name.includes('blacklist')) {
            return 'ipAddresses'; // Threat intelligence
        }
        return 'metadata';
    }

    async collectAllData(companyName, apiKeys = {}) {
        this.results.companyName = companyName;
        this.results.domain = this.extractDomain(companyName);

        // Load SpiderFoot sources
        await this.loadSpiderFootSources();

        const tasks = [
            this.collectWhoisData(this.results.domain),
            this.collectDNSRecords(this.results.domain),
            this.collectSubdomains(this.results.domain),
            this.collectCertificateData(this.results.domain),
            this.collectSocialMedia(companyName),
            this.collectDataBreaches(companyName),
            this.collectDarkWebMentions(companyName),
            this.collectRepositories(companyName),
            this.collectIPAddresses(this.results.domain),
            this.collectURLScanData(this.results.domain),
            this.collectThreatCrowdData(this.results.domain),
            this.collectBGPInfo(this.results.domain),
            this.collectTechnologies(this.results.domain),
            this.collectSpiderFootSources(companyName, this.results.domain)
        ];

        if (apiKeys.shodan) {
            tasks.push(this.collectShodanData(this.results.domain, apiKeys.shodan));
        }

        if (apiKeys.virustotal) {
            tasks.push(this.collectVirusTotalData(this.results.domain, apiKeys.virustotal));
        }

        if (apiKeys.hunter) {
            tasks.push(this.collectEmailData(this.results.domain, apiKeys.hunter));
        }

        await Promise.allSettled(tasks);
        return this.results;
    }

    async collectSpiderFootSources(companyName, domain) {
        try {
            if (!this.spiderfootSources || this.spiderfootSources.length === 0) {
                return;
            }

            // Group sources by category (they already have category from JSON)
            const categorized = {};
            
            this.spiderfootSources.forEach(source => {
                const category = source.category || this.categorizeSpiderFootSource(source);
                
                if (!categorized[category]) {
                    categorized[category] = [];
                }

                // Generate query URL by replacing placeholder
                let queryUrl = source.query_url || source.website;
                if (queryUrl && queryUrl.includes('$$TARGET$$')) {
                    // Replace with domain for domain-based queries, company name for others
                    const target = category === 'socialMedia' || category === 'repositories' 
                        ? companyName 
                        : domain;
                    queryUrl = queryUrl.replace(/\$\$TARGET\$\$/g, encodeURIComponent(target));
                }

                categorized[category].push({
                    source: source.name,
                    summary: source.summary,
                    website: source.website,
                    link: queryUrl,
                    description: source.description || source.summary,
                    model: source.model,
                    module: source.module,
                    category: category
                });
            });

            // Add categorized sources to results
            Object.keys(categorized).forEach(category => {
                if (this.results[category]) {
                    this.results[category].push(...categorized[category]);
                } else {
                    // Store in spiderfootSources for new categories
                    if (!this.results.spiderfootSources) {
                        this.results.spiderfootSources = [];
                    }
                    this.results.spiderfootSources.push({
                        category: category,
                        sources: categorized[category]
                    });
                }
            });

        } catch (error) {
            console.error('SpiderFoot sources collection error:', error);
        }
    }

    extractDomain(input) {
        // Try to extract domain from input
        const domainRegex = /([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/;
        const match = input.match(domainRegex);
        return match ? match[0] : input.toLowerCase().replace(/\s+/g, '') + '.com';
    }

    async collectWhoisData(domain) {
        try {
            // Use free WHOIS API services
            const apis = [
                `https://api.whoisxmlapi.com/v1?apiKey=free&domainName=${domain}`,
                `https://whoisjson.com/api/v1/whois?domain=${domain}`
            ];

            for (const api of apis) {
                try {
                    const response = await fetch(api);
                    if (response.ok) {
                        const data = await response.json();
                        this.results.whois.push({
                            source: 'WHOIS API',
                            data: data,
                            link: `https://whois.com/whois/${domain}`
                        });
                        break;
                    }
                } catch (e) {
                    continue;
                }
            }

            // Always add manual lookup links
            this.results.whois.push({
                source: 'Manual Lookup',
                link: `https://whois.com/whois/${domain}`,
                description: `WHOIS data for ${domain}`
            });
        } catch (error) {
            console.error('WHOIS collection error:', error);
        }
    }

    async collectDNSRecords(domain) {
        try {
            let dataFetched = false;
            
            // Try to fetch actual DNS records using public DNS APIs
            const dnsApis = [
                {
                    name: 'Cloudflare DNS',
                    url: `https://cloudflare-dns.com/dns-query?name=${domain}&type=A`,
                    headers: { 'Accept': 'application/dns-json' }
                },
                {
                    name: 'Google DNS',
                    url: `https://dns.google/resolve?name=${domain}&type=A`
                }
            ];

            for (const api of dnsApis) {
                try {
                    const response = await fetch(api.url, { 
                        headers: api.headers || {},
                        method: 'GET'
                    });
                    if (response.ok) {
                        const data = await response.json();
                        if (data.Answer && data.Answer.length > 0) {
                            this.results.dns.push({
                                source: api.name,
                                type: 'A',
                                records: data.Answer.map(r => ({
                                    name: r.name,
                                    type: r.type,
                                    data: r.data,
                                    ttl: r.TTL
                                })),
                                link: `https://dnschecker.org/#A/${domain}`,
                                description: `A records for ${domain} - ${data.Answer.length} record(s) found`
                            });
                            dataFetched = true;
                            break;
                        }
                    }
                } catch (e) {
                    continue;
                }
            }

            // Only add link-based entries if we didn't fetch actual data, or add as supplementary
            if (!dataFetched) {
                // Add DNS type links for manual lookup only if no data was fetched
                const dnsTypes = ['AAAA', 'MX', 'TXT', 'NS', 'CNAME'];
                for (const type of dnsTypes) {
                    this.results.dns.push({
                        type: type,
                        link: `https://dnschecker.org/#${type}/${domain}`,
                        description: `${type} records for ${domain} (click to view)`
                    });
                }
            } else {
                // If we got A records, still add links for other record types as supplementary
                this.results.dns.push({
                    type: 'Additional Records',
                    link: `https://dnschecker.org/#MX/${domain}`,
                    description: `View MX, TXT, NS, and other DNS records for ${domain}`
                });
            }

            // Always add comprehensive DNS lookup as a supplementary tool
            this.results.dns.push({
                type: 'Complete DNS Analysis',
                link: `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${domain}`,
                description: `Comprehensive DNS analysis tool for ${domain}`
            });
        } catch (error) {
            console.error('DNS collection error:', error);
        }
    }

    async collectSubdomains(domain) {
        try {
            // Fetch actual subdomains from crt.sh (Certificate Transparency)
            try {
                const crtUrl = `https://crt.sh/?q=%.${domain}&output=json`;
                const response = await fetch(crtUrl);
                if (response.ok) {
                    const certificates = await response.json();
                    const subdomains = new Set();
                    
                    certificates.forEach(cert => {
                        if (cert.name_value) {
                            const names = cert.name_value.split('\n');
                            names.forEach(name => {
                                const cleanName = name.trim().toLowerCase();
                                if (cleanName.endsWith(`.${domain}`) || cleanName === domain) {
                                    subdomains.add(cleanName);
                                }
                            });
                        }
                    });

                    if (subdomains.size > 0) {
                        this.results.subdomains.push({
                            source: 'Crt.sh (Certificate Transparency)',
                            subdomains: Array.from(subdomains).sort(),
                            count: subdomains.size,
                            link: `https://crt.sh/?q=%.${domain}`,
                            description: `Found ${subdomains.size} subdomains from certificate transparency logs`
                        });
                    }
                }
            } catch (e) {
                console.warn('Crt.sh fetch failed:', e);
            }

            // Add other subdomain enumeration services as supplementary (only if we got data, otherwise as primary)
            if (subdomains.size === 0) {
                // No data fetched, add as primary sources
                this.results.subdomains.push(
                    {
                        name: 'DNSdumpster',
                        link: `https://dnsdumpster.com/`,
                        description: `Subdomain enumeration for ${domain} (requires manual search)`
                    },
                    {
                        name: 'SecurityTrails',
                        link: `https://securitytrails.com/domain/${domain}/subdomains`,
                        description: `Historical subdomain data for ${domain}`
                    },
                    {
                        name: 'VirusTotal',
                        link: `https://www.virustotal.com/gui/domain/${domain}/relations`,
                        description: `Subdomain relations for ${domain}`
                    }
                );
            } else {
                // Data fetched, add as supplementary tools
                this.results.subdomains.push({
                    name: 'Additional Subdomain Sources',
                    link: `https://dnsdumpster.com/`,
                    description: `Additional subdomain enumeration tools for ${domain}`
                });
            }
        } catch (error) {
            console.error('Subdomain collection error:', error);
        }
    }

    async collectCertificateData(domain) {
        try {
            // Fetch actual certificate data from crt.sh
            try {
                const crtUrl = `https://crt.sh/?q=${domain}&output=json`;
                const response = await fetch(crtUrl);
                if (response.ok) {
                    const certificates = await response.json();
                    
                    if (certificates && certificates.length > 0) {
                        // Group by issuer and get unique certificates
                        const uniqueCerts = new Map();
                        certificates.forEach(cert => {
                            const key = `${cert.issuer_name}-${cert.name_value}`;
                            if (!uniqueCerts.has(key)) {
                                uniqueCerts.set(key, cert);
                            }
                        });

                        this.results.certificates.push({
                            source: 'Crt.sh (Certificate Transparency)',
                            certificates: Array.from(uniqueCerts.values()).slice(0, 20), // Limit to 20
                            total: certificates.length,
                            link: `https://crt.sh/?q=${domain}`,
                            description: `Found ${certificates.length} SSL/TLS certificates for ${domain}`
                        });
                    }
                }
            } catch (e) {
                console.warn('Crt.sh certificate fetch failed:', e);
            }

            // Add other certificate sources
            this.results.certificates.push({
                source: 'Certificate Search (Censys)',
                link: `https://censys.io/search?q=${domain}`,
                description: `Certificate transparency and SSL data`
            });
        } catch (error) {
            console.error('Certificate collection error:', error);
        }
    }

    async collectSocialMedia(companyName) {
        try {
            const platforms = [
                { name: 'LinkedIn', link: `https://www.linkedin.com/search/results/companies/?keywords=${encodeURIComponent(companyName)}` },
                { name: 'Twitter/X', link: `https://twitter.com/search?q=${encodeURIComponent(companyName)}` },
                { name: 'Facebook', link: `https://www.facebook.com/search/top/?q=${encodeURIComponent(companyName)}` },
                { name: 'Instagram', link: `https://www.instagram.com/explore/tags/${encodeURIComponent(companyName.replace(/\s+/g, ''))}/` },
                { name: 'GitHub', link: `https://github.com/search?q=${encodeURIComponent(companyName)}&type=users` },
                { name: 'Reddit', link: `https://www.reddit.com/search/?q=${encodeURIComponent(companyName)}` }
            ];

            this.results.socialMedia = platforms.map(p => ({
                platform: p.name,
                link: p.link,
                description: `Search ${p.name} for ${companyName}`
            }));
        } catch (error) {
            console.error('Social media collection error:', error);
        }
    }

    async collectDataBreaches(companyName) {
        try {
            this.results.dataBreaches = [
                {
                    source: 'Have I Been Pwned',
                    link: `https://haveibeenpwned.com/`,
                    description: `Check if ${companyName} email domains have been breached`
                },
                {
                    source: 'DeHashed',
                    link: `https://dehashed.com/search?query=${encodeURIComponent(companyName)}`,
                    description: `Search for breached credentials related to ${companyName}`
                },
                {
                    source: 'BreachDirectory',
                    link: `https://breachdirectory.tk/`,
                    description: `Check breach databases for ${companyName}`
                }
            ];
        } catch (error) {
            console.error('Data breach collection error:', error);
        }
    }

    async collectDarkWebMentions(companyName) {
        try {
            // Dark web OSINT sources and search methods
            this.results.darkWeb = [
                {
                    source: 'Ahmia Dark Web Search',
                    link: `https://ahmia.fi/search/?q=${encodeURIComponent(companyName)}`,
                    description: `Search dark web for mentions of ${companyName}`,
                    note: 'Requires Tor browser'
                },
                {
                    source: 'Torch Search Engine',
                    link: `http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/search?query=${encodeURIComponent(companyName)}`,
                    description: `Torch dark web search (Tor required)`,
                    note: 'Onion link - requires Tor browser'
                },
                {
                    source: 'NotEvil Dark Web Search',
                    link: `http://hss3uro2hsxfogfq.onion/search?q=${encodeURIComponent(companyName)}`,
                    description: `NotEvil search engine (Tor required)`,
                    note: 'Onion link - requires Tor browser'
                },
                {
                    source: 'DarkSearch',
                    link: `https://darksearch.io/search?query=${encodeURIComponent(companyName)}`,
                    description: `Dark web search without Tor (limited results)`
                },
                {
                    source: 'Manual Dark Web Forums',
                    link: `https://github.com/fastfire/deepdarkCTI`,
                    description: `List of dark web CTI sources and forums to manually search`
                }
            ];
        } catch (error) {
            console.error('Dark web collection error:', error);
        }
    }

    async collectRepositories(companyName) {
        try {
            this.results.repositories = [
                {
                    platform: 'GitHub',
                    link: `https://github.com/search?q=${encodeURIComponent(companyName)}&type=repositories`,
                    description: `GitHub repositories mentioning ${companyName}`
                },
                {
                    platform: 'GitLab',
                    link: `https://gitlab.com/search?search=${encodeURIComponent(companyName)}`,
                    description: `GitLab projects related to ${companyName}`
                },
                {
                    platform: 'Bitbucket',
                    link: `https://bitbucket.org/repo/all?name=${encodeURIComponent(companyName)}`,
                    description: `Bitbucket repositories for ${companyName}`
                }
            ];
        } catch (error) {
            console.error('Repository collection error:', error);
        }
    }

    async collectIPAddresses(domain) {
        try {
            // First, resolve domain to IP
            try {
                // Use DNS to get IP
                const dnsResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
                    headers: { 'Accept': 'application/dns-json' }
                });
                
                if (dnsResponse.ok) {
                    const dnsData = await dnsResponse.json();
                    if (dnsData.Answer && dnsData.Answer.length > 0) {
                        const ip = dnsData.Answer[0].data;
                        
                        // Fetch IP information
                        try {
                            const ipInfoResponse = await fetch(`https://ipapi.co/${ip}/json/`);
                            if (ipInfoResponse.ok) {
                                const ipInfo = await ipInfoResponse.json();
                                this.results.ipAddresses.push({
                                    source: 'IP API (ipapi.co)',
                                    ip: ip,
                                    data: {
                                        city: ipInfo.city,
                                        region: ipInfo.region,
                                        country: ipInfo.country_name,
                                        isp: ipInfo.org,
                                        timezone: ipInfo.timezone,
                                        latitude: ipInfo.latitude,
                                        longitude: ipInfo.longitude
                                    },
                                    link: `https://ipinfo.io/${ip}`,
                                    description: `IP address information for ${domain} (${ip})`
                                });
                            }
                        } catch (e) {
                            console.warn('IP info fetch failed:', e);
                        }
                    }
                }
            } catch (e) {
                console.warn('DNS resolution failed:', e);
            }

            // Add other IP lookup sources as supplementary
            this.results.ipAddresses.push({
                source: 'Additional IP Intelligence',
                link: `https://www.abuseipdb.com/check/${domain}`,
                description: `Additional IP reputation and threat intelligence sources`
            });
        } catch (error) {
            console.error('IP collection error:', error);
        }
    }

    async collectShodanData(domain, apiKey) {
        try {
            // Shodan API integration
            const response = await fetch(`https://api.shodan.io/dns/domain/${domain}?key=${apiKey}`);
            if (response.ok) {
                const data = await response.json();
                this.results.shodan.push({
                    source: 'Shodan API',
                    data: data,
                    link: `https://www.shodan.io/search?query=hostname:${domain}`
                });
            }
        } catch (error) {
            console.error('Shodan collection error:', error);
            // Add manual link even if API fails
            this.results.shodan.push({
                source: 'Shodan Manual Search',
                link: `https://www.shodan.io/search?query=hostname:${domain}`,
                description: `Shodan search for ${domain}`
            });
        }
    }

    async collectVirusTotalData(domain, apiKey) {
        try {
            const response = await fetch(`https://www.virustotal.com/vtapi/v2/domain/report?apikey=${apiKey}&domain=${domain}`);
            if (response.ok) {
                const data = await response.json();
                this.results.virustotal.push({
                    source: 'VirusTotal API',
                    data: data,
                    link: `https://www.virustotal.com/gui/domain/${domain}`
                });
            }
        } catch (error) {
            console.error('VirusTotal collection error:', error);
            this.results.virustotal.push({
                source: 'VirusTotal Manual Search',
                link: `https://www.virustotal.com/gui/domain/${domain}`,
                description: `VirusTotal analysis for ${domain}`
            });
        }
    }

    async collectEmailData(domain, apiKey) {
        try {
            const response = await fetch(`https://api.hunter.io/v2/domain-search?domain=${domain}&api_key=${apiKey}`);
            if (response.ok) {
                const data = await response.json();
                this.results.emails = data.data?.emails || [];
            }
        } catch (error) {
            console.error('Email collection error:', error);
        }
    }

    async collectURLScanData(domain) {
        try {
            // URLScan.io API - search for domain
            const response = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${domain}`, {
                headers: { 'API-Key': '' } // Public API, no key needed
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data.results && data.results.length > 0) {
                    this.results.urlscan.push({
                        source: 'URLScan.io',
                        scans: data.results.slice(0, 10).map(result => ({
                            url: result.page?.url || result.task?.url,
                            title: result.page?.title,
                            screenshot: result.screenshot,
                            timestamp: result.task?.time,
                            uuid: result._id
                        })),
                        total: data.total,
                        link: `https://urlscan.io/search/#${encodeURIComponent(`domain:${domain}`)}`,
                        description: `Found ${data.total} URLScan.io scans for ${domain}`
                    });
                }
            }
        } catch (error) {
            console.error('URLScan collection error:', error);
        }
        
        // Always add URLScan link as supplementary tool
        if (this.results.urlscan.length === 0) {
            this.results.urlscan.push({
                source: 'URLScan.io',
                link: `https://urlscan.io/search/#${encodeURIComponent(`domain:${domain}`)}`,
                description: `Search URLScan.io for ${domain} scans`
            });
        }
    }

    async collectThreatCrowdData(domain) {
        try {
            // ThreatCrowd API - domain intelligence
            const response = await fetch(`https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${domain}`);
            
            if (response.ok) {
                const data = await response.json();
                if (data.response_code === '1') {
                    this.results.threatCrowd.push({
                        source: 'ThreatCrowd',
                        data: {
                            votes: data.votes,
                            references: data.references || [],
                            resolutions: data.resolutions?.slice(0, 20) || [],
                            hashes: data.hashes?.slice(0, 10) || [],
                            emails: data.emails || [],
                            subdomains: data.subdomains?.slice(0, 20) || []
                        },
                        link: `https://www.threatcrowd.org/domain.php?domain=${domain}`,
                        description: `Threat intelligence for ${domain}`
                    });
                }
            }
        } catch (error) {
            console.error('ThreatCrowd collection error:', error);
        }
        
        // Add ThreatCrowd link if no data was fetched
        if (this.results.threatCrowd.length === 0) {
            this.results.threatCrowd.push({
                source: 'ThreatCrowd',
                link: `https://www.threatcrowd.org/domain.php?domain=${domain}`,
                description: `Threat intelligence for ${domain}`
            });
        }
    }

    async collectBGPInfo(domain) {
        try {
            // First get IP, then get BGP info
            const dnsResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
                headers: { 'Accept': 'application/dns-json' }
            });
            
            if (dnsResponse.ok) {
                const dnsData = await dnsResponse.json();
                if (dnsData.Answer && dnsData.Answer.length > 0) {
                    const ip = dnsData.Answer[0].data;
                    
                    // Get IP info to find ASN
                    try {
                        const ipInfoResponse = await fetch(`https://ipapi.co/${ip}/json/`);
                        if (ipInfoResponse.ok) {
                            const ipInfo = await ipInfoResponse.json();
                            
                            if (ipInfo.org) {
                                // Extract ASN from org string (format: "AS12345 Organization")
                                const asnMatch = ipInfo.org.match(/AS(\d+)/);
                                if (asnMatch) {
                                    const asn = asnMatch[1];
                                    
                                    // Get BGP info from BGPView
                                    const bgpResponse = await fetch(`https://api.bgpview.io/asn/${asn}`);
                                    if (bgpResponse.ok) {
                                        const bgpData = await bgpResponse.json();
                                        if (bgpData.status === 'ok' && bgpData.data) {
                                            this.results.bgpInfo.push({
                                                source: 'BGPView',
                                                data: {
                                                    asn: `AS${asn}`,
                                                    name: bgpData.data.name,
                                                    description: bgpData.data.description_full || bgpData.data.description_short,
                                                    country: bgpData.data.country_code,
                                                    website: bgpData.data.website,
                                                    ipv4_prefixes: bgpData.data.ipv4_prefixes?.slice(0, 10) || [],
                                                    ipv6_prefixes: bgpData.data.ipv6_prefixes?.slice(0, 10) || []
                                                },
                                                link: `https://bgpview.io/asn/${asn}`,
                                                description: `BGP/ASN information for ${domain} (AS${asn})`
                                            });
                                        }
                                    }
                                }
                            }
                            
                            // Add IP-based BGP info
                            this.results.bgpInfo.push({
                                source: 'IP API',
                                data: {
                                    asn: ipInfo.org,
                                    network: ipInfo.network,
                                    org: ipInfo.org
                                },
                                link: `https://bgpview.io/ip/${ip}`,
                                description: `Network information for ${ip}`
                            });
                        }
                    } catch (e) {
                        console.warn('BGP info fetch failed:', e);
                    }
                }
            }
        } catch (error) {
            console.error('BGP info collection error:', error);
        }
    }

    async collectTechnologies(domain) {
        try {
            // Try to fetch the main page and detect technologies
            const url = domain.startsWith('http') ? domain : `https://${domain}`;
            
            try {
                const response = await fetch(url, { 
                    method: 'HEAD',
                    mode: 'no-cors' // May fail due to CORS, but we'll try
                });
                
                // Since we can't read headers due to CORS, we'll use Wappalyzer-like detection
                // by fetching the page content if possible
                const pageResponse = await fetch(url);
                if (pageResponse.ok) {
                    const html = await pageResponse.text();
                    const technologies = [];
                    
                    // Detect common technologies
                    if (html.includes('wp-content') || html.includes('wp-includes')) {
                        technologies.push({ name: 'WordPress', confidence: 'high' });
                    }
                    if (html.includes('jquery')) {
                        technologies.push({ name: 'jQuery', confidence: 'medium' });
                    }
                    if (html.includes('react') || html.includes('React')) {
                        technologies.push({ name: 'React', confidence: 'medium' });
                    }
                    if (html.includes('angular')) {
                        technologies.push({ name: 'Angular', confidence: 'medium' });
                    }
                    if (html.includes('bootstrap')) {
                        technologies.push({ name: 'Bootstrap', confidence: 'high' });
                    }
                    if (html.match(/google-analytics\.com|gtag|ga\(/i)) {
                        technologies.push({ name: 'Google Analytics', confidence: 'high' });
                    }
                    if (html.includes('cloudflare')) {
                        technologies.push({ name: 'Cloudflare', confidence: 'high' });
                    }
                    
                    if (technologies.length > 0) {
                        this.results.technologies.push({
                            source: 'Technology Detection',
                            technologies: technologies,
                            link: `https://builtwith.com/${domain}`,
                            description: `Detected ${technologies.length} technologies on ${domain}`
                        });
                    }
                }
            } catch (e) {
                // CORS or fetch failed, add link to BuiltWith
                console.warn('Technology detection failed (CORS):', e);
            }
            
            // Always add BuiltWith link
            this.results.technologies.push({
                source: 'BuiltWith',
                link: `https://builtwith.com/${domain}`,
                description: `Complete technology stack analysis for ${domain}`
            });
            
            // Add Wappalyzer link
            this.results.technologies.push({
                source: 'Wappalyzer',
                link: `https://www.wappalyzer.com/lookup/${domain}`,
                description: `Technology detection for ${domain}`
            });
        } catch (error) {
            console.error('Technology collection error:', error);
        }
    }
}

