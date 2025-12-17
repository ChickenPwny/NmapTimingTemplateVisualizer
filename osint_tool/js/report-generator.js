/**
 * Report Generator
 * Creates formatted HTML reports from OSINT data
 */

class ReportGenerator {
    constructor() {
        this.sections = [
            { key: 'whois', title: 'WHOIS Data', icon: '📋', badge: 'info' },
            { key: 'dns', title: 'DNS Records', icon: '🌐', badge: 'info' },
            { key: 'subdomains', title: 'Subdomain Discovery', icon: '🔍', badge: 'info' },
            { key: 'certificates', title: 'SSL/TLS Certificates', icon: '🔒', badge: 'info' },
            { key: 'ipAddresses', title: 'IP Address Information', icon: '📍', badge: 'info' },
            { key: 'socialMedia', title: 'Social Media Presence', icon: '📱', badge: 'info' },
            { key: 'repositories', title: 'Code Repositories', icon: '💻', badge: 'info' },
            { key: 'dataBreaches', title: 'Data Breach Checks', icon: '⚠️', badge: 'warning' },
            { key: 'darkWeb', title: 'Dark Web Intelligence', icon: '🌑', badge: 'danger', isDarkWeb: true },
            { key: 'threatIntelligence', title: 'Threat Intelligence', icon: '🛡️', badge: 'warning' },
            { key: 'searchEngines', title: 'Search Engines', icon: '🔎', badge: 'info' },
            { key: 'shodan', title: 'Shodan Intelligence', icon: '🛡️', badge: 'info' },
            { key: 'virustotal', title: 'VirusTotal Analysis', icon: '🦠', badge: 'warning' },
            { key: 'emails', title: 'Email Discovery', icon: '📧', badge: 'info' },
            { key: 'urlscan', title: 'URLScan.io Analysis', icon: '🔎', badge: 'info' },
            { key: 'threatCrowd', title: 'ThreatCrowd Intelligence', icon: '⚠️', badge: 'warning' },
            { key: 'bgpInfo', title: 'BGP/Network Information', icon: '🌐', badge: 'info' },
            { key: 'technologies', title: 'Technology Stack', icon: '⚙️', badge: 'info' },
            { key: 'spiderfootSources', title: 'Additional OSINT Sources', icon: '🕷️', badge: 'info' },
            { key: 'other', title: 'Other Sources', icon: '📦', badge: 'info' }
        ];
    }

    generateReport(data) {
        const container = document.getElementById('reportContent');
        container.innerHTML = '';

        // Add report metadata
        const metadata = this.createMetadataSection(data);
        container.appendChild(metadata);

        // Generate sections
        this.sections.forEach(section => {
            const sectionData = data[section.key];
            if (sectionData && sectionData.length > 0) {
                // Handle spiderfootSources special structure
                if (section.key === 'spiderfootSources') {
                    sectionData.forEach(categoryGroup => {
                        if (categoryGroup.sources && categoryGroup.sources.length > 0) {
                            const categorySection = {
                                ...section,
                                title: `${section.title} - ${categoryGroup.category}`,
                                key: categoryGroup.category
                            };
                            const sectionElement = this.createSection(categorySection, categoryGroup.sources);
                            container.appendChild(sectionElement);
                        }
                    });
                } else {
                    const sectionElement = this.createSection(section, sectionData);
                    container.appendChild(sectionElement);
                }
            }
        });

        // Add summary
        const summary = this.createSummary(data);
        container.appendChild(summary);
    }

    createMetadataSection(data) {
        const section = document.createElement('div');
        section.className = 'report-section';
        section.innerHTML = `
            <h3><span class="report-section-icon">📊</span>Report Metadata</h3>
            <div class="findings-list">
                <div class="finding-item">
                    <div class="finding-header">
                        <span class="finding-title">Target Company</span>
                    </div>
                    <div class="finding-description">${data.companyName || 'N/A'}</div>
                </div>
                <div class="finding-item">
                    <div class="finding-header">
                        <span class="finding-title">Primary Domain</span>
                    </div>
                    <div class="finding-description">${data.domain || 'N/A'}</div>
                </div>
                <div class="finding-item">
                    <div class="finding-header">
                        <span class="finding-title">Report Generated</span>
                    </div>
                    <div class="finding-description">${new Date().toLocaleString()}</div>
                </div>
            </div>
        `;
        return section;
    }

    createSection(sectionConfig, data) {
        const section = document.createElement('div');
        section.className = 'report-section' + (sectionConfig.isDarkWeb ? ' darkweb-section' : '');

        const title = document.createElement('h3');
        title.innerHTML = `<span class="report-section-icon">${sectionConfig.icon}</span>${sectionConfig.title}`;
        section.appendChild(title);

        const findingsList = document.createElement('ul');
        findingsList.className = 'findings-list';

        data.forEach(item => {
            const finding = this.createFinding(item, sectionConfig);
            findingsList.appendChild(finding);
        });

        section.appendChild(findingsList);
        return section;
    }

    createFinding(item, sectionConfig) {
        const li = document.createElement('li');
        li.className = 'finding-item';

        const header = document.createElement('div');
        header.className = 'finding-header';

        const title = document.createElement('span');
        title.className = 'finding-title';
        title.textContent = item.source || item.platform || item.type || item.name || 'Finding';

        const badge = document.createElement('span');
        badge.className = `finding-badge badge-${sectionConfig.badge}`;
        
        // Show data status badge
        if (item.records || item.subdomains || item.certificates || (item.ip && item.data)) {
            badge.textContent = 'DATA FETCHED';
            badge.className = 'finding-badge badge-success';
        } else if (item.link) {
            badge.textContent = 'LINK ONLY';
            badge.className = `finding-badge badge-${sectionConfig.badge}`;
        } else {
            badge.textContent = sectionConfig.badge.toUpperCase();
        }

        header.appendChild(title);
        header.appendChild(badge);
        li.appendChild(header);

        if (item.description || item.summary) {
            const desc = document.createElement('div');
            desc.className = 'finding-description';
            desc.textContent = item.description || item.summary || '';
            li.appendChild(desc);
        }

        // Display fetched data
        if (item.records && item.records.length > 0) {
            const dataDiv = document.createElement('div');
            dataDiv.className = 'finding-data';
            dataDiv.style.marginTop = '10px';
            dataDiv.style.padding = '10px';
            dataDiv.style.background = '#f0f0f0';
            dataDiv.style.borderRadius = '6px';
            
            const dataTitle = document.createElement('strong');
            dataTitle.textContent = 'DNS Records: ';
            dataDiv.appendChild(dataTitle);
            
            const recordsList = document.createElement('ul');
            recordsList.style.marginTop = '5px';
            recordsList.style.marginLeft = '20px';
            item.records.forEach(record => {
                const recordItem = document.createElement('li');
                recordItem.textContent = `${record.name} (${record.type}): ${record.data} [TTL: ${record.ttl}]`;
                recordsList.appendChild(recordItem);
            });
            dataDiv.appendChild(recordsList);
            li.appendChild(dataDiv);
        }

        // Display subdomains
        if (item.subdomains && item.subdomains.length > 0) {
            const subdomainsDiv = document.createElement('div');
            subdomainsDiv.className = 'finding-data';
            subdomainsDiv.style.marginTop = '10px';
            subdomainsDiv.style.padding = '10px';
            subdomainsDiv.style.background = '#e8f4f8';
            subdomainsDiv.style.borderRadius = '6px';
            
            const subTitle = document.createElement('strong');
            subTitle.textContent = `Found ${item.count || item.subdomains.length} Subdomains: `;
            subdomainsDiv.appendChild(subTitle);
            
            const subList = document.createElement('div');
            subList.style.marginTop = '5px';
            subList.style.display = 'flex';
            subList.style.flexWrap = 'wrap';
            subList.style.gap = '5px';
            
            item.subdomains.slice(0, 20).forEach(subdomain => {
                const subBadge = document.createElement('span');
                subBadge.style.padding = '4px 8px';
                subBadge.style.background = '#2a5298';
                subBadge.style.color = 'white';
                subBadge.style.borderRadius = '4px';
                subBadge.style.fontSize = '0.85em';
                subBadge.textContent = subdomain;
                subList.appendChild(subBadge);
            });
            
            if (item.subdomains.length > 20) {
                const moreBadge = document.createElement('span');
                moreBadge.style.padding = '4px 8px';
                moreBadge.style.background = '#6c757d';
                moreBadge.style.color = 'white';
                moreBadge.style.borderRadius = '4px';
                moreBadge.style.fontSize = '0.85em';
                moreBadge.textContent = `+${item.subdomains.length - 20} more`;
                subList.appendChild(moreBadge);
            }
            
            subdomainsDiv.appendChild(subList);
            li.appendChild(subdomainsDiv);
        }

        // Display IP address data
        if (item.ip && item.data) {
            const ipDiv = document.createElement('div');
            ipDiv.className = 'finding-data';
            ipDiv.style.marginTop = '10px';
            ipDiv.style.padding = '10px';
            ipDiv.style.background = '#f0f8f0';
            ipDiv.style.borderRadius = '6px';
            
            const ipInfo = document.createElement('div');
            ipInfo.innerHTML = `
                <strong>IP Address:</strong> ${item.ip}<br>
                ${item.data.city ? `<strong>Location:</strong> ${item.data.city}, ${item.data.region || ''}, ${item.data.country || ''}<br>` : ''}
                ${item.data.isp ? `<strong>ISP:</strong> ${item.data.isp}<br>` : ''}
                ${item.data.timezone ? `<strong>Timezone:</strong> ${item.data.timezone}<br>` : ''}
                ${item.data.latitude ? `<strong>Coordinates:</strong> ${item.data.latitude}, ${item.data.longitude}` : ''}
            `;
            ipDiv.appendChild(ipInfo);
            li.appendChild(ipDiv);
        }

        // Display URLScan data
        if (item.scans && item.scans.length > 0) {
            const scanDiv = document.createElement('div');
            scanDiv.className = 'finding-data';
            scanDiv.style.marginTop = '10px';
            scanDiv.style.padding = '10px';
            scanDiv.style.background = '#e3f2fd';
            scanDiv.style.borderRadius = '6px';
            
            const scanTitle = document.createElement('strong');
            scanTitle.textContent = `Found ${item.total || item.scans.length} URLScan.io Scans: `;
            scanDiv.appendChild(scanTitle);
            
            const scanList = document.createElement('ul');
            scanList.style.marginTop = '5px';
            scanList.style.marginLeft = '20px';
            
            item.scans.slice(0, 5).forEach(scan => {
                const scanItem = document.createElement('li');
                scanItem.style.marginBottom = '5px';
                scanItem.innerHTML = `
                    <strong>URL:</strong> <a href="${scan.url}" target="_blank">${scan.url}</a><br>
                    ${scan.title ? `<strong>Title:</strong> ${scan.title}<br>` : ''}
                    ${scan.timestamp ? `<strong>Scanned:</strong> ${new Date(scan.timestamp).toLocaleDateString()}<br>` : ''}
                    ${scan.uuid ? `<a href="https://urlscan.io/result/${scan.uuid}/" target="_blank">View Scan</a>` : ''}
                `;
                scanList.appendChild(scanItem);
            });
            
            if (item.scans.length > 5) {
                const moreItem = document.createElement('li');
                moreItem.style.fontStyle = 'italic';
                moreItem.textContent = `... and ${item.scans.length - 5} more scans`;
                scanList.appendChild(moreItem);
            }
            
            scanDiv.appendChild(scanList);
            li.appendChild(scanDiv);
        }

        // Display ThreatCrowd data
        if (item.data && item.data.subdomains) {
            const tcDiv = document.createElement('div');
            tcDiv.className = 'finding-data';
            tcDiv.style.marginTop = '10px';
            tcDiv.style.padding = '10px';
            tcDiv.style.background = '#fff3cd';
            tcDiv.style.borderRadius = '6px';
            
            const tcInfo = document.createElement('div');
            let tcContent = '';
            
            if (item.data.votes !== undefined) {
                tcContent += `<strong>Votes:</strong> ${item.data.votes}<br>`;
            }
            if (item.data.subdomains && item.data.subdomains.length > 0) {
                tcContent += `<strong>Subdomains:</strong> ${item.data.subdomains.length} found<br>`;
                const subList = document.createElement('ul');
                subList.style.marginLeft = '20px';
                item.data.subdomains.slice(0, 10).forEach(sub => {
                    const subItem = document.createElement('li');
                    subItem.textContent = sub;
                    subList.appendChild(subItem);
                });
                tcInfo.innerHTML = tcContent;
                tcInfo.appendChild(subList);
            }
            if (item.data.resolutions && item.data.resolutions.length > 0) {
                tcContent += `<strong>IP Resolutions:</strong> ${item.data.resolutions.length} found<br>`;
            }
            if (item.data.emails && item.data.emails.length > 0) {
                tcContent += `<strong>Related Emails:</strong> ${item.data.emails.length} found<br>`;
            }
            
            tcInfo.innerHTML = tcContent;
            tcDiv.appendChild(tcInfo);
            li.appendChild(tcDiv);
        }

        // Display BGP/ASN data
        if (item.data && item.data.asn) {
            const bgpDiv = document.createElement('div');
            bgpDiv.className = 'finding-data';
            bgpDiv.style.marginTop = '10px';
            bgpDiv.style.padding = '10px';
            bgpDiv.style.background = '#f0f8ff';
            bgpDiv.style.borderRadius = '6px';
            
            const bgpInfo = document.createElement('div');
            bgpInfo.innerHTML = `
                <strong>ASN:</strong> ${item.data.asn}<br>
                ${item.data.name ? `<strong>Name:</strong> ${item.data.name}<br>` : ''}
                ${item.data.description ? `<strong>Description:</strong> ${item.data.description}<br>` : ''}
                ${item.data.country ? `<strong>Country:</strong> ${item.data.country}<br>` : ''}
                ${item.data.website ? `<strong>Website:</strong> <a href="${item.data.website}" target="_blank">${item.data.website}</a><br>` : ''}
                ${item.data.ipv4_prefixes && item.data.ipv4_prefixes.length > 0 ? `<strong>IPv4 Prefixes:</strong> ${item.data.ipv4_prefixes.length} found<br>` : ''}
                ${item.data.network ? `<strong>Network:</strong> ${item.data.network}<br>` : ''}
            `;
            bgpDiv.appendChild(bgpInfo);
            li.appendChild(bgpDiv);
        }

        // Display technology stack
        if (item.technologies && item.technologies.length > 0) {
            const techDiv = document.createElement('div');
            techDiv.className = 'finding-data';
            techDiv.style.marginTop = '10px';
            techDiv.style.padding = '10px';
            techDiv.style.background = '#f5f5f5';
            techDiv.style.borderRadius = '6px';
            
            const techTitle = document.createElement('strong');
            techTitle.textContent = `Detected Technologies: `;
            techDiv.appendChild(techTitle);
            
            const techList = document.createElement('div');
            techList.style.marginTop = '5px';
            techList.style.display = 'flex';
            techList.style.flexWrap = 'wrap';
            techList.style.gap = '5px';
            
            item.technologies.forEach(tech => {
                const techBadge = document.createElement('span');
                techBadge.style.padding = '4px 8px';
                techBadge.style.background = tech.confidence === 'high' ? '#28a745' : '#ffc107';
                techBadge.style.color = 'white';
                techBadge.style.borderRadius = '4px';
                techBadge.style.fontSize = '0.85em';
                techBadge.textContent = tech.name;
                techBadge.title = `Confidence: ${tech.confidence}`;
                techList.appendChild(techBadge);
            });
            
            techDiv.appendChild(techList);
            li.appendChild(techDiv);
        }

        // Display certificate data
        if (item.certificates && item.certificates.length > 0) {
            const certDiv = document.createElement('div');
            certDiv.className = 'finding-data';
            certDiv.style.marginTop = '10px';
            certDiv.style.padding = '10px';
            certDiv.style.background = '#fff8e1';
            certDiv.style.borderRadius = '6px';
            
            const certTitle = document.createElement('strong');
            certTitle.textContent = `Found ${item.total || item.certificates.length} Certificates: `;
            certDiv.appendChild(certTitle);
            
            const certList = document.createElement('ul');
            certList.style.marginTop = '5px';
            certList.style.marginLeft = '20px';
            certList.style.maxHeight = '200px';
            certList.style.overflowY = 'auto';
            
            item.certificates.slice(0, 10).forEach(cert => {
                const certItem = document.createElement('li');
                certItem.style.marginBottom = '5px';
                certItem.innerHTML = `
                    <strong>Issuer:</strong> ${cert.issuer_name || 'Unknown'}<br>
                    <strong>Domain:</strong> ${cert.name_value || cert.common_name || 'N/A'}<br>
                    ${cert.not_before ? `<strong>Valid From:</strong> ${cert.not_before}<br>` : ''}
                    ${cert.not_after ? `<strong>Valid Until:</strong> ${cert.not_after}` : ''}
                `;
                certList.appendChild(certItem);
            });
            
            if (item.certificates.length > 10) {
                const moreItem = document.createElement('li');
                moreItem.style.fontStyle = 'italic';
                moreItem.textContent = `... and ${item.certificates.length - 10} more certificates`;
                certList.appendChild(moreItem);
            }
            
            certDiv.appendChild(certList);
            li.appendChild(certDiv);
        }

        if (item.note) {
            const note = document.createElement('div');
            note.className = 'finding-description';
            note.style.fontStyle = 'italic';
            note.style.color = sectionConfig.isDarkWeb ? 'rgba(255,255,255,0.8)' : '#999';
            note.textContent = `Note: ${item.note}`;
            li.appendChild(note);
        }

        const linksDiv = document.createElement('div');
        linksDiv.className = 'finding-links';

        // Primary query link (with target pre-filled)
        if (item.link) {
            const link = document.createElement('a');
            link.href = item.link;
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
            link.className = 'finding-link';
            link.textContent = '🔗 Query Source';
            link.title = `Open ${item.source || 'source'} with target query`;
            linksDiv.appendChild(link);
        }

        // Website link (if different from query link)
        if (item.website && item.website !== item.link) {
            const websiteLink = document.createElement('a');
            websiteLink.href = item.website;
            websiteLink.target = '_blank';
            websiteLink.rel = 'noopener noreferrer';
            websiteLink.className = 'finding-link';
            websiteLink.style.background = '#6c757d';
            websiteLink.textContent = '🌐 Visit Website';
            websiteLink.title = 'Visit source website';
            linksDiv.appendChild(websiteLink);
        }

        // Add additional links based on item type
        if (item.data && !item.ip) {
            const dataLink = document.createElement('a');
            dataLink.href = '#';
            dataLink.className = 'finding-link';
            dataLink.style.background = '#17a2b8';
            dataLink.textContent = '📊 View Raw Data';
            dataLink.onclick = (e) => {
                e.preventDefault();
                alert(JSON.stringify(item.data, null, 2));
            };
            linksDiv.appendChild(dataLink);
        }

        if (linksDiv.children.length > 0) {
            li.appendChild(linksDiv);
        }

        return li;
    }

    createSummary(data) {
        const section = document.createElement('div');
        section.className = 'report-section';
        
        let totalFindings = 0;
        let spiderfootCount = 0;
        let dataRichCount = 0;
        let linkOnlyCount = 0;
        
        // Helper to check if item has actual data
        const hasData = (item) => {
            return !!(item.records || item.subdomains || item.certificates || 
                     (item.ip && item.data) || item.scans || 
                     (item.data && item.data.subdomains) || 
                     (item.data && item.data.asn) || 
                     item.technologies);
        };
        
        this.sections.forEach(s => {
            if (data[s.key] && data[s.key].length > 0) {
                if (s.key === 'spiderfootSources') {
                    // Count SpiderFoot sources
                    data[s.key].forEach(catGroup => {
                        if (catGroup.sources) {
                            spiderfootCount += catGroup.sources.length;
                            totalFindings += catGroup.sources.length;
                        }
                    });
                } else {
                    data[s.key].forEach(item => {
                        totalFindings++;
                        if (hasData(item)) {
                            dataRichCount++;
                        } else {
                            linkOnlyCount++;
                        }
                    });
                }
            }
        });

        const categoriesCount = this.sections.filter(s => {
            if (s.key === 'spiderfootSources') {
                return data[s.key] && data[s.key].length > 0;
            }
            return data[s.key] && data[s.key].length > 0;
        }).length;

        const dataRichnessPercent = totalFindings > 0 ? Math.round((dataRichCount / totalFindings) * 100) : 0;

        section.innerHTML = `
            <h3><span class="report-section-icon">📈</span>Report Summary</h3>
            <div class="findings-list">
                <div class="finding-item">
                    <div class="finding-header">
                        <span class="finding-title">Total Data Sources</span>
                        <span class="finding-badge badge-success">${totalFindings}</span>
                    </div>
                    <div class="finding-description">
                        This report aggregated data from ${totalFindings} OSINT sources across multiple categories.
                    </div>
                </div>
                <div class="finding-item" style="border-left: 4px solid ${dataRichnessPercent >= 50 ? '#28a745' : dataRichnessPercent >= 25 ? '#ffc107' : '#dc3545'};">
                    <div class="finding-header">
                        <span class="finding-title">📊 Data Richness</span>
                        <span class="finding-badge badge-${dataRichnessPercent >= 50 ? 'success' : dataRichnessPercent >= 25 ? 'warning' : 'danger'}">${dataRichnessPercent}%</span>
                    </div>
                    <div class="finding-description">
                        <strong>${dataRichCount}</strong> sources with fetched data, <strong>${linkOnlyCount}</strong> link-only sources.
                        ${dataRichnessPercent >= 50 ? 'Excellent data coverage!' : dataRichnessPercent >= 25 ? 'Good data coverage with some links.' : 'Limited data - mostly links. Some APIs may require authentication or have CORS restrictions.'}
                    </div>
                </div>
                ${spiderfootCount > 0 ? `
                <div class="finding-item" style="border-left: 4px solid #9d4edd;">
                    <div class="finding-header">
                        <span class="finding-title">🕷️ SpiderFoot Sources</span>
                        <span class="finding-badge badge-info">${spiderfootCount}</span>
                    </div>
                    <div class="finding-description">
                        ${spiderfootCount} free OSINT sources integrated from <a href="https://github.com/smicallef/spiderfoot" target="_blank">SpiderFoot</a>, providing comprehensive intelligence gathering capabilities.
                    </div>
                </div>
                ` : ''}
                <div class="finding-item">
                    <div class="finding-header">
                        <span class="finding-title">Categories Analyzed</span>
                        <span class="finding-badge badge-info">${categoriesCount}</span>
                    </div>
                    <div class="finding-description">
                        Data collected from WHOIS, DNS, subdomains, certificates, social media, dark web, threat intelligence, and more.
                    </div>
                </div>
            </div>
        `;

        return section;
    }

    exportToJSON(data) {
        const json = JSON.stringify(data, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `osint-report-${data.domain || 'report'}-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    exportToPDF(data) {
        // Simple PDF export using window.print()
        // For better PDF generation, consider using jsPDF library
        window.print();
    }
}

