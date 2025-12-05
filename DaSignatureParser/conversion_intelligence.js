class ConversionIntelligence {
    constructor() {
        this.optimizationRules = {
            performance: this.optimizePerformance,
            accuracy: this.optimizeAccuracy,
            compatibility: this.optimizeCompatibility
        };
    }

    analyzeConversion(originalRule, convertedRule) {
        const analysis = {
            changes: this.identifyChanges(originalRule, convertedRule),
            optimizations: this.identifyOptimizations(originalRule, convertedRule),
            risks: this.identifyRisks(originalRule, convertedRule),
            recommendations: this.generateConversionRecommendations(originalRule, convertedRule)
        };

        return analysis;
    }

    identifyChanges(original, converted) {
        const changes = [];
        
        if (original.protocol !== converted.protocol) {
            changes.push({
                type: 'protocol',
                from: original.protocol,
                to: converted.protocol,
                impact: 'medium',
                description: `Protocol changed from ${original.protocol} to ${converted.protocol}`
            });
        }

        // Check for option changes
        const originalOptions = Object.keys(original.options);
        const convertedOptions = Object.keys(converted.options);
        
        const added = convertedOptions.filter(opt => !originalOptions.includes(opt));
        const removed = originalOptions.filter(opt => !convertedOptions.includes(opt));
        
        added.forEach(opt => {
            changes.push({
                type: 'option_added',
                option: opt,
                impact: 'low',
                description: `Added ${opt} option for target system compatibility`
            });
        });

        removed.forEach(opt => {
            changes.push({
                type: 'option_removed',
                option: opt,
                impact: 'medium',
                description: `Removed ${opt} option (not supported in target system)`
            });
        });

        return changes;
    }

    identifyOptimizations(original, converted) {
        const optimizations = [];
        
        // Check for performance optimizations
        if (converted.options.bsize && !original.options.bsize) {
            optimizations.push({
                type: 'performance',
                description: 'Added bsize optimization for better performance',
                benefit: 'Reduces search space and improves matching speed'
            });
        }

        // Check for accuracy improvements
        if (converted.options.http_user_agent && original.options.http_header) {
            optimizations.push({
                type: 'accuracy',
                description: 'Converted generic http.header to specific http.user_agent',
                benefit: 'More precise matching and reduced false positives'
            });
        }

        return optimizations;
    }

    identifyRisks(original, converted) {
        const risks = [];
        
        // Check for potential functionality loss
        if (original.options.fast_pattern && !converted.options.fast_pattern) {
            risks.push({
                type: 'functionality',
                severity: 'medium',
                description: 'fast_pattern removed - may impact performance in high-traffic environments',
                mitigation: 'Monitor rule performance and consider alternative optimizations'
            });
        }

        // Check for behavioral differences
        if (original.options.urilen && converted.options.urilen) {
            risks.push({
                type: 'behavioral',
                severity: 'high',
                description: 'urilen range interpretation differs between systems',
                mitigation: 'Test rule behavior in target environment'
            });
        }

        return risks;
    }

    generateConversionRecommendations(original, converted) {
        const recommendations = [];
        
        // Performance recommendations
        if (converted.options.content && converted.options.content.length > 50) {
            recommendations.push({
                type: 'performance',
                priority: 'medium',
                message: 'Consider adding fast_pattern for long content strings',
                action: 'Add fast_pattern to improve matching performance'
            });
        }

        // Best practice recommendations
        if (!converted.options.reference && original.options.msg && 
            original.options.msg.toLowerCase().includes('malware')) {
            recommendations.push({
                type: 'best_practice',
                priority: 'low',
                message: 'Consider adding reference URL for malware rule',
                action: 'Add reference:url,virustotal.com; for additional context'
            });
        }

        return recommendations;
    }
}
