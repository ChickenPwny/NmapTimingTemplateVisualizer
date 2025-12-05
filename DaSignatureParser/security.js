// Security utilities for da signature parser - SIEM Rule Specific
class SecurityUtils {
    static sanitizeInput(input) {
        if (typeof input !== 'string') return '';
        
        // For SIEM rules, we need to be much more conservative
        // Only remove truly dangerous patterns that could execute code
        return input
            .replace(/javascript:/gi, '') // Remove javascript: protocol
            .replace(/on\w+\s*=/gi, '') // Remove event handlers like onclick=
            .replace(/<script[^>]*>/gi, '') // Remove script opening tags
            .replace(/<\/script>/gi, '') // Remove script closing tags
            .replace(/<iframe[^>]*>/gi, '') // Remove iframe tags
            .replace(/<object[^>]*>/gi, '') // Remove object tags
            .replace(/<embed[^>]*>/gi, '') // Remove embed tags
            .replace(/eval\s*\(/gi, '') // Remove eval functions
            .replace(/expression\s*\(/gi, '') // Remove CSS expressions
            .replace(/import\s+/gi, '') // Remove import statements
            .replace(/require\s*\(/gi, ''); // Remove require statements
    }

    static sanitizeOutput(output) {
        if (typeof output !== 'string') return '';
        
        // For SIEM rules, we don't need to escape HTML entities
        // since we're displaying in textareas, not innerHTML
        return output;
    }

    static validateRuleContent(content) {
        // Check for truly malicious patterns that could execute code
        const dangerousPatterns = [
            /<script[^>]*>/i,
            /javascript:/i,
            /on\w+\s*=/i,
            /eval\s*\(/i,
            /expression\s*\(/i,
            /import\s+/i,
            /require\s*\(/i
        ];
        
        return !dangerousPatterns.some(pattern => pattern.test(content));
    }

    static sanitizeForDisplay(content) {
        // For displaying in textareas, we don't need to sanitize
        // since textareas display content as text, not HTML
        return content;
    }

    // SIEM-specific validation
    static validateSIEMRule(rule) {
        // Check if it looks like a valid SIEM rule
        const rulePattern = /^(alert|log|pass|drop|reject|sdrop)\s+\w+\s+.*(->|<>).*\(.*\)$/;
        return rulePattern.test(rule.trim());
    }

    // Check for suspicious content in rule messages
    static validateRuleMessage(message) {
        // Allow most content in rule messages, but flag truly dangerous patterns
        const suspiciousPatterns = [
            /<script/i,
            /javascript:/i,
            /on\w+\s*=/i
        ];
        
        return !suspiciousPatterns.some(pattern => pattern.test(message));
    }
}
