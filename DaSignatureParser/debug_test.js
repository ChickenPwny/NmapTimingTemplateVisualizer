// Debug test for SIEM rule parsing
const testRule = `alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"ET-MALWARE C2 HTTP POST with File Upload"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/upload.php"; http.header; content:"User-Agent|3A| Mozilla/5.0"; http.content; content:"file=malicious.exe"; fast_pattern; urilen:2<>10; isdataat:!0,relative; pcre:"/malware\\.exe/i"; flowbits:set,attack_stage1; classtype:trojan-activity; reference:url,virustotal.com; sid:1000001; rev:3;)`;

console.log('Testing rule:', testRule);

// Test the regex pattern
const rulePattern = /^(alert|log|pass|drop|reject|sdrop)\s+\w+\s+.*(->|<>).*\(.*\)$/;
console.log('Rule pattern test:', rulePattern.test(testRule));

// Test individual parts
const headerMatch = testRule.match(/^(alert|log|pass|drop|reject|sdrop)\s+(\w+)\s+(.+)/);
console.log('Header match:', headerMatch);

if (headerMatch) {
    const rest = headerMatch[3];
    console.log('Rest of rule:', rest);
    
    const directionMatch = rest.match(/^(.+?)\s*(->|<>)\s*(.+?)\s*\((.+)\)$/);
    console.log('Direction match:', directionMatch);
}

// Test the parser
const parser = new SIEMRuleParser();
console.log('Is valid rule:', parser.isValidRule(testRule));
console.log('Detected type:', parser.detectRuleType(testRule));

try {
    const parsed = parser.parseRules(testRule);
    console.log('Parsed rules:', parsed);
} catch (error) {
    console.error('Parse error:', error);
}
