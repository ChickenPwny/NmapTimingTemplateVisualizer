// Test the regex pattern directly
const testRule = `alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"ET-MALWARE C2 HTTP POST with File Upload"; flow:to_server,established; http.method; content:"POST"; http.uri; content:"/upload.php"; http.header; content:"User-Agent|3A| Mozilla/5.0"; http.content; content:"file=malicious.exe"; fast_pattern; urilen:2<>10; isdataat:!0,relative; pcre:"/malware\\.exe/i"; flowbits:set,attack_stage1; classtype:trojan-activity; reference:url,virustotal.com; sid:1000001; rev:3;)`;

console.log('Testing rule:', testRule);
console.log('Rule length:', testRule.length);

// Test the regex pattern
const rulePattern = /^(alert|log|pass|drop|reject|sdrop)\s+\w+\s+.*(->|<>).*\(.*\)$/;
console.log('Rule pattern test:', rulePattern.test(testRule));

// Test step by step
const actionMatch = testRule.match(/^(alert|log|pass|drop|reject|sdrop)/);
console.log('Action match:', actionMatch);

const protocolMatch = testRule.match(/^(alert|log|pass|drop|reject|sdrop)\s+(\w+)/);
console.log('Protocol match:', protocolMatch);

const directionMatch = testRule.match(/(->|<>)/);
console.log('Direction match:', directionMatch);

const optionsMatch = testRule.match(/\((.+)\)$/);
console.log('Options match:', optionsMatch);

// Test if the rule contains the expected elements
console.log('Contains alert:', testRule.includes('alert'));
console.log('Contains tcp:', testRule.includes('tcp'));
console.log('Contains ->:', testRule.includes('->'));
console.log('Contains (: ', testRule.includes('('));
console.log('Contains ): ', testRule.includes(')'));
