/**
 * HashCat CLI Command Generator
 * Generates ready-to-use HashCat commands with maskprocessor integration
 */

class HashcatCLIGenerator {
    constructor() {
        this.hashTypes = {
            'md5': '0',
            'sha1': '100',
            'sha256': '1400',
            'sha512': '1700',
            'ntlm': '1000',
            'bcrypt': '3200',
            'md5crypt': '500',
            'sha512crypt': '1800'
        };
    }

    /**
     * Generate HashCat command with mask attack
     */
    generateMaskAttackCommand(mask, hashFile, options = {}) {
        const parts = ['hashcat'];
        
        // Hash type
        const hashType = options.hashType || '0'; // Default to MD5
        parts.push(`-m ${hashType}`);
        
        // Attack mode (mask attack = 3)
        parts.push('-a 3');
        
        // Hash file
        parts.push(`"${hashFile}"`);
        
        // Mask
        parts.push(`"${mask}"`);
        
        // Options
        if (options.customCharsets) {
            Object.entries(options.customCharsets).forEach(([num, charset], index) => {
                parts.push(`-${index + 1} "${charset}"`);
            });
        }
        
        // Increment
        if (options.increment) {
            parts.push(`-i`);
            if (options.increment.start && options.increment.stop) {
                parts.push(`--increment-min=${options.increment.start}`);
                parts.push(`--increment-max=${options.increment.stop}`);
            }
        }
        
        // Output file
        if (options.outputFile) {
            parts.push(`-o "${options.outputFile}"`);
        }
        
        // Restore file
        if (options.restoreFile) {
            parts.push(`--restore-file-path="${options.restoreFile}"`);
        }
        
        // Performance tuning
        if (options.workload) {
            parts.push(`-w ${options.workload}`); // 1-4, higher = more resources
        }
        
        // Rules
        if (options.rulesFile) {
            parts.push(`-r "${options.rulesFile}"`);
        }
        
        // Pot file
        if (options.potFile) {
            parts.push(`--potfile-path="${options.potFile}"`);
        }
        
        return parts.join(' ');
    }

    /**
     * Generate HashCat command with wordlist attack
     */
    generateWordlistAttackCommand(wordlistFile, hashFile, options = {}) {
        const parts = ['hashcat'];
        
        // Hash type
        const hashType = options.hashType || '0';
        parts.push(`-m ${hashType}`);
        
        // Attack mode (wordlist = 0)
        parts.push('-a 0');
        
        // Hash file
        parts.push(`"${hashFile}"`);
        
        // Wordlist file
        parts.push(`"${wordlistFile}"`);
        
        // Output file
        if (options.outputFile) {
            parts.push(`-o "${options.outputFile}"`);
        }
        
        // Rules
        if (options.rulesFile) {
            parts.push(`-r "${options.rulesFile}"`);
        }
        
        // Performance tuning
        if (options.workload) {
            parts.push(`-w ${options.workload}`);
        }
        
        return parts.join(' ');
    }

    /**
     * Generate maskprocessor command
     */
    generateMaskprocessorCommand(mask, options = {}) {
        const parts = ['mp64.bin'];
        
        // Custom charsets
        if (options.customCharsets) {
            Object.entries(options.customCharsets).forEach(([key, charset], index) => {
                const charsetNum = index + 1;
                parts.push(`-${charsetNum} "${charset}"`);
            });
        }
        
        // Increment mode
        if (options.increment) {
            parts.push(`-i ${options.increment.start}:${options.increment.stop}`);
        }
        
        // Start position
        if (options.startAt) {
            parts.push(`-s "${options.startAt}"`);
        }
        
        // Stop position
        if (options.stopAt) {
            parts.push(`-l "${options.stopAt}"`);
        }
        
        // Output file
        if (options.outputFile) {
            parts.push(`-o "${options.outputFile}"`);
        } else {
            // Default output to wordlist file
            const wordlistFile = options.wordlistFile || 'generated_wordlist.txt';
            parts.push(`-o "${wordlistFile}"`);
        }
        
        // The mask
        parts.push(`"${mask}"`);
        
        return parts.join(' ');
    }

    /**
     * Generate complete command set for user
     */
    generateCommandSet(data) {
        const commands = [];
        const hashFile = data.hashFile || 'hashes.txt';
        const wordlistFile = data.wordlistFile || 'generated_wordlist.txt';
        
        // Command 1: Generate wordlist using maskprocessor
        if (data.masks && data.masks.length > 0) {
            const primaryMask = data.masks[0].mask;
            commands.push({
                title: 'Generate Wordlist with Maskprocessor',
                description: 'Generate wordlist from the primary mask pattern',
                command: this.generateMaskprocessorCommand(primaryMask, {
                    outputFile: wordlistFile,
                    increment: data.increment || { start: 4, stop: 12 }
                }),
                category: 'maskprocessor'
            });
        }
        
        // Command 2: HashCat mask attack (direct)
        if (data.masks && data.masks.length > 0) {
            data.masks.slice(0, 3).forEach((maskData, index) => {
                commands.push({
                    title: `HashCat Mask Attack #${index + 1}: ${maskData.mask}`,
                    description: maskData.description,
                    command: this.generateMaskAttackCommand(maskData.mask, hashFile, {
                        hashType: data.hashType || '0',
                        outputFile: `cracked_${index + 1}.txt`,
                        workload: data.workload || 3
                    }),
                    category: 'hashcat_mask'
                });
            });
        }
        
        // Command 3: HashCat wordlist attack
        commands.push({
            title: 'HashCat Wordlist Attack',
            description: 'Crack hashes using the generated wordlist',
            command: this.generateWordlistAttackCommand(wordlistFile, hashFile, {
                hashType: data.hashType || '0',
                outputFile: 'cracked_wordlist.txt',
                workload: data.workload || 3
            }),
            category: 'hashcat_wordlist'
        });
        
        // Command 4: HashCat with rules
        commands.push({
            title: 'HashCat Wordlist Attack with Rules',
            description: 'Apply password rules to wordlist (requires rules file)',
            command: this.generateWordlistAttackCommand(wordlistFile, hashFile, {
                hashType: data.hashType || '0',
                outputFile: 'cracked_rules.txt',
                rulesFile: 'rules/best64.rule',
                workload: data.workload || 3
            }),
            category: 'hashcat_rules'
        });
        
        // Command 5: Combined attack (wordlist + mask)
        commands.push({
            title: 'HashCat Hybrid Attack (Wordlist + Mask)',
            description: 'Combine wordlist with mask pattern',
            command: this.generateHybridCommand(wordlistFile, data.masks?.[0]?.mask || '?d?d?d?d', hashFile, {
                hashType: data.hashType || '0',
                outputFile: 'cracked_hybrid.txt'
            }),
            category: 'hashcat_hybrid'
        });
        
        return commands;
    }

    /**
     * Generate hybrid attack command
     */
    generateHybridCommand(wordlistFile, mask, hashFile, options = {}) {
        const parts = ['hashcat'];
        parts.push(`-m ${options.hashType || '0'}`);
        parts.push('-a 6'); // Hybrid attack mode (wordlist + mask)
        parts.push(`"${hashFile}"`);
        parts.push(`"${wordlistFile}"`);
        parts.push(`"${mask}"`);
        
        if (options.outputFile) {
            parts.push(`-o "${options.outputFile}"`);
        }
        
        return parts.join(' ');
    }

    /**
     * Format commands for display
     */
    formatCommands(commands) {
        let output = '# HashCat CLI Commands\n';
        output += '# Generated by HashCat Mask Generator\n\n';
        
        // Group by category
        const categories = {};
        commands.forEach(cmd => {
            if (!categories[cmd.category]) {
                categories[cmd.category] = [];
            }
            categories[cmd.category].push(cmd);
        });
        
        Object.entries(categories).forEach(([category, cmds]) => {
            output += `\n## ${category.replace(/_/g, ' ').toUpperCase()}\n\n`;
            cmds.forEach(cmd => {
                output += `# ${cmd.title}\n`;
                output += `# ${cmd.description}\n`;
                output += `${cmd.command}\n\n`;
            });
        });
        
        // Add helpful comments
        output += '\n# Notes:\n';
        output += '# - Replace "hashes.txt" with your actual hash file\n';
        output += '# - Replace hash type (-m) if not using MD5\n';
        output += '# - Adjust -w workload (1-4) based on your system\n';
        output += '# - Use --show to display already cracked hashes\n';
        output += '# - Use --status to see progress\n';
        
        return output;
    }

    /**
     * Get hash type help
     */
    getHashTypeHelp() {
        return Object.entries(this.hashTypes)
            .map(([name, code]) => `-m ${code}: ${name.toUpperCase()}`)
            .join('\n');
    }
}

// Export for use in other modules
window.HashcatCLIGenerator = HashcatCLIGenerator;
