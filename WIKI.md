# Nmap Timing Template Visualizer - Wiki

## Overview

The Nmap Timing Template Visualizer is an interactive web-based tool that provides real-time visualization of Nmap's timing templates (T0-T5) and their underlying parameters. This tool helps security professionals, penetration testers, and network administrators understand how different timing configurations affect scan behavior, speed, stealth, and accuracy.

## Table of Contents

- [Getting Started](#getting-started)
- [Features](#features)
- [Understanding Timing Templates](#understanding-timing-templates)
- [Timing Parameters Explained](#timing-parameters-explained)
- [Metrics and Visualizations](#metrics-and-visualizations)
- [Usage Guide](#usage-guide)
- [Examples](#examples)
- [Technical Details](#technical-details)
- [FAQ](#faq)

## Getting Started

### Quick Access

**Live Demo:** [https://chickenpwny.github.io/NmapTimingTemplateVisualizer/](https://chickenpwny.github.io/NmapTimingTemplateVisualizer/)

### Local Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ChickenPwny/NmapTimingTemplateVisualizer.git
   cd NmapTimingTemplateVisualizer
   ```

2. Open `index.html` in any modern web browser
   - No server required
   - No dependencies
   - Works offline

## Features

### Interactive Template Selection
- **Six Timing Templates:** Switch between Paranoid (T0), Sneaky (T1), Polite (T2), Normal (T3), Aggressive (T4), and Insane (T5)
- **Real-time Updates:** All parameters and metrics update instantly when selecting a template

### Custom Parameter Adjustment
- **Individual Sliders:** Fine-tune each timing parameter independently
- **Live Calculations:** Metrics automatically recalculate based on your custom settings
- **Visual Feedback:** See how your changes affect stealth, speed, and performance

### Comprehensive Visualizations
- **Detection Level Bar:** Visual representation of scan stealthiness
- **Scan Speed Indicator:** Relative speed comparison across templates
- **Port Knocks Counter:** Shows probe retransmission settings
- **Parallelism Gauge:** Displays concurrent probe configuration

### Command Generation
- **Simple Command:** Quick template-based command (`nmap -T3 target`)
- **Granular Command:** Complete command with all timing arguments
- **Copy to Clipboard:** One-click copying for immediate use

### Educational Content
- **Detailed Descriptions:** Learn what each parameter does
- **Template Comparisons:** Understand how T0-T5 differ
- **Best Practices:** Guidance on when to use each template

## Understanding Timing Templates

Nmap offers six timing templates that balance speed, accuracy, and stealth. Each template applies a specific set of timing parameters optimized for different scenarios.

### Template Comparison

| Template | Name | Speed | Stealth | Use Case |
|----------|------|-------|---------|----------|
| **T0** | Paranoid | Extremely Slow | Very High | Maximum stealth, IDS evasion |
| **T1** | Sneaky | Very Slow | Very High | Stealth scanning, avoiding detection |
| **T2** | Polite | Slow | High | Reduce bandwidth, be respectful |
| **T3** | Normal | Normal | Moderate | Default behavior, balanced approach |
| **T4** | Aggressive | Fast | Low | Fast networks, speed prioritized |
| **T5** | Insane | Maximum | None | Maximum speed, accuracy may suffer |

### Template Details

#### T0 - Paranoid
- **Max RTT Timeout:** 5 minutes
- **Scan Delay:** 5 minutes between probes
- **Parallelism:** Serial (one probe at a time)
- **Max Retries:** 10
- **Best For:** Maximum stealth, avoiding IDS alerts, critical targets

#### T1 - Sneaky
- **Max RTT Timeout:** 15 seconds
- **Scan Delay:** 15 seconds between probes
- **Parallelism:** Very low (~10)
- **Max Retries:** 10
- **Best For:** Stealth scanning, IDS evasion with better speed than T0

#### T2 - Polite
- **Max RTT Timeout:** 10 seconds
- **Scan Delay:** 400ms between probes
- **Parallelism:** Low (~50)
- **Max Retries:** 10
- **Best For:** Reducing bandwidth usage, avoiding host crashes, polite scanning

#### T3 - Normal (Default)
- **Max RTT Timeout:** 1 second
- **Scan Delay:** Adaptive (0ms default)
- **Parallelism:** Dynamic (~100)
- **Max Retries:** 10
- **Best For:** General purpose scanning, balanced approach

#### T4 - Aggressive
- **Max RTT Timeout:** 1250ms
- **Min RTT Timeout:** 100ms
- **Initial RTT Timeout:** 500ms
- **Max Scan Delay:** 10ms
- **Max Retries:** 6
- **Parallelism:** High (~200)
- **Best For:** Fast, reliable networks, time-constrained scans

#### T5 - Insane
- **Max RTT Timeout:** 300ms
- **Min RTT Timeout:** 50ms
- **Initial RTT Timeout:** 250ms
- **Max Scan Delay:** 5ms
- **Max Retries:** 2
- **Host Timeout:** 15 minutes
- **Script Timeout:** 10 minutes
- **Parallelism:** Maximum (~300+)
- **Best For:** Very fast networks, accepting lower accuracy for maximum speed

## Timing Parameters Explained

### RTT Timeouts

#### --max-rtt-timeout
- **What it does:** Maximum time Nmap waits for a probe response before retransmitting or giving up
- **Range:** 50ms - 5000ms (5 seconds)
- **Impact:** Higher values handle slow networks better but increase scan time. Lower values speed up scans on fast networks.
- **Template Values:**
  - T0-T2: 5 minutes to 10 seconds
  - T3-T4: 1000-1250ms
  - T5: 300ms

#### --min-rtt-timeout
- **What it does:** Lower bound for round trip timeout calculations
- **Range:** 50ms - 5000ms
- **Impact:** Rarely adjusted manually. Provides a floor for timeout calculations.
- **Template Values:** T0-T4: 100ms, T5: 50ms

#### --initial-rtt-timeout
- **What it does:** Starting timeout value for first probes before Nmap adapts based on network responses
- **Range:** 50ms - 5000ms
- **Impact:** Lower values speed up initial scans. Higher values are more conservative.
- **Template Values:**
  - T0: 5 minutes
  - T1: 15 seconds
  - T2-T3: 1 second
  - T4: 500ms
  - T5: 250ms

### Retry and Delay Settings

#### --max-retries
- **What it does:** Maximum number of probe retransmissions before giving up on a port
- **Range:** 0 - 10
- **Impact:** Higher values improve accuracy on unreliable networks but slow scans. Lower values speed up scans but may miss ports.
- **Template Values:**
  - T0-T3: 10 retries
  - T4: 6 retries
  - T5: 2 retries

#### --max-scan-delay
- **What it does:** Maximum delay allowed between probes to avoid rate limiting
- **Range:** 0ms (adaptive) - 300000ms (5 minutes)
- **Impact:** Higher delays avoid rate limiting and IDS detection but slow scans dramatically. Set to 0 for adaptive behavior.
- **Template Values:**
  - T0: 5 minutes
  - T1: 15 seconds
  - T2: 400ms
  - T3-T5: Adaptive (0ms) with caps at 10ms (T4) or 5ms (T5)

### Parallelism

#### Parallelism (Concurrent Probes)
- **What it does:** Number of probes sent simultaneously per host group
- **Range:** 0 (serial) - 300+
- **Impact:** Higher values speed scans but may overwhelm targets or trigger security controls. Serial (0) maximizes stealth.
- **Template Values:**
  - T0-T2: Serial or very low (1-50)
  - T3-T5: Dynamic and high (100-300+)

## Metrics and Visualizations

### Detection Level (Stealth)
- **What it measures:** Scan stealthiness based on timeouts, delays, and parallelism
- **Scale:** 0-100%
- **Higher values:** More stealthy, longer timeouts and delays, lower parallelism
- **Lower values:** Faster scans but more detectable
- **Typical Values:**
  - T0-T1: 90-100% (Very Stealth)
  - T2: ~75% (Stealth)
  - T3: ~50% (Moderate)
  - T4: ~25% (Low Stealth)
  - T5: ~5% (No Stealth)

### Scan Speed
- **What it measures:** Relative scanning speed compared across templates
- **Scale:** 0-100%
- **Factors:** RTT timeouts, delays, retries, parallelism
- **Typical Values:**
  - T0: ~5% (Extremely Slow)
  - T1: ~8% (Very Slow)
  - T2: ~15% (Slow)
  - T3: ~50% (Normal)
  - T4: ~85% (Fast)
  - T5: ~100% (Maximum)

### Port Knocks (Probes per Port)
- **What it measures:** Number of probe attempts per port before giving up
- **Scale:** 0-10 retries
- **Relationship:** Directly maps to --max-retries setting
- **Impact:** More retries = better accuracy but slower scans

### Parallelism (Concurrent Probes)
- **What it measures:** Number of probes sent simultaneously
- **Scale:** 0-300+
- **Impact:** Higher parallelism = faster scans but more network load
- **Trade-off:** Speed vs. stealth vs. target impact

## Usage Guide

### Basic Usage

1. **Open the Visualizer:** Navigate to the live demo or open `index.html` locally

2. **Select a Template:** Use the main slider to choose T0-T5
   - Watch all parameters and metrics update automatically
   - Review the generated CLI command

3. **Customize Parameters (Optional):** Adjust individual sliders
   - Custom mode indicator appears
   - Metrics recalculate in real-time
   - Granular command updates automatically

4. **Copy Commands:** Click the "Copy" button on either command panel
   - Simple command: Template-based (`nmap -T3 target`)
   - Granular command: Full command with all parameters

5. **Use in Terminal:** Paste the command and replace `target` with your actual target

### Advanced Usage

#### Custom Timing Configuration
1. Select a base template (recommended: T4 for fast networks)
2. Adjust specific parameters that need optimization
3. Monitor the metrics to understand trade-offs
4. Copy the granular command for use

#### Learning Mode
1. Start with T3 (Normal) to see baseline settings
2. Compare with T0 (Paranoid) to understand stealth settings
3. Compare with T5 (Insane) to understand speed settings
4. Adjust individual parameters to see isolated effects

## Examples

### Example 1: Stealth Scan
```
Template: T1 (Sneaky)
Command: nmap -T1 --max-rtt-timeout 15000ms --max-scan-delay 15s target
Use Case: Scanning sensitive networks, avoiding IDS detection
```

### Example 2: Fast Local Network Scan
```
Template: T5 (Insane)
Command: nmap -T5 --max-rtt-timeout 300ms --min-rtt-timeout 50ms --initial-rtt-timeout 250ms --max-retries 2 target
Use Case: Fast local network, speed prioritized over accuracy
```

### Example 3: Custom Balanced Scan
```
Custom Configuration:
- Max RTT: 1000ms
- Initial RTT: 500ms
- Max Retries: 6
- Max Scan Delay: 10ms
- Parallelism: 200

Command: nmap --max-rtt-timeout 1000ms --initial-rtt-timeout 500ms --max-retries 6 --max-scan-delay 10ms target
Use Case: Optimized for specific network conditions
```

## Technical Details

### Architecture
- **Pure HTML/CSS/JavaScript:** No frameworks or dependencies
- **Client-side Only:** All calculations happen in the browser
- **Responsive Design:** Works on desktop, tablet, and mobile
- **Accessibility:** ARIA labels and semantic HTML

### Browser Compatibility
- Chrome/Edge: Full support
- Firefox: Full support
- Safari: Full support
- Opera: Full support

### Performance
- **Instant Updates:** Real-time parameter adjustment
- **Lightweight:** Single HTML file, ~120KB
- **Offline Capable:** No external resources required

## FAQ

### Q: Why are some parameters not included in the visualizer?
A: The visualizer focuses on the most commonly adjusted timing parameters. Some advanced parameters like `--min-hostgroup`, `--max-hostgroup`, `--min-rate`, and `--max-rate` are not included but can be added manually to generated commands.

### Q: Can I use this tool without Nmap knowledge?
A: Yes! The tool is designed for learning. Start with the templates (T0-T5) and read the descriptions to understand what each parameter does.

### Q: Are the generated commands safe to use?
A: The commands are safe in terms of syntax, but scanning networks requires authorization. Always ensure you have permission before scanning any target.

### Q: How accurate are the metric calculations?
A: The metrics are approximations based on typical network behavior and Nmap documentation. Actual scan performance depends on network conditions, target responsiveness, and other factors.

### Q: Can I save my custom configurations?
A: Currently, custom configurations are not saved automatically. You can copy the generated command and save it for later use. Browser-based saving could be added in future versions.

### Q: Why does T3 show "Normal" when it's the default?
A: T3 is Nmap's default timing template, so it represents normal/balanced behavior. The visualizer reflects this by showing it as the default selection.

### Q: What's the difference between scan-delay and max-scan-delay?
A: `--scan-delay` sets a fixed delay between probes. `--max-scan-delay` sets the maximum delay Nmap can use when adapting to rate limiting. When set to 0, Nmap uses adaptive delays.

## Contributing

Contributions are welcome! Areas for improvement:
- Additional timing parameters
- Saved configurations
- Export/import settings
- Comparison views between templates
- Real-time scan simulation

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Resources

- **Nmap Official Documentation:** [https://nmap.org/book/man-performance.html](https://nmap.org/book/man-performance.html)
- **Nmap Timing Templates:** [https://nmap.org/book/performance-timing-templates.html](https://nmap.org/book/performance-timing-templates.html)
- **GitHub Repository:** [https://github.com/ChickenPwny/NmapTimingTemplateVisualizer](https://github.com/ChickenPwny/NmapTimingTemplateVisualizer)

## Acknowledgments

This tool is based on the official Nmap documentation and timing template specifications. Special thanks to the Nmap development team for creating such a powerful and well-documented tool.

---

**Last Updated:** January 2025

