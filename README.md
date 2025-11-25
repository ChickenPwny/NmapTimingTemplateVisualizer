# Nmap Timing Template Visualizer

Interactive web-based visualizer for Nmap timing templates T0 through T5 showing real-time metrics for detection level scan speed port knocks and parallelism with individual parameter sliders for all timing arguments plus copy-paste commands for both simple template and full granular Nmap command syntax

## Features

- **Interactive Timing Template Slider** - Switch between Paranoid (T0), Sneaky (T1), Polite (T2), Normal (T3), Aggressive (T4), and Insane (T5) modes
- **Real-time Metrics Visualization** - Visual bars showing:
  - Detection Level (Stealth)
  - Scan Speed
  - Port Knocks (Probes per Port)
  - Parallelism (Concurrent Probes)
- **Parameter Sliders** - See individual timing arguments:
  - `--max-rtt-timeout`
  - `--min-rtt-timeout`
  - `--initial-rtt-timeout`
  - `--max-retries`
  - `--max-scan-delay`
  - Parallelism settings
- **Copy-Paste Commands** - Two command panels with copy buttons:
  - Simple template command (e.g., `nmap -T3 target`)
  - Full granular command with all timing arguments

## Usage

Simply open `index.html` in any modern web browser. No server or dependencies required!

1. Use the slider to select a timing template (0-5)
2. Observe how metrics and parameters change in real-time
3. Copy the commands using the copy buttons
4. Use the commands in your Nmap scans

## Timing Templates

| Template | Name | Speed | Stealth |
|----------|------|-------|---------|
| T0 | Paranoid | Extremely Slow | Very High |
| T1 | Sneaky | Very Slow | Very High |
| T2 | Polite | Slow | High |
| T3 | Normal | Normal | Moderate |
| T4 | Aggressive | Fast | Low |
| T5 | Insane | Maximum | None |

## Technical Details

This is a pure HTML/CSS/JavaScript application with:
- No external dependencies
- Responsive design
- Real-time updates
- Clipboard API for easy command copying

## Purpose

This tool helps network security professionals, penetration testers, and security enthusiasts understand how Nmap's timing templates work and what timing parameters are actually being used behind the scenes. It's perfect for learning, teaching, or optimizing your scanning strategies.

## Live Demo

Visit the [GitHub Pages site](https://chickenpwny.github.io/NmapTimingTemplateVisualizer/) to use the visualizer online.

## License

MIT License - see [LICENSE](LICENSE) file for details

