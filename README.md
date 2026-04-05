<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Whirlpool/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Whirlpool/main/docs/assets/logo-light.svg">
  <img alt="Whirlpool" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Whirlpool/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Python](https://img.shields.io/badge/language-Python-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Privilege escalation reasoning engine -- parses LinPEAS/WinPEAS output and generates ranked exploitation playbooks**

Feed it raw enumeration output, get back a prioritized attack plan with exact commands, confidence ratings, and multi-step attack chains. 329 GTFOBins entries, 86 LOLBAS binaries, 42 kernel exploits, 9 potato attacks. Everything runs offline -- no API calls, no internet required.

> **Authorization Required**: This tool is designed exclusively for authorized security testing with explicit written permission. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

[Quick Start](#quick-start) • [Features](#features) • [Knowledge Bases](#knowledge-bases) • [Ranking System](#ranking-system) • [Architecture](#architecture) • [Security](#security)

</div>

---

## Highlights

<table>
<tr>
<td width="50%">

**Auto-Detection**
Feed Whirlpool any enumeration file and it figures out the format. Handles LinPEAS `.sh` output (Unicode box headers), WinPEAS `.exe` output, `.bat` output (`_-_-_-_->` markers), `.exe` beta format (`[+]` sections), and manual command output -- all automatically.

**Composite Scoring**
Every technique gets a weighted score across four dimensions: reliability (40%), safety (30%), simplicity (20%), and stealth (10%). Five ranking profiles -- default, OSCP, CTF, stealth, safe -- shift the weights to match your scenario.

**Noise Filtering**
Purpose-built parsers with aggressive false-positive filtering. The sudo parser rejects grep artifacts, version-like patterns, and common non-runas words. Real-world tested against 22 HTB/Vulnhub LinPEAS and WinPEAS samples with zero crashes and zero blank results.

</td>
<td width="50%">

**Offline Knowledge Bases**
329 GTFOBins entries, 86 LOLBAS binaries, 42 kernel exploits with version ranges, and 9 potato attacks with OS compatibility matrices. Everything runs locally -- no API calls, no internet required.

**Attack Chain Detection**
Detects multi-step privilege escalation paths that single-finding scanners miss: cron PATH hijack, writable cron scripts, Docker/LXD escapes, NFS SUID planting, wildcard injection, LD_PRELOAD abuse, writable /etc/passwd, and more.

**Multiple Output Formats**
Rich terminal output with Catppuccin Mocha theming, Markdown report generation for documentation, and structured JSON export for tool integration. Quick-wins mode surfaces the top 5 highest-probability techniques.

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

<table>
<tr>
<th>Requirement</th>
<th>Version</th>
<th>Purpose</th>
</tr>
<tr>
<td>Python</td>
<td>3.9+</td>
<td>Runtime</td>
</tr>
<tr>
<td>pip or pipx</td>
<td>Any</td>
<td>Package installation</td>
</tr>
</table>

### Build

```bash
# pipx (recommended -- isolated environment)
pipx install git+https://github.com/Real-Fruit-Snacks/Whirlpool.git

# Or from a local clone
git clone https://github.com/Real-Fruit-Snacks/Whirlpool.git
cd Whirlpool && pip install -e .
```

### Verification

```bash
# Analyze LinPEAS output (auto-detected)
whirlpool linpeas_output.txt

# Quick wins only
whirlpool enum.txt --quick-wins

# OSCP-optimized ranking
whirlpool enum.txt --profile oscp

# Export to Markdown
whirlpool enum.txt --format markdown --output report.md
```

---

## Features

<table>
<tr>
<th>Feature</th>
<th>Description</th>
</tr>
<tr><td><strong>Auto-detection</strong></td><td>Identifies input format from content -- no <code>--type</code> flag needed</td></tr>
<tr><td><strong>LinPEAS parsing</strong></td><td>SUID, SGID, capabilities, sudo, cron, NFS, Docker, kernel version, SSH keys</td></tr>
<tr><td><strong>WinPEAS parsing</strong></td><td>Privileges, services, scheduled tasks, missing patches, user info, network</td></tr>
<tr><td><strong>Sudo noise filtering</strong></td><td>Rejects grep artifacts, version patterns, and common false-positive words</td></tr>
<tr><td><strong>GTFOBins matching</strong></td><td>Matches SUID/sudo/capability binaries against 329 known-exploitable entries</td></tr>
<tr><td><strong>LOLBAS matching</strong></td><td>Matches Windows binaries against 86 living-off-the-land techniques</td></tr>
<tr><td><strong>Kernel exploit matching</strong></td><td>Version-range matching against 42 Linux/Windows kernel CVEs (2015-2025)</td></tr>
<tr><td><strong>Potato attack selection</strong></td><td>OS-aware recommendation from 9 potato variants</td></tr>
<tr><td><strong>Token privilege analysis</strong></td><td>SeBackup, SeDebug, SeLoadDriver, SeRestore, SeTakeOwnership exploitation paths</td></tr>
<tr><td><strong>Attack chain detection</strong></td><td>12 multi-step chain types (PATH hijack, Docker escape, NFS plant, etc.)</td></tr>
<tr><td><strong>Composite scoring</strong></td><td>Four-dimension weighted scoring (reliability, safety, simplicity, stealth)</td></tr>
<tr><td><strong>5 ranking profiles</strong></td><td>Default, OSCP, CTF, stealth, safe -- each shifts scoring weights</td></tr>
<tr><td><strong>Quick wins</strong></td><td>Surfaces top 5 highest-probability techniques</td></tr>
<tr><td><strong>Catppuccin Mocha theme</strong></td><td>Rich terminal output with semantic color mapping</td></tr>
<tr><td><strong>Markdown reports</strong></td><td>Full analysis report with techniques, commands, and references</td></tr>
<tr><td><strong>JSON export</strong></td><td>Structured output for tool integration and automation</td></tr>
<tr><td><strong>Diff mode</strong></td><td>Compare two enum scans and show new/removed findings</td></tr>
<tr><td><strong>Stdin/pipe support</strong></td><td>Read from stdin via <code>-</code> or auto-detected pipe input</td></tr>
</table>

---

## CLI Reference

```
whirlpool [-h] [-t TYPE] [-f FORMAT] [-o OUTPUT] [-p PROFILE]
          [--categories CAT[,CAT...]] [--quick-wins] [--no-chains]
          [--no-color] [--min-confidence LEVEL] [--max-risk LEVEL]
          [--lhost IP] [--lport PORT] [--diff SECOND_FILE]
          [--list-techniques] [-v] [--version]
          [input]
```

<table>
<tr>
<th>Flag</th>
<th>Values</th>
<th>Default</th>
<th>Description</th>
</tr>
<tr><td><code>input</code></td><td>file path, <code>-</code>, or omit for pipe</td><td></td><td>Input file</td></tr>
<tr><td><code>-t, --type</code></td><td><code>auto</code>, <code>linpeas</code>, <code>winpeas</code>, <code>manual_linux</code>, <code>manual_windows</code></td><td><code>auto</code></td><td>Input format</td></tr>
<tr><td><code>-f, --format</code></td><td><code>terminal</code>, <code>markdown</code>, <code>json</code></td><td><code>terminal</code></td><td>Output format</td></tr>
<tr><td><code>-o, --output</code></td><td>file path</td><td>stdout</td><td>Output file</td></tr>
<tr><td><code>-p, --profile</code></td><td><code>default</code>, <code>oscp</code>, <code>ctf</code>, <code>stealth</code>, <code>safe</code></td><td><code>default</code></td><td>Ranking profile</td></tr>
<tr><td><code>--categories</code></td><td>comma-separated</td><td>all</td><td>Filter to specific categories</td></tr>
<tr><td><code>--quick-wins</code></td><td></td><td></td><td>Show top 5 techniques only</td></tr>
<tr><td><code>--no-chains</code></td><td></td><td></td><td>Disable multi-step chain detection</td></tr>
<tr><td><code>--min-confidence</code></td><td><code>theoretical</code>, <code>low</code>, <code>medium</code>, <code>high</code></td><td></td><td>Filter floor</td></tr>
<tr><td><code>--max-risk</code></td><td><code>low</code>, <code>medium</code>, <code>high</code></td><td></td><td>Filter ceiling</td></tr>
<tr><td><code>--lhost</code></td><td>IP address</td><td></td><td>Substitute ATTACKER_IP placeholders</td></tr>
<tr><td><code>--lport</code></td><td>port number</td><td></td><td>Substitute LPORT placeholders</td></tr>
<tr><td><code>--diff</code></td><td>file path</td><td></td><td>Compare two scans</td></tr>
</table>

---

## Knowledge Bases

Whirlpool ships with four offline knowledge bases in `whirlpool/data/`:

<table>
<tr>
<th>File</th>
<th>Entries</th>
<th>Source</th>
<th>Contents</th>
</tr>
<tr><td><code>gtfobins.json</code></td><td>329 binaries</td><td><a href="https://gtfobins.github.io/">GTFOBins</a></td><td>SUID, sudo, capabilities, file_read, file_write, shell exploitation commands</td></tr>
<tr><td><code>kernel_exploits.json</code></td><td>42 CVEs</td><td>Various</td><td>23 Linux + 19 Windows kernel exploits with affected version ranges</td></tr>
<tr><td><code>lolbas.json</code></td><td>86 binaries</td><td><a href="https://lolbas-project.github.io/">LOLBAS</a></td><td>Windows living-off-the-land techniques (execute, download, etc.)</td></tr>
<tr><td><code>potato_matrix.json</code></td><td>9 attacks</td><td>Various</td><td>Potato attack variants with OS compatibility matrix and decision logic</td></tr>
</table>

### Supported Techniques

#### Linux

- SUID/SGID binary exploitation (GTFOBins cross-reference)
- Linux capabilities abuse (cap_setuid, cap_dac_override, etc.)
- Sudo privilege escalation (GTFOBins lookup + NOPASSWD + LD_PRELOAD + wildcard + argument escape)
- Cron job manipulation (writable scripts, relative paths)
- PATH hijacking via cron
- Wildcard injection (tar, rsync)
- Docker group escape / Docker socket abuse
- LXD/LXC container escape
- NFS no_root_squash SUID planting
- Kernel exploits (DirtyPipe, DirtyCOW, PwnKit, Baron Samedit, etc.)
- Credential/password file analysis (SSH keys, config files)
- Network service analysis (internal-only services with port forwarding commands)
- Writable sensitive files (/etc/passwd, /etc/shadow, /etc/sudoers, /etc/crontab, systemd units)
- Dangerous group membership (disk, adm, shadow, staff, video, root, wheel, sudo)

#### Windows

- Token privilege abuse (SeImpersonate, SeBackup, SeDebug, SeLoadDriver, SeRestore, SeTakeOwnership)
- Potato attacks (PrintSpoofer, GodPotato, JuicyPotato, SweetPotato, etc.)
- Service binary replacement
- Unquoted service paths
- Weak service permissions
- DLL hijacking (writable service binary directories)
- Scheduled task hijacking
- Registry exploitation (AlwaysInstallElevated, AutoLogon credentials)
- UAC bypass detection (fodhelper, eventvwr, sdclt, computerdefaults)
- Kernel exploits (PrintNightmare, EternalBlue, MS16-032, etc.)
- Missing patch-to-exploit mapping
- LOLBAS techniques
- AD/Kerberos suggestions (Kerberoasting, AS-REP Roasting, BloodHound)

---

## Ranking System

Each exploitation path is scored across four dimensions, then combined with profile-specific weights:

<table>
<tr>
<th>Component</th>
<th>Default</th>
<th>OSCP</th>
<th>CTF</th>
<th>Stealth</th>
<th>Safe</th>
</tr>
<tr><td><strong>Reliability</strong> -- likelihood of success</td><td>40%</td><td>50%</td><td>50%</td><td>25%</td><td>30%</td></tr>
<tr><td><strong>Safety</strong> -- system stability risk</td><td>30%</td><td>25%</td><td>10%</td><td>25%</td><td>50%</td></tr>
<tr><td><strong>Simplicity</strong> -- ease of execution</td><td>20%</td><td>20%</td><td>35%</td><td>10%</td><td>15%</td></tr>
<tr><td><strong>Stealth</strong> -- detection avoidance</td><td>10%</td><td>5%</td><td>5%</td><td>40%</td><td>5%</td></tr>
</table>

### Profiles

<table>
<tr>
<th>Profile</th>
<th>Use Case</th>
</tr>
<tr><td><code>default</code></td><td>Balanced scoring for general use</td></tr>
<tr><td><code>oscp</code></td><td>Prioritizes reliable, documented techniques for exam environments</td></tr>
<tr><td><code>ctf</code></td><td>Prioritizes quick wins and speed -- get root fast</td></tr>
<tr><td><code>stealth</code></td><td>Prioritizes low-detection techniques for red team ops</td></tr>
<tr><td><code>safe</code></td><td>Prioritizes system stability -- avoid crashing the target</td></tr>
</table>

---

## Python API

```python
from whirlpool.parser.linpeas import LinPEASParser
from whirlpool.parser.winpeas import WinPEASParser
from whirlpool.engine.analyzer import Analyzer
from whirlpool.engine.ranker import Ranker, RankingProfile
from whirlpool.engine.chain import ChainDetector

# Parse enumeration output
parser = LinPEASParser()
results = parser.parse_file("linpeas_output.txt")

# Analyze for exploitation paths
analyzer = Analyzer()
paths = analyzer.analyze_linux(results)

# Rank with a specific profile
ranker = Ranker(profile=RankingProfile.OSCP)
ranked = ranker.rank(paths)

# Get top 5 quick wins
quick_wins = ranker.get_quick_wins(paths, top_n=5)

# Detect multi-step attack chains
detector = ChainDetector()
chains = detector.detect_chains(results)
```

---

## Architecture

Whirlpool follows a three-stage pipeline: **parse** enumeration output into structured data, **analyze** findings against knowledge bases to generate exploitation paths, and **rank** paths using a composite scoring system.

```
Whirlpool/
├── cli.py                        # Argparse entry point, auto-detection, output routing
│
├── parser/
│   ├── linpeas.py                # LinPEAS parser (3 format variants, noise filtering)
│   ├── winpeas.py                # WinPEAS parser (3 format variants, missing patches)
│   ├── manual_linux.py           # Manual Linux command parser (id, sudo -l, getcap, etc.)
│   └── manual_windows.py         # Manual Windows command parser (whoami, systeminfo, etc.)
│
├── engine/
│   ├── analyzer.py               # Core analysis -- matches findings against knowledge bases
│   ├── ranker.py                 # Composite scoring with 5 ranking profiles
│   └── chain.py                  # Multi-step attack chain detection (12 chain types)
│
├── data/
│   ├── gtfobins.json             # 329 Unix binaries
│   ├── kernel_exploits.json      # 42 Linux + Windows kernel exploits
│   ├── potato_matrix.json        # 9 potato attacks with OS compatibility matrix
│   └── lolbas.json               # 86 Windows LOLBAS binaries
│
├── output/
│   ├── terminal.py               # Rich terminal output with Catppuccin Mocha theme
│   ├── markdown.py               # Markdown report generator
│   └── json_out.py               # Structured JSON output
│
├── docs/                          # ── GitHub Pages ──
│   ├── index.html                # Project website
│   └── assets/
│       ├── logo-dark.svg         # Logo for dark theme
│       └── logo-light.svg        # Logo for light theme
│
└── tests/                         # 237 tests
    ├── test_parsers.py           # Parser tests (LinPEAS, WinPEAS, manual)
    ├── test_analyzer.py          # Analysis engine tests
    ├── test_ranker.py            # Ranking system tests
    └── test_chain.py             # Chain detection tests
```

### Pipeline

```
                    +------------------------------------------+
  LinPEAS output -->|                                          |
  WinPEAS output -->|  Parser         Analyzer        Ranker   |--> Terminal
  Manual commands ->|  (structured) -> (paths) -> (ranked)     |--> Markdown
                    |                                          |--> JSON
                    +------------------------------------------+
                              ^               ^
                              |               |
                    ANSI stripping    gtfobins.json
                    Section detection  kernel_exploits.json
                    Noise filtering    potato_matrix.json
                    3 format variants  lolbas.json
```

---

## Testing

```bash
# Clone and install with dev dependencies
git clone https://github.com/Real-Fruit-Snacks/Whirlpool.git
cd Whirlpool && pip install -e ".[dev]"

# Run all 237 tests
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=whirlpool --cov-report=html

# Type checking
mypy whirlpool/

# Linting
ruff check whirlpool/
```

---

## Platform Support

<table>
<tr>
<th>Capability</th>
<th>Linux</th>
<th>macOS</th>
<th>Windows</th>
</tr>
<tr>
<td>CLI</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>LinPEAS Parsing</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>WinPEAS Parsing</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>Rich Terminal UI</td>
<td>Full</td>
<td>Full</td>
<td>Full (Windows Terminal recommended)</td>
</tr>
<tr>
<td>Markdown Export</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>JSON Export</td>
<td>Full</td>
<td>Full</td>
<td>Full</td>
</tr>
</table>

---

## Security

### Vulnerability Reporting

**Report security issues via:**
- GitHub Security Advisories (preferred)
- Private disclosure to maintainers
- Responsible disclosure timeline (90 days)

**Do NOT:**
- Open public GitHub issues for vulnerabilities
- Disclose before coordination with maintainers
- Exploit vulnerabilities in unauthorized contexts

### Threat Model

**In scope:**
- Parsing enumeration output from authorized assessments
- Generating exploitation guidance for authorized penetration tests
- Offline analysis with no network calls

**Out of scope:**
- Direct exploitation of target systems
- Executing generated commands automatically
- Network scanning or active reconnaissance

### What Whirlpool Does NOT Do

Whirlpool is a **privilege escalation reasoning engine**, not an exploitation tool:

- **Not an attack tool** -- Generates commands as text for the operator, never executes them
- **Not a scanner** -- Analyzes output from other tools, does not scan hosts directly
- **Not a C2 framework** -- No remote execution, no network connections
- **Not anti-forensics** -- No evidence destruction or log tampering

---

## License

MIT License

Copyright &copy; 2026 Real-Fruit-Snacks

```
THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
THE AUTHORS ARE NOT LIABLE FOR ANY DAMAGES ARISING FROM USE.
USE AT YOUR OWN RISK AND ONLY WITH PROPER AUTHORIZATION.
```

---

## Resources

- **GitHub**: [github.com/Real-Fruit-Snacks/Whirlpool](https://github.com/Real-Fruit-Snacks/Whirlpool)
- **Documentation**: [real-fruit-snacks.github.io/Whirlpool](https://real-fruit-snacks.github.io/Whirlpool)
- **Issues**: [Report a Bug](https://github.com/Real-Fruit-Snacks/Whirlpool/issues)
- **Security**: [SECURITY.md](SECURITY.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

<div align="center">

**Part of the Real-Fruit-Snacks water-themed security toolkit**

[Aquifer](https://github.com/Real-Fruit-Snacks/Aquifer) • [Cascade](https://github.com/Real-Fruit-Snacks/Cascade) • [Conduit](https://github.com/Real-Fruit-Snacks/Conduit) • [Flux](https://github.com/Real-Fruit-Snacks/Flux) • [HydroShot](https://github.com/Real-Fruit-Snacks/HydroShot) • [Riptide](https://github.com/Real-Fruit-Snacks/Riptide) • [Runoff](https://github.com/Real-Fruit-Snacks/Runoff) • [Seep](https://github.com/Real-Fruit-Snacks/Seep) • [Slipstream](https://github.com/Real-Fruit-Snacks/Slipstream) • [Tidepool](https://github.com/Real-Fruit-Snacks/Tidepool) • [Undertow](https://github.com/Real-Fruit-Snacks/Undertow) • **Whirlpool**

*Remember: With great power comes great responsibility.*

</div>
