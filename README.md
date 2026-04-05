<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Whirlpool/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Whirlpool/main/docs/assets/logo-light.svg">
  <img alt="Whirlpool" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Whirlpool/main/docs/assets/logo-dark.svg" width="420">
</picture>

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Privilege escalation reasoning engine -- parses LinPEAS/WinPEAS output and generates ranked exploitation playbooks**

Feed it raw enumeration output, get back a prioritized attack plan with exact commands, confidence ratings, and multi-step attack chains. 329 GTFOBins entries, 86 LOLBAS binaries, 42 kernel exploits, 9 potato attacks. Everything runs offline -- no API calls, no internet required.

> **Authorization Required**: This tool is designed exclusively for authorized security testing with explicit written permission. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

</div>

---

## Quick Start

### Prerequisites

- **Python** 3.9+
- **pip** or **pipx**

### Install

```bash
# pipx (recommended -- isolated environment)
pipx install git+https://github.com/Real-Fruit-Snacks/Whirlpool.git

# Or from a local clone
git clone https://github.com/Real-Fruit-Snacks/Whirlpool.git
cd Whirlpool && pip install -e .
```

### Run

```bash
# Analyze LinPEAS output (auto-detected)
whirlpool linpeas_output.txt

# Quick wins only
whirlpool enum.txt --quick-wins

# OSCP-optimized ranking
whirlpool enum.txt --profile oscp

# Export to Markdown
whirlpool enum.txt --format markdown --output report.md

# JSON with attacker IP substitution
whirlpool enum.txt --format json --lhost 10.10.14.1 --lport 4444

# Diff two scans
whirlpool first.txt --diff second.txt
```

---

## Features

### Auto-Detection

Feed Whirlpool any enumeration file and it figures out the format. Handles LinPEAS `.sh` output (Unicode box headers), WinPEAS `.exe` output, `.bat` output, `.exe` beta format, and manual command output -- all automatically:

```bash
# No --type flag needed
whirlpool linpeas_output.txt
whirlpool winpeas_output.txt
whirlpool manual_commands.txt
```

### Offline Knowledge Bases

329 GTFOBins entries, 86 LOLBAS binaries, 42 kernel exploits with version ranges, and 9 potato attacks with OS compatibility matrices. All shipped as JSON in `whirlpool/data/`:

```bash
# All matching happens locally -- zero network calls
whirlpool enum.txt
```

| File | Entries | Source |
|---|---|---|
| `gtfobins.json` | 329 binaries | GTFOBins |
| `kernel_exploits.json` | 42 CVEs | 23 Linux + 19 Windows |
| `lolbas.json` | 86 binaries | LOLBAS Project |
| `potato_matrix.json` | 9 attacks | OS compatibility matrix |

### Composite Scoring

Every technique scored across four dimensions with profile-specific weights:

```bash
# Five ranking profiles
whirlpool enum.txt --profile default   # Balanced (40/30/20/10)
whirlpool enum.txt --profile oscp      # Reliable + documented
whirlpool enum.txt --profile ctf       # Speed -- get root fast
whirlpool enum.txt --profile stealth   # Low detection
whirlpool enum.txt --profile safe      # System stability
```

Dimensions: reliability (likelihood of success), safety (system stability risk), simplicity (ease of execution), stealth (detection avoidance).

### Attack Chain Detection

Detects 12 multi-step privilege escalation paths that single-finding scanners miss:

```bash
# Chains enabled by default, disable with --no-chains
whirlpool enum.txt
whirlpool enum.txt --no-chains
```

Chain types include cron PATH hijack, writable cron scripts, Docker/LXD escapes, NFS SUID planting, wildcard injection, LD_PRELOAD abuse, and writable /etc/passwd.

### Noise Filtering

Purpose-built parsers with aggressive false-positive filtering. The sudo parser rejects grep artifacts, version-like patterns, and common non-runas words. Tested against 22 HTB/Vulnhub samples with zero crashes and zero blank results.

### Multiple Output Formats

```bash
# Rich terminal with Catppuccin Mocha theme
whirlpool enum.txt

# Markdown report
whirlpool enum.txt --format markdown --output report.md

# Structured JSON for tool integration
whirlpool enum.txt --format json > results.json

# Quick wins -- top 5 techniques
whirlpool enum.txt --quick-wins
```

### Python API

```python
from whirlpool.parser.linpeas import LinPEASParser
from whirlpool.engine.analyzer import Analyzer
from whirlpool.engine.ranker import Ranker, RankingProfile

parser = LinPEASParser()
results = parser.parse_file("linpeas_output.txt")

analyzer = Analyzer()
paths = analyzer.analyze_linux(results)

ranker = Ranker(profile=RankingProfile.OSCP)
ranked = ranker.rank(paths)
quick_wins = ranker.get_quick_wins(paths, top_n=5)
```

---

## Architecture

```
whirlpool/
├── cli.py                        # Argparse entry point, auto-detection, output routing
├── parser/                       # LinPEAS, WinPEAS, manual command parsers (3 format variants)
├── engine/
│   ├── analyzer.py               # Core analysis -- matches findings against knowledge bases
│   ├── ranker.py                 # Composite scoring with 5 ranking profiles
│   └── chain.py                  # Multi-step attack chain detection (12 chain types)
├── data/                         # Offline JSON knowledge bases (GTFOBins, LOLBAS, kernel, potato)
├── output/                       # Terminal (Catppuccin Mocha), Markdown, JSON renderers
└── tests/                        # 237 tests
```

Three-stage pipeline: parse enumeration output into structured data, analyze findings against knowledge bases to generate exploitation paths, rank paths using composite scoring.

---

## Platform Support

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| CLI | Full | Full | Full |
| LinPEAS Parsing | Full | Full | Full |
| WinPEAS Parsing | Full | Full | Full |
| Rich Terminal UI | Full | Full | Full (Windows Terminal recommended) |
| Markdown/JSON Export | Full | Full | Full |

---

## Security

Report security issues via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Whirlpool/security/advisories/new) (preferred) or private disclosure to maintainers. Responsible disclosure timeline: 90 days. Do not open public issues for vulnerabilities.

Whirlpool does **not**:

- Execute generated commands -- outputs text for the operator to review
- Scan hosts or perform active reconnaissance
- Make network connections -- runs entirely offline
- Manage implants or maintain persistent access

---

## License

[MIT](LICENSE) -- Copyright 2026 Real-Fruit-Snacks
