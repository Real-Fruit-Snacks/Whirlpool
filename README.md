<div align="center">

<img src="docs/banner.svg" alt="Whirlpool" width="800">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/Real-Fruit-Snacks/Whirlpool/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-green.svg)](https://python.org/)
[![Tests](https://img.shields.io/badge/Tests-237%20passing-brightgreen.svg)](#testing)
[![CI](https://github.com/Real-Fruit-Snacks/Whirlpool/actions/workflows/ci.yml/badge.svg)](https://github.com/Real-Fruit-Snacks/Whirlpool/actions/workflows/ci.yml)

<br>

Whirlpool is a CLI privilege escalation reasoning engine that parses enumeration output from LinPEAS, WinPEAS, and manual commands, matches findings against offline knowledge bases, and generates ranked, actionable exploitation playbooks. Feed it raw output, get back a prioritized attack plan.

<br>

```
──────────────────────────────── WHIRLPOOL ─────────────────────────────────
                    Privilege Escalation Reasoning Engine

  Hostname    jarvis
  Kernel      4.9.0
  User        www-data

Profile:  DEFAULT   12 paths found | 6 high confidence | 9 low risk

────────────────────────────────── QUICK WINS ──────────────────────────────

╭──────────────────────────────────────────────────────────────────────────╮
│ [1] Sudo systemctl  ████████████████████ 95                              │
│  HIGH    LOW RISK    SUDO                                                │
│ User can run systemctl as root with NOPASSWD                             │
│ Finding: (ALL : ALL) NOPASSWD: /bin/systemctl                            │
│ Note: NOPASSWD                                                           │
╰──────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────╮
│ $ sudo systemctl                                                         │
│ $ !sh                                                                    │
╰──────────────────────────────────────────────────────────────────────────╯

────────────────────────────────────────────────────────────────────────────

╭──────────────────────────────────────────────────────────────────────────╮
│ [2] SUID pkexec  ████████████████░░░░ 82                                 │
│  HIGH    LOW RISK    SUID                                                │
│ Exploit SUID bit on pkexec (CVE-2021-4034)                               │
│ Finding: /usr/bin/pkexec                                                 │
╰──────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────╮
│ $ /usr/bin/pkexec /bin/sh                                                │
╰──────────────────────────────────────────────────────────────────────────╯
```

</div>

<br>

## Table of Contents

- [Highlights](#highlights)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Features](#features)
- [Knowledge Bases](#knowledge-bases)
- [Ranking System](#ranking-system)
- [Python API](#python-api)
- [Testing](#testing)
- [Contributing](#contributing)

---

## Highlights

<table>
<tr>
<td width="50%">

### Auto-Detection
Feed Whirlpool any enumeration file and it figures out the format. Handles LinPEAS `.exe` output (Unicode box headers), `.bat` output (`_-_-_-_->` markers), `.exe` beta format (`[+]` sections), and manual command output — all automatically.

</td>
<td width="50%">

### Offline Knowledge Bases
329 GTFOBins entries, 86 LOLBAS binaries, 42 kernel exploits with version ranges, and 9 potato attacks with OS compatibility matrices. Everything runs locally — no API calls, no internet required.

</td>
</tr>
<tr>
<td width="50%">

### Composite Scoring
Every technique gets a weighted score across four dimensions: reliability (40%), safety (30%), simplicity (20%), and stealth (10%). Five ranking profiles — default, OSCP, CTF, stealth, safe — shift the weights to match your scenario.

</td>
<td width="50%">

### Attack Chain Detection
Detects multi-step privilege escalation paths that single-finding scanners miss: cron PATH hijack, writable cron scripts, Docker/LXD escapes, NFS SUID planting, wildcard injection, LD_PRELOAD abuse, writable /etc/passwd, and more.

</td>
</tr>
<tr>
<td width="50%">

### Noise Filtering
Purpose-built parsers with aggressive false-positive filtering. The sudo parser rejects grep artifacts, version-like patterns, and common non-runas words. Real-world tested against 22 HTB/Vulnhub LinPEAS and WinPEAS samples with zero crashes and zero blank results.

</td>
<td width="50%">

### Multiple Output Formats
Rich terminal output with Catppuccin Mocha theming, Markdown report generation for documentation, and structured JSON export for tool integration. Quick-wins mode surfaces the top 5 highest-probability techniques.

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

| Requirement | Version |
|-------------|---------|
| Python | >= 3.9 |
| pip | any |
| Platform | Linux, macOS, or Windows |

### Install & Run

```bash
git clone https://github.com/Real-Fruit-Snacks/Whirlpool.git
cd Whirlpool
pip install -e .
```

```bash
# Analyze LinPEAS output (auto-detected)
whirlpool linpeas_output.txt

# Analyze WinPEAS output
whirlpool winpeas.txt --type winpeas

# Quick wins only
whirlpool enum.txt --quick-wins

# OSCP-optimized ranking
whirlpool enum.txt --profile oscp

# Export to Markdown
whirlpool enum.txt --format markdown --output report.md

# Export to JSON
whirlpool enum.txt --format json --output results.json

# Filter by confidence and risk
whirlpool enum.txt --min-confidence medium --max-risk medium

# Substitute attacker IP/port into commands
whirlpool enum.txt --lhost 10.10.14.1 --lport 4444

# Compare two scans (diff mode)
whirlpool first_scan.txt --diff second_scan.txt

# Read from stdin / pipe
cat linpeas.txt | whirlpool
whirlpool -

# Filter by category
whirlpool enum.txt --categories suid,sudo,docker

# List knowledge base contents
whirlpool --list-techniques
```

### CLI Reference

```
whirlpool [-h] [-t TYPE] [-f FORMAT] [-o OUTPUT] [-p PROFILE]
          [--categories CAT[,CAT...]] [--quick-wins] [--no-chains]
          [--no-color] [--min-confidence LEVEL] [--max-risk LEVEL]
          [--lhost IP] [--lport PORT] [--diff SECOND_FILE]
          [--list-techniques] [-v] [--version]
          [input]
```

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `input` | file path, `-`, or omit for pipe | | Input file (`-` for stdin, omit when piping) |
| `-t, --type` | `auto`, `linpeas`, `winpeas`, `manual_linux`, `manual_windows` | `auto` | Input format |
| `-f, --format` | `terminal`, `markdown`, `json` | `terminal` | Output format |
| `-o, --output` | file path | stdout | Output file |
| `-p, --profile` | `default`, `oscp`, `ctf`, `stealth`, `safe` | `default` | Ranking profile |
| `--categories` | comma-separated category names | all | Filter to specific categories |
| `--quick-wins` | | | Show top 5 techniques only |
| `--no-chains` | | | Disable multi-step chain detection |
| `--no-color` | | | Plain text output |
| `--min-confidence` | `theoretical`, `low`, `medium`, `high` | | Filter floor |
| `--max-risk` | `low`, `medium`, `high` | | Filter ceiling |
| `--lhost` | IP address | | Substitute ATTACKER_IP/LHOST placeholders |
| `--lport` | port number | | Substitute LPORT/ATTACKER_PORT placeholders |
| `--diff` | file path | | Compare two scans, show new/removed findings |
| `--list-techniques` | | | Print knowledge base summary and exit |
| `-v, --verbose` | | | Verbose diagnostics |

---

## Architecture

Whirlpool follows a three-stage pipeline: **parse** enumeration output into structured data, **analyze** findings against knowledge bases to generate exploitation paths, and **rank** paths using a composite scoring system. No network calls, no subprocess execution, no eval — command strings are output as text for the operator, never executed.

```
whirlpool/
├── cli.py                    # Argparse entry point, auto-detection, output routing
├── parser/
│   ├── linpeas.py            # LinPEAS parser (3 format variants, noise filtering)
│   ├── winpeas.py            # WinPEAS parser (3 format variants, missing patches)
│   ├── manual_linux.py       # Manual Linux command parser (id, sudo -l, getcap, etc.)
│   └── manual_windows.py     # Manual Windows command parser (whoami, systeminfo, etc.)
├── engine/
│   ├── analyzer.py           # Core analysis — matches findings against knowledge bases
│   ├── ranker.py             # Composite scoring with 5 ranking profiles
│   └── chain.py              # Multi-step attack chain detection (12 chain types)
├── data/
│   ├── gtfobins.json         # 329 Unix binaries — SUID, sudo, capabilities, file_read, file_write, shell
│   ├── kernel_exploits.json  # 42 Linux + Windows kernel exploits with version ranges
│   ├── potato_matrix.json    # 9 potato attacks with OS compatibility matrix
│   └── lolbas.json           # 86 Windows LOLBAS binaries and techniques
├── output/
│   ├── terminal.py           # Rich terminal output with Catppuccin Mocha theme
│   ├── markdown.py           # Markdown report generator
│   └── json_out.py           # Structured JSON output
└── __init__.py
```

### Pipeline

```
                    ┌──────────────────────────────────────────┐
  LinPEAS output ──►│                                          │
  WinPEAS output ──►│  Parser         Analyzer        Ranker   │──► Terminal
  Manual commands ──►│  (structured) ──► (paths) ──► (ranked)  │──► Markdown
                    │                                          │──► JSON
                    └──────────────────────────────────────────┘
                              ▲               ▲
                              │               │
                    ANSI stripping    gtfobins.json
                    Section detection  kernel_exploits.json
                    Noise filtering    potato_matrix.json
                    3 format variants  lolbas.json
```

### Parser Format Support

| Parser | Format | Detection Marker |
|--------|--------|-----------------|
| LinPEAS | Standard `.sh` output | `╔══════════╣` section headers |
| WinPEAS | `.exe` output | `═══` Unicode separators |
| WinPEAS | `.bat` output | `_-_-_-_->` ASCII markers, `Host Name:` systeminfo format |
| WinPEAS | `.exe` beta | `[+] Section Name(T1082)` with MITRE ATT&CK IDs |
| Manual Linux | `id`, `sudo -l`, `getcap`, `uname -a`, etc. | `uid=` / `gid=` patterns |
| Manual Windows | `whoami /priv`, `systeminfo`, `sc query`, etc. | `SeImpersonate` / `PRIVILEGES INFORMATION` |

---

## Features

| Feature | Description |
|---------|-------------|
| **Auto-detection** | Identifies input format from content — no `--type` flag needed |
| **LinPEAS parsing** | SUID, SGID, capabilities, sudo, cron, NFS, Docker, kernel version, SSH keys |
| **WinPEAS parsing** | Privileges, services, scheduled tasks, missing patches, user info, network |
| **Sudo noise filtering** | Rejects grep artifacts, version patterns, and common false-positive words |
| **GTFOBins matching** | Matches SUID/sudo/capability binaries against 329 known-exploitable entries (incl. file_read, file_write, shell) |
| **LOLBAS matching** | Matches Windows binaries against 86 living-off-the-land techniques |
| **Kernel exploit matching** | Version-range matching against 42 Linux/Windows kernel CVEs (2015-2025) |
| **Potato attack selection** | OS-aware recommendation from 9 potato variants |
| **Token privilege analysis** | SeBackup, SeDebug, SeLoadDriver, SeRestore, SeTakeOwnership exploitation paths |
| **Credential analysis** | SSH key, password file, and config file detection with exploitation commands |
| **Network service analysis** | Internal-only service detection with port forwarding commands (SSH, chisel, socat) |
| **Writable file analysis** | /etc/passwd, /etc/shadow, /etc/sudoers, /etc/crontab, systemd units exploitation |
| **Group membership analysis** | disk, adm, shadow, staff, video, root, wheel, sudo, admin group exploitation |
| **SGID binary analysis** | Cross-references GTFOBins and flags high-value group ownership |
| **DLL hijacking** | Detects services with writable binary directories on Windows |
| **UAC bypass detection** | fodhelper, eventvwr, sdclt, computerdefaults techniques on medium-integrity Admin |
| **Missing patch mapping** | Maps MS16-032, MS14-058, MS15-051, MS10-059, etc. to exploit commands |
| **AD/Kerberos suggestions** | Kerberoasting, AS-REP Roasting, BloodHound enumeration for domain-joined hosts |
| **Attack chain detection** | 12 multi-step chain types (PATH hijack, Docker escape, NFS plant, etc.) |
| **Composite scoring** | Four-dimension weighted scoring (reliability, safety, simplicity, stealth) |
| **5 ranking profiles** | Default, OSCP, CTF, stealth, safe — each shifts scoring weights |
| **Quick wins** | Surfaces top 5 highest-probability techniques |
| **Catppuccin Mocha theme** | Rich terminal output with semantic color mapping |
| **Markdown reports** | Full analysis report with techniques, commands, and references |
| **JSON export** | Structured output for tool integration and automation |
| **Confidence/risk filtering** | Filter results by confidence floor and risk ceiling |
| **Category filtering** | Filter results to specific categories (suid, sudo, docker, etc.) |
| **Placeholder substitution** | `--lhost`/`--lport` replaces ATTACKER_IP and LPORT in all commands |
| **Diff mode** | Compare two enum scans and show new/removed findings |
| **Stdin/pipe support** | Read from stdin via `-` or auto-detected pipe input |

---

## Knowledge Bases

Whirlpool ships with four offline knowledge bases in `whirlpool/data/`:

| File | Entries | Source | Contents |
|------|---------|--------|----------|
| `gtfobins.json` | 329 binaries | [GTFOBins](https://gtfobins.github.io/) | SUID, sudo, capabilities, file_read, file_write, shell exploitation commands |
| `kernel_exploits.json` | 42 CVEs | Various | 23 Linux + 19 Windows kernel exploits with affected version ranges, commands, reliability ratings |
| `lolbas.json` | 86 binaries | [LOLBAS](https://lolbas-project.github.io/) | Windows living-off-the-land techniques (execute, download, etc.) |
| `potato_matrix.json` | 9 attacks | Various | Potato attack variants with OS compatibility matrix and decision logic |

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
- Missing patch-to-exploit mapping (MS16-032, MS14-058, MS15-051, MS10-059, etc.)
- LOLBAS techniques
- AD/Kerberos suggestions (Kerberoasting, AS-REP Roasting, BloodHound)

---

## Ranking System

Each exploitation path is scored across four dimensions, then combined with profile-specific weights:

| Component | Default | OSCP | CTF | Stealth | Safe |
|-----------|---------|------|-----|---------|------|
| **Reliability** — likelihood of success | 40% | 50% | 50% | 25% | 30% |
| **Safety** — system stability risk | 30% | 25% | 10% | 25% | 50% |
| **Simplicity** — ease of execution | 20% | 20% | 35% | 10% | 15% |
| **Stealth** — detection avoidance | 10% | 5% | 5% | 40% | 5% |

Additional adjustments are applied based on:

- **Category bonuses**: Sudo (+10), SUID (+5), credentials (+10), Docker (+5), writable_file (+10), group (+5), UAC (+5), kernel (-10)
- **Confidence level**: High (+15 reliability, +10 simplicity) down to theoretical (-30, -20)
- **Risk level**: Low (+15 safety, +10 stealth) vs high (-20, -15)

### Profiles

| Profile | Use Case |
|---------|----------|
| `default` | Balanced scoring for general use |
| `oscp` | Prioritizes reliable, documented techniques for exam environments |
| `ctf` | Prioritizes quick wins and speed — get root fast |
| `stealth` | Prioritizes low-detection techniques for red team ops |
| `safe` | Prioritizes system stability — avoid crashing the target |

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

# Score breakdown for a single path
breakdown = ranker.get_score_breakdown(ranked[0])

# Detect multi-step attack chains
detector = ChainDetector()
chains = detector.detect_chains(results)

# Windows analysis
win_parser = WinPEASParser()
win_results = win_parser.parse_file("winpeas_output.txt")
win_paths = analyzer.analyze_windows(win_results)
```

---

## Testing

```bash
pip install -e ".[dev]"

# Run all 237 tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_parsers.py -v

# Run with coverage
python -m pytest tests/ --cov=whirlpool --cov-report=html

# Type checking
mypy whirlpool/

# Linting
ruff check whirlpool/
```

Tests cover parsers (LinPEAS, WinPEAS, manual Linux, manual Windows), the analysis engine, the ranking system, chain detection, all three output formats (including attack chain rendering), edge cases (empty input, malformed data, ANSI-only content), and sudo noise filtering. Real-world validation was performed against 22 HTB/Vulnhub samples (12 LinPEAS, 10 WinPEAS) with zero failures.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run `python -m pytest tests/ -v` — all tests must pass
5. Commit with a descriptive message
6. Open a Pull Request

### Adding Knowledge Base Entries

- **New GTFOBins entry**: Add to `whirlpool/data/gtfobins.json`
- **New kernel exploit**: Add to `whirlpool/data/kernel_exploits.json` with version ranges
- **New potato attack**: Add to `whirlpool/data/potato_matrix.json` with OS compatibility
- **New LOLBAS binary**: Add to `whirlpool/data/lolbas.json`
- **New attack chain**: Add detection method in `whirlpool/engine/chain.py`

### Code Style

- Python 3.9+ type hints throughout
- Dataclasses for structured data
- Pathlib for file operations
- No external dependencies except `rich` for terminal output
- `ruff` for linting, `black` for formatting, `mypy` for type checking

---

<div align="center">

**Built for offense. Designed for clarity.**

[GitHub](https://github.com/Real-Fruit-Snacks/Whirlpool) | [License (MIT)](LICENSE) | [Report Issue](https://github.com/Real-Fruit-Snacks/Whirlpool/issues)

*Whirlpool — privilege escalation reasoning engine*

</div>

---

## Disclaimer

This tool is intended for authorized security testing, CTF competitions, and educational purposes only. Always obtain proper authorization before testing on systems you do not own.
