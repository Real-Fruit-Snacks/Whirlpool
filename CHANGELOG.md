# Changelog

All notable changes to Whirlpool will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-04

### Added
- LinPEAS parser with 3 format variants (Unicode box, legacy, minimal)
- WinPEAS parser with 3 format variants (.exe, .bat, .exe beta)
- Manual Linux and Windows command parsers
- Core analysis engine matching findings against knowledge bases
- Composite scoring system with 4 dimensions (reliability, safety, simplicity, stealth)
- 5 ranking profiles (default, OSCP, CTF, stealth, safe)
- Multi-step attack chain detection (12 chain types)
- GTFOBins knowledge base (329 entries)
- LOLBAS knowledge base (86 entries)
- Kernel exploit database (42 CVEs with version ranges)
- Potato attack matrix (9 attacks with OS compatibility)
- Rich terminal output with Catppuccin Mocha theming
- Markdown report generation
- Structured JSON export
- Quick wins mode (top 5 techniques)
- Diff mode for comparing two scans
- Stdin/pipe support
- Auto-detection of input format
- Aggressive noise filtering for sudo parser
- Category and confidence filtering
- Attacker IP/port placeholder substitution (--lhost, --lport)
