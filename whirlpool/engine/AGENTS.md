<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-23 | Updated: 2026-02-23 -->

# engine

## Purpose
Core analysis engine that matches parsed enumeration findings against knowledge bases, generates scored exploitation paths, detects multi-step attack chains, and ranks results using configurable composite scoring profiles.

## Key Files

| File | Description |
|------|-------------|
| `__init__.py` | Exports Analyzer, Ranker, ChainDetector |
| `analyzer.py` | Core analysis — defines Category/Confidence/Risk enums, ExploitationPath dataclass, and Analyzer class. `analyze_linux()` matches SUID/sudo/capabilities/cron/docker/NFS/kernel against GTFOBins and kernel_exploits.json. `analyze_windows()` matches services/privileges/scheduled tasks against potato_matrix.json and lolbas.json. Loads JSON data files from `whirlpool/data/` |
| `ranker.py` | Composite scoring engine — RankingProfile enum (DEFAULT, OSCP, CTF, STEALTH, SAFE) with configurable weights across 4 dimensions: reliability (40%), safety (30%), simplicity (20%), stealth (10%). Applies category bonuses, confidence adjustments, and risk adjustments. Supports filtering by min_confidence, max_risk, and categories |
| `chain.py` | Multi-step attack chain detection — ChainStep/AttackChain dataclasses and ChainDetector class with 12 detector methods: PATH hijack via cron, writable cron scripts, Docker escape, LXD escape, NFS SUID planting, writable /etc/passwd, writable /etc/shadow, service hijack, LD_PRELOAD injection, SSH key access, wildcard injection (tar/rsync), sudo PATH injection |

## For AI Agents

### Working In This Directory
- `analyzer.py` is the largest file (~700 lines) — it loads JSON data files at init time from `whirlpool/data/`
- The scoring system uses 4 dimensions (reliability, safety, simplicity, stealth) scored 0-100
- Category enum has 23 values covering both Linux and Windows techniques
- ChainDetector methods use `getattr()` with defaults to safely handle both LinPEAS and WinPEAS result types
- ExploitationPath is the central data type passed between all components

### Testing Requirements
- `python -m pytest tests/test_engine.py -v`
- New techniques need entries in both analyzer.py and the relevant JSON data file
- New chain detectors should be added to `ChainDetector._chain_detectors` list

### Common Patterns
- Enums for all categorical types (Category, Confidence, Risk, RankingProfile)
- Dataclasses with scoring fields and sensible defaults
- `getattr(results, field, default)` pattern in chain detectors for cross-platform safety
- Profile-based weight configuration via dict lookup

## Dependencies

### Internal
- Reads JSON from `whirlpool/data/` (gtfobins.json, kernel_exploits.json, potato_matrix.json, lolbas.json)
- Imports type hints from `whirlpool.parser.linpeas` and `whirlpool.parser.winpeas` (TYPE_CHECKING only)

### External
- `json`, `re`, `logging`, `dataclasses`, `enum`, `pathlib` (stdlib only)

<!-- MANUAL: -->
