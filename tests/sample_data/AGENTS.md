<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-23 | Updated: 2026-02-23 -->

# sample_data

## Purpose
Sample enumeration output files used for testing parsers and the full analysis pipeline. Contains both synthetic samples and real-world captures from HackTheBox/CTF machines.

## Key Files

| File | Description |
|------|-------------|
| `linpeas_sample.txt` | Synthetic LinPEAS output for Linux parser testing |
| `winpeas_sample.txt` | Synthetic WinPEAS output for Windows parser testing |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `real_world/` | Real enumeration captures from HTB/CTF machines (see `real_world/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Sample files are used by `tests/test_sample_data.py` and `tests/test_parsers.py`
- CLI integration tests reference these files: `whirlpool tests/sample_data/linpeas_sample.txt`
- When adding new parser features, add representative output snippets to existing samples or create new sample files

### Common Patterns
- Files contain raw tool output including ANSI escape codes
- Real-world samples provide regression testing against actual enumeration data

<!-- MANUAL: -->
