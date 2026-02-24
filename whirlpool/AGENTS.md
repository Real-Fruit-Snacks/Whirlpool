<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-23 | Updated: 2026-02-23 -->

# whirlpool

## Purpose
Main Python package containing the full privilege escalation analysis pipeline: input parsing, technique matching against knowledge bases, composite scoring/ranking, multi-step chain detection, and multi-format output generation.

## Key Files

| File | Description |
|------|-------------|
| `__init__.py` | Package init — exports `__version__` (0.1.0) |
| `cli.py` | Argparse CLI entry point: auto-detects input type, orchestrates parse->analyze->rank->output pipeline, supports diff mode, placeholder substitution (--lhost/--lport), category filtering |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `parser/` | Enumeration output parsers — LinPEAS, WinPEAS, manual Linux/Windows commands (see `parser/AGENTS.md`) |
| `engine/` | Core analysis: technique matching, composite scoring, attack chain detection (see `engine/AGENTS.md`) |
| `knowledge/` | Knowledge base module stubs — actual data lives in `data/` (see `knowledge/AGENTS.md`) |
| `data/` | JSON knowledge bases: GTFOBins, kernel exploits, LOLBAS, potato matrix (see `data/AGENTS.md`) |
| `output/` | Output formatters: Rich terminal, Markdown reports, JSON export (see `output/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- `cli.py` is the main orchestrator — it imports from all subpackages
- Input flow: `read_content()` -> `detect_input_type()` -> `parse_input()` -> `Analyzer` -> `Ranker` -> output formatter
- The `detect_input_type()` function uses content heuristics (keywords, character patterns) to auto-detect LinPEAS vs WinPEAS vs manual
- `_substitute_placeholders()` replaces ATTACKER_IP/LHOST/LPORT in exploitation commands using word-boundary regex
- `_diff_paths()` compares two scan results by (technique_name, finding) tuples

### Testing Requirements
- CLI tests: `python -m pytest tests/test_cli.py -v`
- Integration test against sample data: `whirlpool tests/sample_data/linpeas_sample.txt`

### Common Patterns
- Lazy imports of heavy modules (Analyzer, output formatters) inside `main()` to speed up `--help`
- Multiple encoding fallback when reading input files (utf-8 -> utf-16 -> latin-1 -> cp1252)
- 100MB file size guard on input

## Dependencies

### Internal
- `parser/` — All parser classes
- `engine/` — Analyzer, Ranker, ChainDetector
- `output/` — All output formatters

### External
- `argparse`, `json`, `re`, `sys`, `pathlib` (stdlib)

<!-- MANUAL: -->
