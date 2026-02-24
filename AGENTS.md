<!-- Generated: 2026-02-23 | Updated: 2026-02-23 -->

# Whirlpool

## Purpose
A Python CLI privilege escalation reasoning engine that parses enumeration output (LinPEAS, WinPEAS, manual commands), matches findings against knowledge bases (GTFOBins, kernel exploits, LOLBAS, potato attacks), and generates ranked, actionable exploitation playbooks for penetration testing and CTF scenarios.

## Key Files

| File | Description |
|------|-------------|
| `pyproject.toml` | Project config: dependencies (rich), dev tools (pytest, black, ruff, mypy), CLI entry point |
| `CLAUDE.md` | AI agent instructions, dev commands, architecture reference |
| `README.md` | User-facing documentation |
| `LICENSE` | MIT license |
| `.gitignore` | Git ignore rules |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `whirlpool/` | Main Python package — parsers, analysis engine, knowledge bases, output formatters (see `whirlpool/AGENTS.md`) |
| `tests/` | Pytest test suite with sample enumeration data (see `tests/AGENTS.md`) |
| `docs/` | Landing page and banner assets (see `docs/AGENTS.md`) |
| `.github/` | CI/CD workflows (ci.yml, pages.yml) |

## For AI Agents

### Working In This Directory
- Python 3.9+ required; only external runtime dependency is `rich`
- Install dev mode: `pip install -e .`
- CLI entry point: `whirlpool.cli:main` (registered as `whirlpool` console script)
- All data files are JSON in `whirlpool/data/` — bundled via `setuptools.package-data`

### Testing Requirements
- Run all tests: `python -m pytest tests/ -v`
- Coverage: `python -m pytest tests/ --cov=whirlpool --cov-report=html`
- Type checking: `mypy whirlpool/`
- Linting: `ruff check whirlpool/`
- Formatting: `black whirlpool/`

### Common Patterns
- Dataclasses for all structured data (SUIDEntry, ExploitationPath, AttackChain, etc.)
- `pathlib.Path` for file operations
- Type hints throughout (Python 3.9+ style with `from __future__ import annotations`)
- `from __future__ import annotations` in every module for PEP 604 union syntax

## Dependencies

### External
- `rich>=13.0.0` — Terminal output formatting (colors, tables, panels)
- `pytest`, `black`, `ruff`, `mypy` — Dev-only tooling

<!-- MANUAL: -->
