<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-23 | Updated: 2026-02-23 -->

# knowledge

## Purpose
Knowledge base module stubs for platform-specific privilege escalation techniques. Analysis logic is implemented in `whirlpool.engine.analyzer`; actual data files live in `whirlpool/data/`. These modules serve as extension points for future platform-specific analysis code.

## Key Files

| File | Description |
|------|-------------|
| `__init__.py` | Package docstring pointing to analyzer and data directories |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `linux/` | Linux-specific knowledge module stub (see `linux/AGENTS.md`) |
| `windows/` | Windows-specific knowledge module stub (see `windows/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Currently contains only `__init__.py` stubs with docstrings
- Future platform-specific analysis code should go here
- The actual knowledge base data is in `whirlpool/data/*.json`
- Analysis logic that consumes the data is in `whirlpool/engine/analyzer.py`

### Common Patterns
- Extension point architecture — add new analysis modules here as the project grows

<!-- MANUAL: -->
