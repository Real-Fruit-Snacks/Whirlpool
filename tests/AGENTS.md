<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-23 | Updated: 2026-02-23 -->

# tests

## Purpose
Pytest test suite covering parsers, analysis engine, knowledge bases, output formatters, CLI behavior, and real-world enumeration sample validation.

## Key Files

| File | Description |
|------|-------------|
| `__init__.py` | Test package marker |
| `test_parsers.py` | LinPEAS and WinPEAS parser unit tests |
| `test_parser_edge_cases.py` | Edge case and regression tests for parsers |
| `test_engine.py` | Analyzer and ranking engine tests |
| `test_knowledge.py` | Knowledge base data integrity tests (JSON validity, required fields) |
| `test_output.py` | Terminal, Markdown, and JSON output formatter tests |
| `test_cli.py` | CLI argument parsing, input detection, end-to-end pipeline tests |
| `test_sample_data.py` | Validates parsing against real-world enumeration samples |
| `test_version_range.py` | Kernel version range comparison tests |
| `test_windows_analysis.py` | Windows-specific analysis tests (potato attacks, token privileges, services) |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `sample_data/` | LinPEAS/WinPEAS sample output files for testing (see `sample_data/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Run all tests: `python -m pytest tests/ -v`
- Run single file: `python -m pytest tests/test_parsers.py -v`
- Coverage: `python -m pytest tests/ --cov=whirlpool --cov-report=html`
- Config in `pyproject.toml` under `[tool.pytest.ini_options]`: testpaths=tests, addopts="-v --tb=short"

### Testing Requirements
- All tests must pass before merging
- New parser features need corresponding tests with sample data
- New analysis techniques need test coverage

### Common Patterns
- Tests import directly from `whirlpool.*` subpackages
- Sample data files in `sample_data/` provide realistic LinPEAS/WinPEAS output
- Real-world samples in `sample_data/real_world/` from actual HTB/CTF machines

## Dependencies

### Internal
- All `whirlpool.*` subpackages

### External
- `pytest>=7.0.0`
- `pytest-cov>=4.0.0`

<!-- MANUAL: -->
