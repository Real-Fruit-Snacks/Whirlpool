<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-23 | Updated: 2026-02-23 -->

# data

## Purpose
JSON knowledge base files containing privilege escalation technique databases. Loaded by `whirlpool.engine.analyzer` at initialization time and matched against parsed enumeration findings.

## Key Files

| File | Description |
|------|-------------|
| `gtfobins.json` | GTFOBins database — binary name -> techniques (suid, sudo, capabilities). Each technique has commands and description. Source: https://gtfobins.github.io/ |
| `kernel_exploits.json` | Kernel exploit database — CVE -> exploit info with affected_versions (min, max), reliability, risk, commands, references. Separate sections for `linux` and `windows` |
| `potato_matrix.json` | Windows potato attack database — attack name -> OS compatibility matrix, required privileges, commands. Covers SeImpersonate/SeAssignPrimaryToken exploits |
| `lolbas.json` | LOLBAS database — binary/script name -> techniques (execute, download, etc.). Separate `binaries` and `scripts` sections. Source: https://lolbas-project.github.io/ |

## For AI Agents

### Working In This Directory
- These are pure data files — no code logic
- Bundled into the Python package via `[tool.setuptools.package-data]` in pyproject.toml
- Loaded by `Analyzer.__init__()` using `Path(__file__).parent / 'data'` resolution
- Also loaded by `cli.py:list_techniques()` for the `--list-techniques` summary
- All files must be valid JSON

### Testing Requirements
- `python -m pytest tests/test_knowledge.py -v` validates JSON structure and required fields
- After modifying any JSON file, run knowledge tests to verify data integrity

### Common Patterns
- Top-level key is a category (`binaries`, `linux`, `windows`, `attacks`, `scripts`)
- Each entry maps a technique/binary/CVE name to its metadata dict
- Version ranges use `min`/`max` string fields for kernel exploit matching

## Dependencies

### Internal
- Consumed by `whirlpool.engine.analyzer`
- Referenced by `whirlpool.cli:list_techniques()`

<!-- MANUAL: -->
