<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-23 | Updated: 2026-02-23 -->

# parser

## Purpose
Parsers that extract structured data from enumeration tool output (LinPEAS, WinPEAS) and manual command output. Each parser strips ANSI codes, identifies sections via regex, and returns typed dataclass result objects.

## Key Files

| File | Description |
|------|-------------|
| `__init__.py` | Exports all four parser classes |
| `linpeas.py` | LinPEAS output parser — extracts SUID binaries, sudo rights, capabilities, cron jobs, Docker info, NFS shares, network services, writable files, SSH keys, user info, kernel version. Returns `LinPEASResults` dataclass. Also handles raw text via `_extract_from_all_lines()` for manual input |
| `winpeas.py` | WinPEAS output parser — extracts services, scheduled tasks, token privileges, registry keys, user info, OS version, installed patches, credentials. Returns `WinPEASResults` dataclass. Handles both .bat (`_-_-_-_->`) and .exe (`═══`) format markers |
| `manual_linux.py` | Manual Linux command parser — parses individual command outputs (id, sudo -l, crontab, netstat, find SUID, etc.) into `LinPEASResults`. Uses structured dict input with command name keys |
| `manual_windows.py` | Manual Windows command parser — parses whoami, whoami /priv, systeminfo, sc query, schtasks, etc. into `WinPEASResults`. Uses structured dict input with command name keys |

## For AI Agents

### Working In This Directory
- All parsers return dataclass result objects (`LinPEASResults` or `WinPEASResults`)
- ANSI stripping is the first step in all parsers (`ANSI_PATTERN` regex)
- LinPEAS/WinPEAS parsers work on full tool output text blobs
- Manual parsers expect `dict[str, str]` mapping command names to their output
- The CLI routes `manual_linux`/`manual_windows` input types through LinPEAS/WinPEAS parsers respectively (via `_extract_from_all_lines()`)

### Testing Requirements
- `python -m pytest tests/test_parsers.py tests/test_parser_edge_cases.py -v`
- Test against sample data in `tests/sample_data/`
- New extraction patterns need test cases with representative output snippets

### Common Patterns
- Module-level compiled regex patterns (prefixed with `_`) for performance
- Dataclass result containers with sensible defaults (empty lists, empty strings)
- Section-based parsing: identify section headers, then parse content within each section
- `frozenset` for noise/exclusion word lists

## Dependencies

### Internal
- `linpeas.py` dataclasses are imported by `manual_linux.py` (SUIDEntry, SudoEntry, etc.)
- `winpeas.py` dataclasses are imported by `manual_windows.py` (ServiceInfo, TokenPrivilege, etc.)

### External
- `re`, `dataclasses`, `pathlib` (stdlib only)

<!-- MANUAL: -->
