# Whirlpool Improvements Tracker

## Must Fix (Bugs)

- [x] **1. CLI manual parser routing broken** — Fixed comment to accurately explain design decision (LinPEAS/WinPEAS parsers are correct for raw text blobs; ManualParsers need structured command dicts). Also fixed WinPEAS detection order in `detect_input_type()`.
- [x] **2. Dead code in chain detector** — Fixed `_detect_sudo_path_injection()` to assign `getattr()` result and iterate over sudo rights looking for relative-path commands.
- [x] **3. Baron Samedit (CVE-2021-3156) never matches** — Normalized `sudo_min`/`sudo_max` to `min`/`max` in kernel_exploits.json, added `check_command` and `note` fields.
- [x] **4. Kernel version suffix handling broken** — `_version_in_range()` now splits components on `-` and takes only the leading numeric token (`5.4.0-42-generic` -> `(5, 4, 0)`).
- [x] **5. LOLBAS data loaded but never analyzed** — Added `_analyze_lolbas()` method + `Category.LOLBAS` enum value, wired into `analyze_windows()`.

## Should Fix (Robustness)

- [x] **6. Potato OS matching uses unreliable substring matching** — New `_potato_os_compatible()` method uses regex token extraction for server year/desktop version matching.
- [x] **7. icacls parser skips same-line path+permissions** — Removed `continue` after path extraction so same-line permissions are checked.
- [x] **8. Manual `parse_crontab` only handles system format** — Two-pattern approach: system format (5 fields + user + command) and user format (5 fields + command), with heuristic username detection.
- [x] **9. No stdin/pipe support** — CLI now accepts `-` for explicit stdin and auto-detects piped input via `sys.stdin.isatty()`.

## Test Coverage Gaps

- [x] **10. 22 real-world sample files unused in tests** — Parametrized smoke tests for all sample files in `test_sample_data.py` (57 tests).
- [x] **11. Zero CLI integration tests** — 31 tests in `test_cli.py` covering all flags, formats, filters, error handling.
- [x] **12. Zero Windows analysis tests** — 16 tests in `test_windows_analysis.py` covering SeImpersonate, unquoted paths, AlwaysInstallElevated, kernel matching.
- [x] **13. No kernel version matching tests** — 26 tests in `test_version_range.py` covering boundaries, suffixes, malformed input.

## Data Gaps

- [x] **14. GTFOBins ~50% coverage** — Expanded from 206 to 329 binaries (+83 new, +18 new techniques on existing entries).
- [x] **15. Kernel exploits missing 2024-2025 CVEs** — Added 5 Linux + 5 Windows CVEs from 2023-2025 (now 23 Linux, 19 Windows).
- [x] **16. LOLBAS only 40 of 100+ entries** — Expanded from 39 to 86 entries (+47 new).
- [x] **17. Knowledge modules are empty placeholders** — Updated docstrings to accurately reference `engine/analyzer.py` as the analysis location.

## Nice to Have

- [x] **18. `--categories` filter flag** — Added `--categories suid,sudo,...` with validation against Category enum values.
- [x] **19. `--list-techniques` command** — Added `--list-techniques` that prints knowledge base summary and exits (input file optional).
- [x] **20. Single version source of truth** — `__init__.py` is now the source; `json_out.py` imports it, `pyproject.toml` uses `dynamic = ["version"]`.
- [x] **21. Knowledge base schema validation** — `_validate_data()` runs at load time, logs warnings for invalid entries instead of runtime crashes.

---

## Feature Additions (Round 2)

### Critical — Parsed data being silently ignored

- [x] **22. Credential/password file analysis** — Added `_analyze_credentials_linux()` with SSH key, password file, and config file detection. Generates `ssh -i`, `su`, `mysql` commands.
- [x] **23. Network service analysis** — Added `_analyze_network_services()` to flag internal-only services (MySQL, PostgreSQL, Redis, MongoDB, web panels) with SSH/chisel/socat port forwarding commands.
- [x] **24. Writable sensitive file analysis** — Added `_analyze_writable_files()` for `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/crontab`, systemd units, root's `.bashrc`/`.profile` with exact exploitation commands.
- [x] **25. SGID binary analysis** — Added `_analyze_sgid()` cross-referencing GTFOBins and flagging high-value groups (`shadow`, `disk`, `adm`, `video`).
- [x] **26. Sudo edge cases** — Expanded `_analyze_sudo()` with LD_PRELOAD env_keep detection, wildcard rule abuse, and argument-escape binary detection (vim, less, man, more, etc.).
- [x] **27. DLL hijacking analysis (Windows)** — Added `_analyze_dll_hijack()` to identify services with writable binary directories and generate MSFvenom DLL commands.

### Important — Significantly improve usefulness

- [x] **28. Expanded token privilege analysis (Windows)** — Expanded `_analyze_tokens()` with SeBackupPrivilege, SeDebugPrivilege, SeLoadDriverPrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege exploitation paths.
- [x] **29. GTFOBins file-read/file-write/shell techniques** — Added `file_read`, `file_write`, and `shell` technique categories to 39 high-priority binaries in gtfobins.json.
- [x] **30. Dangerous group analysis** — Added `_analyze_groups()` for `disk`, `adm`, `shadow`, `staff`, `video`, `root`, `wheel`, `sudo`, `admin` groups with specific exploitation commands.
- [x] **31. Windows missing-patch-to-exploit mapping** — Added `_analyze_missing_patches()` mapping MS16-032, MS14-058, MS15-051, MS10-059, MS16-075, MS10-015, MS11-046, MS09-012 to exploit commands.
- [x] **32. `--lhost`/`--lport` command substitution** — Added `--lhost` and `--lport` CLI flags with placeholder substitution in paths and chain steps.

### Nice to Have

- [x] **33. UAC bypass detection (Windows)** — Added `_analyze_uac()` detecting medium-integrity Admin and suggesting fodhelper, eventvwr, sdclt, computerdefaults bypass techniques.
- [x] **34. Diff mode** — Added `--diff SECOND_FILE` to compare two enum scans and show new/removed findings.
- [x] **35. AD/Kerberos suggestions** — Added `_analyze_ad_kerberos()` with Kerberoasting, AS-REP Roasting, and BloodHound enumeration when `domain_joined` is True.
- [x] **36. Port forwarding command templates** — Network service analysis generates SSH local forward, chisel, and socat commands with proper syntax.
