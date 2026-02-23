# Code Review Findings (Round 3)

## CRITICAL (1)

- [x] **1. Placeholder substitution corrupts `LHOST=` in commands** — `cli.py:212-213,236-237`: `cmd.replace('LHOST', lhost)` turns `LHOST=ATTACKER_IP` into `10.10.14.1=10.10.14.1`. Use `re.sub` with word boundaries.

## HIGH (3)

- [x] **2. `_analyze_groups` uses `Category.DOCKER` instead of `Category.GROUP`** — `analyzer.py:1812`: Wrong category for group membership findings.
- [x] **3. New Category enums defined but never used** — `analyzer.py`: `Category.NETWORK` unused in `_analyze_network_services` (uses CREDENTIALS), `Category.UAC` unused in `_analyze_uac` (uses REGISTRY), `Category.DLL` unused in `_analyze_dll_hijack` (uses SERVICE).
- [x] **4. Operator precedence bug in `--lhost`/`--lport` guard** — `cli.py:522`: `if lhost or lport is not None:` should be `if lhost is not None or lport is not None:`.

## MEDIUM (4)

- [x] **5. Inconsistent placeholder `PORT` vs `LPORT` in cron commands** — `analyzer.py:582,1514`: Uses `PORT` while all other commands use `LPORT`.
- [x] **6. Hardcoded port `4444` bypasses `--lport` substitution** — `analyzer.py:1259,1856,1920,1961`: Should use `LPORT` placeholder.
- [x] **7. `_analyze_sgid` uses `Category.SUID` for SGID findings** — `analyzer.py:1650,1669`: SGID findings should use `Category.SUID` with SGID note (no separate enum needed, but technique names already say "SGID").
- [x] **8. `_diff_paths` comparison uses only `technique_name`** — `cli.py:256-257`: Should use composite key `(technique_name, finding)` to distinguish same technique on different binaries.

## LOW (2)

- [x] **9. Token privilege paths use `Category.POTATO` for non-potato techniques** — `analyzer.py:969,994,1017,1042,1067`: SeBackup/SeDebug/etc. should use `Category.TOKEN`.
- [x] **10. Large method size and code duplication** — Informational, no fix needed.
