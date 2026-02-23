# Code Review Findings

## HIGH (2)

- [x] **1. Bidirectional substring matching in Windows kernel exploit matching** — `analyzer.py:957-961`: `_analyze_kernel_windows` uses `os_version.lower() in ver.lower()` which false-matches short OS strings against every entry
- [x] **2. `read_content` passes `None` to `Path()`** — `cli.py:77`: `Path(None)` raises `TypeError` in Python 3.12+

## MEDIUM (7)

- [x] **3. `Category.LOLBAS` missing from terminal output mappings** — `terminal.py:83-123`: No icon or color for LOLBAS category
- [x] **4. `Category.LOLBAS` missing from `CATEGORY_RELIABILITY_BONUS`** — `ranker.py:68-77`: No scoring adjustment for LOLBAS
- [x] **5. Bare `except Exception` swallows `MemoryError`/`RecursionError`** — `cli.py:483`: Should re-raise fatal exceptions
- [x] **6. No input size limit on file/stdin reads** — `cli.py:75,81`: Unbounded memory allocation on large files
- [x] **7. ANSI regex `.*?` can cause slowdowns** — `linpeas.py:13`, `winpeas.py:13`: Minor ReDoS on crafted input
- [x] **8. `_analyze_tokens` accesses `.name` directly** — `analyzer.py:801`: Inconsistent with defensive `getattr` elsewhere
- [x] **9. Markdown output doesn't escape user content** — `markdown.py:191`: Finding names could inject markdown

## LOW (5)

- [x] **10. Parsers not reusable** — State not reset between `parse()` calls
- [x] **11. Duplicate groups in `_parse_user_info`** — `linpeas.py:468-476`: Groups appended without dedup check
- [x] **12. `write_text()` missing `encoding='utf-8'`** — `markdown.py:83`, `json_out.py:122`, `cli.py:461,473`
- [x] **13. f-strings in logging prevent lazy formatting** — `chain.py:87`, `manual_linux.py:382`, `manual_windows.py:342`
- [x] **14. `parse_crontab` skips `@reboot`/`@daily` entries** — `manual_linux.py:120-174`: Only handles 5-field format
