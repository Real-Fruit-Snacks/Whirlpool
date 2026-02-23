# Code Review Findings (Round 2)

## MEDIUM (4)

- [x] **1. `re.compile()` inside method bodies recompiled each call** — `linpeas.py:531,572,623`, `manual_linux.py:137,143,148,152`: Hoisted to module-level constants
- [x] **2. `any([...])` uses list instead of generator** — `linpeas.py:692`: Replaced with `or` chain
- [x] **3. Double `.split()` on same line wastes work** — `linpeas.py:745`, `manual_linux.py:162`: Used walrus operator / local variable
- [x] **4. NFS regex `.*` can backtrack on malformed input** — `linpeas.py:44`: Changed to `[^)]*`

## LOW (6)

- [x] **5. `_validate_data` mutates dict in place** — `analyzer.py:148-193`: Rebuilt via new dict instead of del
- [x] **6. `parse_input` silently falls back to LinPEAS for unknown input** — `cli.py:132-134`: Added stderr warning
- [x] **7. `target_info` values not escaped in markdown header** — `markdown.py:107-115`: Applied `_escape_md()` to all values
- [x] **8. `Callable` import inconsistency** — `manual_windows.py:11`: Changed to `collections.abc.Callable`
- [x] **9. Chain detector fallback `'program'` is misleading** — `chain.py:587`: Uses `getattr(sudo, 'raw_line', 'program')` as fallback
- [x] **10. Duck typing via `getattr` instead of Protocol** — `analyzer.py`, `chain.py`, `cli.py`: Informational, no fix needed
