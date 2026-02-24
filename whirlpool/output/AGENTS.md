<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-23 | Updated: 2026-02-23 -->

# output

## Purpose
Output formatters that render analysis results in three formats: Rich terminal with Catppuccin Mocha theme, Markdown for OSCP reports and CTF writeups, and JSON for programmatic consumption.

## Key Files

| File | Description |
|------|-------------|
| `__init__.py` | Exports TerminalOutput, MarkdownOutput, JSONOutput |
| `terminal.py` | Rich library terminal output — Catppuccin Mocha color theme, bordered section panels, score badges, confidence/risk pills, command blocks. Methods: `print_header()`, `print_quick_wins()`, `print_all_paths()`, `print_chains()`, `print_summary()`. Graceful fallback if Rich is not installed |
| `markdown.py` | Markdown report generator — table of contents, target info, quick wins, full technique details, attack chains. Includes `_escape_md()` for safe user-derived text. Suitable for OSCP exam reports |
| `json_out.py` | JSON output — structured dict with metadata, target_info, quick_wins, all paths with score breakdowns, attack chains. Methods: `generate()` returns dict, `to_json()` returns formatted string |

## For AI Agents

### Working In This Directory
- `terminal.py` has a `RICH_AVAILABLE` guard — falls back to plain text if Rich is not installed
- All three formatters instantiate their own `Ranker()` for scoring
- The Catppuccin Mocha palette is defined as a dict in `terminal.py` (`MOCHA`)
- Markdown output escapes special characters to prevent injection via finding text
- JSON output includes both `generate()` (returns dict) and `to_json()` (returns string) methods

### Testing Requirements
- `python -m pytest tests/test_output.py -v`
- Test both with and without Rich installed for terminal output

### Common Patterns
- Each formatter class follows the same interface pattern: constructor, then `generate()` or `print_*()` methods
- All formatters accept `paths: list[ExploitationPath]`, optional `chains`, optional `target_info`
- Import from `..engine.analyzer` and `..engine.ranker` for types and scoring

## Dependencies

### Internal
- `whirlpool.engine.analyzer` — ExploitationPath, Category, Confidence, Risk
- `whirlpool.engine.ranker` — Ranker
- `whirlpool.engine.chain` — AttackChain (markdown, json_out)
- `whirlpool.__version__` (terminal, json_out)

### External
- `rich>=13.0.0` — Terminal output (optional at runtime, graceful fallback)
- `json`, `re`, `datetime`, `pathlib` (stdlib)

<!-- MANUAL: -->
