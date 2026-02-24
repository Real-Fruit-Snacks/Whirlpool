<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-23 | Updated: 2026-02-23 -->

# real_world

## Purpose
Real enumeration output captures from HackTheBox and CTF machines, used for regression testing and validating parser accuracy against genuine tool output.

## Key Files

| File | Description |
|------|-------------|
| `linpeas_admirer.txt` | LinPEAS output from HTB Admirer |
| `linpeas_blunder.txt` | LinPEAS output from HTB Blunder |
| `linpeas_book.txt` | LinPEAS output from HTB Book |
| `linpeas_devoops.txt` | LinPEAS output from HTB DevOops |
| `linpeas_fristileaks.txt` | LinPEAS output from VulnHub FristiLeaks |
| `linpeas_hawk.txt` | LinPEAS output from HTB Hawk |
| `linpeas_jarvis.txt` | LinPEAS output from HTB Jarvis |
| `linpeas_magic.txt` | LinPEAS output from HTB Magic |
| `linpeas_mango.txt` | LinPEAS output from HTB Mango |
| `linpeas_sneakymailer.txt` | LinPEAS output from HTB SneakyMailer |
| `linpeas_tabby.txt` | LinPEAS output from HTB Tabby |
| `linpeas_waldo.txt` | LinPEAS output from HTB Waldo |
| `winpeas_arctic.txt` | WinPEAS output from HTB Arctic |
| `winpeas_cascade.txt` | WinPEAS output from HTB Cascade |
| `winpeas_chatterbox.txt` | WinPEAS output from HTB Chatterbox |
| `winpeas_control.txt` | WinPEAS output from HTB Control |
| `winpeas_devel.txt` | WinPEAS output from HTB Devel |
| `winpeas_jeeves.txt` | WinPEAS output from HTB Jeeves |
| `winpeas_optimum.txt` | WinPEAS output from HTB Optimum |
| `winpeas_remote.txt` | WinPEAS output from HTB Remote |
| `winpeas_secnotes.txt` | WinPEAS output from HTB SecNotes |
| `winpeas_silo.txt` | WinPEAS output from HTB Silo |

## For AI Agents

### Working In This Directory
- 12 Linux samples + 10 Windows samples from real machines
- Used by `tests/test_sample_data.py` for regression testing
- Files contain raw tool output with ANSI escape codes, Unicode box-drawing characters
- Useful for testing parser robustness against varied output formats and edge cases

### Testing Requirements
- Adding a new sample: also add a test case in `tests/test_sample_data.py`
- Parsers should not crash on any real-world sample (even if extraction is incomplete)

<!-- MANUAL: -->
