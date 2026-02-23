"""Integration tests for the CLI main() function and detect_input_type()."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from whirlpool.cli import detect_input_type, main


# Resolve sample data paths relative to this file so tests work regardless of cwd
_TESTS_DIR = Path(__file__).parent
_SAMPLE_DIR = _TESTS_DIR / "sample_data"
_LINPEAS_SAMPLE = str(_SAMPLE_DIR / "linpeas_sample.txt")
_WINPEAS_SAMPLE = str(_SAMPLE_DIR / "winpeas_sample.txt")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _run_main(args: list[str], capsys) -> tuple[int, str, str]:
    """Run main() and return (exit_code, stdout, stderr)."""
    code = main(args)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ---------------------------------------------------------------------------
# Basic invocations
# ---------------------------------------------------------------------------

class TestMainBasicInvocations:

    def test_main_with_linpeas_sample(self, capsys) -> None:
        """main() with a LinPEAS sample exits 0."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        code, out, err = _run_main([_LINPEAS_SAMPLE], capsys)
        assert code == 0

    def test_main_with_winpeas_sample(self, capsys) -> None:
        """main() with a WinPEAS sample exits 0."""
        if not Path(_WINPEAS_SAMPLE).exists():
            pytest.skip("winpeas_sample.txt not present")

        code, out, err = _run_main([_WINPEAS_SAMPLE], capsys)
        assert code == 0

    def test_main_with_type_override(self, capsys) -> None:
        """main() with explicit --type linpeas exits 0."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        code, out, err = _run_main([_LINPEAS_SAMPLE, "--type", "linpeas"], capsys)
        assert code == 0

    def test_main_no_color(self, capsys) -> None:
        """main() with --no-color exits 0."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        code, out, err = _run_main([_LINPEAS_SAMPLE, "--no-color"], capsys)
        assert code == 0

    def test_main_verbose(self, capsys) -> None:
        """main() with --verbose exits 0 and emits verbose info to stderr."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        code, out, err = _run_main([_LINPEAS_SAMPLE, "--verbose"], capsys)
        assert code == 0
        # Verbose mode prints platform info to stderr
        assert "platform" in err.lower() or "parsing" in err.lower()


# ---------------------------------------------------------------------------
# Output format tests
# ---------------------------------------------------------------------------

class TestMainOutputFormats:

    def test_main_format_json(self, capsys) -> None:
        """--format json produces valid JSON on stdout."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        code, out, err = _run_main([_LINPEAS_SAMPLE, "--format", "json"], capsys)
        assert code == 0
        # Output should be valid JSON
        parsed = json.loads(out)
        assert isinstance(parsed, dict)

    def test_main_format_markdown(self, capsys) -> None:
        """--format markdown produces output with markdown headers."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        code, out, err = _run_main([_LINPEAS_SAMPLE, "--format", "markdown"], capsys)
        assert code == 0
        # Markdown output should contain at least one header
        assert "#" in out

    def test_main_output_file(self, capsys, tmp_path) -> None:
        """--output writes file content and the file exists with non-empty content."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        out_file = tmp_path / "report.md"
        code, out, err = _run_main(
            [_LINPEAS_SAMPLE, "--format", "markdown", "--output", str(out_file)],
            capsys,
        )
        assert code == 0
        assert out_file.exists(), "Output file was not created"
        content = out_file.read_text(encoding="utf-8")
        assert len(content) > 0, "Output file is empty"

    def test_main_output_file_json(self, capsys, tmp_path) -> None:
        """--output with --format json writes valid JSON to file."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        out_file = tmp_path / "report.json"
        code, out, err = _run_main(
            [_LINPEAS_SAMPLE, "--format", "json", "--output", str(out_file)],
            capsys,
        )
        assert code == 0
        assert out_file.exists()
        parsed = json.loads(out_file.read_text(encoding="utf-8"))
        assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# Filtering and profile tests
# ---------------------------------------------------------------------------

class TestMainFilters:

    def test_main_quick_wins(self, capsys) -> None:
        """--quick-wins flag runs without error."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        code, out, err = _run_main([_LINPEAS_SAMPLE, "--quick-wins"], capsys)
        assert code == 0

    def test_main_profile_oscp(self, capsys) -> None:
        """--profile oscp exits 0."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        code, out, err = _run_main([_LINPEAS_SAMPLE, "--profile", "oscp"], capsys)
        assert code == 0

    def test_main_profile_ctf(self, capsys) -> None:
        """--profile ctf exits 0."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        code, out, err = _run_main([_LINPEAS_SAMPLE, "--profile", "ctf"], capsys)
        assert code == 0

    def test_main_profile_stealth(self, capsys) -> None:
        """--profile stealth exits 0."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        code, out, err = _run_main([_LINPEAS_SAMPLE, "--profile", "stealth"], capsys)
        assert code == 0

    def test_main_profile_safe(self, capsys) -> None:
        """--profile safe exits 0."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        code, out, err = _run_main([_LINPEAS_SAMPLE, "--profile", "safe"], capsys)
        assert code == 0

    def test_main_min_confidence_high(self, capsys) -> None:
        """--min-confidence high exits 0."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        code, out, err = _run_main(
            [_LINPEAS_SAMPLE, "--min-confidence", "high"], capsys
        )
        assert code == 0

    def test_main_min_confidence_medium(self, capsys) -> None:
        """--min-confidence medium exits 0."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        code, out, err = _run_main(
            [_LINPEAS_SAMPLE, "--min-confidence", "medium"], capsys
        )
        assert code == 0

    def test_main_max_risk_low(self, capsys) -> None:
        """--max-risk low exits 0."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        code, out, err = _run_main([_LINPEAS_SAMPLE, "--max-risk", "low"], capsys)
        assert code == 0

    def test_main_max_risk_medium(self, capsys) -> None:
        """--max-risk medium exits 0."""
        if not Path(_LINPEAS_SAMPLE).exists():
            pytest.skip("linpeas_sample.txt not present")

        code, out, err = _run_main([_LINPEAS_SAMPLE, "--max-risk", "medium"], capsys)
        assert code == 0


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

class TestMainErrorCases:

    def test_main_missing_file(self, capsys) -> None:
        """Non-existent input file returns exit code 1."""
        code, out, err = _run_main(["/nonexistent/path/file.txt"], capsys)
        assert code == 1
        assert "not found" in err.lower() or "error" in err.lower()

    def test_main_not_a_file(self, capsys, tmp_path) -> None:
        """Passing a directory as input returns exit code 1."""
        code, out, err = _run_main([str(tmp_path)], capsys)
        assert code == 1
        assert "not a file" in err.lower() or "error" in err.lower()


# ---------------------------------------------------------------------------
# detect_input_type() unit tests
# ---------------------------------------------------------------------------

class TestDetectInputType:

    def test_detect_input_type_linpeas(self) -> None:
        """Content with LinPEAS markers is detected as linpeas."""
        content = "linpeas output\n╔══════════╣ Basic information\nuid=1000(user)"
        assert detect_input_type(content) == "linpeas"

    def test_detect_input_type_linpeas_by_name(self) -> None:
        """Content mentioning 'linpeas' is detected as linpeas."""
        content = "# linpeas.sh\nSome output here"
        assert detect_input_type(content) == "linpeas"

    def test_detect_input_type_winpeas(self) -> None:
        """Content with WinPEAS markers is detected as winpeas."""
        content = "winpeas output\nSeImpersonatePrivilege Enabled"
        assert detect_input_type(content) == "winpeas"

    def test_detect_input_type_winpeas_by_name(self) -> None:
        """Content mentioning 'winpeas' is detected as winpeas."""
        content = "winpeas.exe output\nsome windows stuff"
        assert detect_input_type(content) == "winpeas"

    def test_detect_input_type_manual_linux(self) -> None:
        """Content with uid=/gid= patterns is detected as manual_linux."""
        content = "uid=1000(user) gid=1000(user) groups=1000(user)"
        assert detect_input_type(content) == "manual_linux"

    def test_detect_input_type_manual_windows(self) -> None:
        """Content with privileges information is detected as manual_windows."""
        content = "PRIVILEGES INFORMATION\nSeImpersonatePrivilege Enabled"
        result = detect_input_type(content)
        assert result in ("manual_windows", "winpeas")

    def test_detect_input_type_unknown(self) -> None:
        """Completely generic content is detected as unknown."""
        content = "hello world\nsome random text\nnot enumeration output at all"
        assert detect_input_type(content) == "unknown"

    def test_detect_input_type_winpeas_bat_format(self) -> None:
        """WinPEAS .bat format with _-_-_-_-> markers is detected."""
        content = "_-_-_-_-_-> Basic Info\nsome windows data"
        assert detect_input_type(content) == "winpeas"

    def test_detect_input_type_winpeas_exe_format(self) -> None:
        """WinPEAS .exe format with box-drawing and privileges is detected."""
        content = "═══════════════\nToken Privileges\nSeImpersonatePrivilege Enabled"
        assert detect_input_type(content) == "winpeas"

    def test_detect_input_type_empty_string(self) -> None:
        """Empty string returns unknown without crashing."""
        assert detect_input_type("") == "unknown"

    def test_detect_input_type_windows_path_heuristic(self) -> None:
        """Content with C:\\ paths falls back to manual_windows."""
        content = "Service path: C:\\Program Files\\App\\service.exe"
        result = detect_input_type(content)
        assert result in ("manual_windows", "unknown")
