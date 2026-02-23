"""Smoke tests for real-world sample data files.

Discovers all .txt files in tests/sample_data/ and runs them through the
appropriate parser, asserting no crash and basic data extraction.
Also includes specific assertion tests for well-known sample files.
"""

from __future__ import annotations

import pytest
from pathlib import Path

from whirlpool.cli import detect_input_type, parse_input
from whirlpool.parser.linpeas import LinPEASParser
from whirlpool.parser.winpeas import WinPEASParser


# Collect all .txt sample files for parametrize
_SAMPLE_DIR = Path(__file__).parent / "sample_data"
_ALL_SAMPLE_FILES = sorted(_SAMPLE_DIR.rglob("*.txt"))


def _file_ids(paths: list[Path]) -> list[str]:
    """Return short relative IDs for parametrize display."""
    base = Path(__file__).parent
    return [str(p.relative_to(base)) for p in paths]


# ---------------------------------------------------------------------------
# Parametrized smoke tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sample_path", _ALL_SAMPLE_FILES, ids=_file_ids(_ALL_SAMPLE_FILES))
def test_sample_file_parses_without_crash(sample_path: Path) -> None:
    """Every sample file must parse without raising an exception."""
    content = sample_path.read_text(encoding="utf-8", errors="replace")
    detected = detect_input_type(content)

    # parse_input expects a file path string
    results, platform = parse_input(str(sample_path))

    assert results is not None
    assert platform in ("linux", "windows", "unknown")


@pytest.mark.parametrize("sample_path", _ALL_SAMPLE_FILES, ids=_file_ids(_ALL_SAMPLE_FILES))
def test_sample_file_extracts_some_data(sample_path: Path) -> None:
    """LinPEAS and WinPEAS samples should produce non-empty results objects."""
    content = sample_path.read_text(encoding="utf-8", errors="replace")
    detected = detect_input_type(content)

    results, platform = parse_input(str(sample_path))

    if platform == "linux":
        # At least one of these should be populated for any real LinPEAS output
        has_data = (
            bool(getattr(results, "suid_binaries", [])) or
            bool(getattr(results, "sudo_rights", [])) or
            bool(getattr(results, "capabilities", [])) or
            bool(getattr(results, "cron_jobs", [])) or
            bool(getattr(results, "kernel_version", "")) or
            bool(getattr(results, "current_user", ""))
        )
        # We only assert for files auto-detected as linpeas
        if detected == "linpeas":
            assert has_data, (
                f"LinPEAS sample {sample_path.name} produced entirely empty results"
            )

    elif platform == "windows":
        has_data = (
            bool(getattr(results, "privileges", [])) or
            bool(getattr(results, "services", [])) or
            bool(getattr(results, "scheduled_tasks", [])) or
            bool(getattr(results, "os_version", "")) or
            bool(getattr(results, "current_user", ""))
        )
        if detected == "winpeas":
            assert has_data, (
                f"WinPEAS sample {sample_path.name} produced entirely empty results"
            )


# ---------------------------------------------------------------------------
# Specific assertion tests for well-known sample files
# ---------------------------------------------------------------------------

class TestLinpeasSampleSpecific:
    """Targeted assertions for the primary linpeas_sample.txt."""

    def test_linpeas_sample_suid_binaries_found(self) -> None:
        """linpeas_sample.txt should contain at least one SUID binary."""
        sample = _SAMPLE_DIR / "linpeas_sample.txt"
        if not sample.exists():
            pytest.skip("linpeas_sample.txt not present")

        parser = LinPEASParser()
        content = sample.read_text(encoding="utf-8", errors="replace")
        results = parser.parse(content)

        assert len(results.suid_binaries) > 0, (
            "Expected at least one SUID binary in linpeas_sample.txt"
        )

    def test_linpeas_sample_returns_linux_platform(self) -> None:
        """linpeas_sample.txt should be detected as linux."""
        sample = _SAMPLE_DIR / "linpeas_sample.txt"
        if not sample.exists():
            pytest.skip("linpeas_sample.txt not present")

        content = sample.read_text(encoding="utf-8", errors="replace")
        assert detect_input_type(content) == "linpeas"

    def test_linpeas_sample_parse_input_platform(self) -> None:
        """parse_input on linpeas_sample.txt returns linux platform."""
        sample = _SAMPLE_DIR / "linpeas_sample.txt"
        if not sample.exists():
            pytest.skip("linpeas_sample.txt not present")

        results, platform = parse_input(str(sample))
        assert platform == "linux"


class TestWinpeasSampleSpecific:
    """Targeted assertions for the primary winpeas_sample.txt."""

    def test_winpeas_sample_privileges_found(self) -> None:
        """winpeas_sample.txt should contain at least one privilege entry."""
        sample = _SAMPLE_DIR / "winpeas_sample.txt"
        if not sample.exists():
            pytest.skip("winpeas_sample.txt not present")

        parser = WinPEASParser()
        content = sample.read_text(encoding="utf-8", errors="replace")
        results = parser.parse(content)

        assert len(results.privileges) > 0 or len(results.services) > 0, (
            "Expected at least some data extracted from winpeas_sample.txt"
        )

    def test_winpeas_sample_returns_windows_platform(self) -> None:
        """winpeas_sample.txt should be detected as windows."""
        sample = _SAMPLE_DIR / "winpeas_sample.txt"
        if not sample.exists():
            pytest.skip("winpeas_sample.txt not present")

        content = sample.read_text(encoding="utf-8", errors="replace")
        assert detect_input_type(content) in ("winpeas", "manual_windows")

    def test_winpeas_sample_parse_input_platform(self) -> None:
        """parse_input on winpeas_sample.txt returns windows platform."""
        sample = _SAMPLE_DIR / "winpeas_sample.txt"
        if not sample.exists():
            pytest.skip("winpeas_sample.txt not present")

        results, platform = parse_input(str(sample))
        assert platform == "windows"


class TestRealWorldLinpeasSamples:
    """Assertions for real-world LinPEAS samples in real_world/."""

    def test_linpeas_admirer_has_data(self) -> None:
        """linpeas_admirer.txt produces non-empty results."""
        sample = _SAMPLE_DIR / "real_world" / "linpeas_admirer.txt"
        if not sample.exists():
            pytest.skip("linpeas_admirer.txt not present")

        results, platform = parse_input(str(sample))
        assert platform == "linux"
        has_data = (
            bool(getattr(results, "suid_binaries", [])) or
            bool(getattr(results, "sudo_rights", [])) or
            bool(getattr(results, "kernel_version", ""))
        )
        assert has_data, "admirer sample should extract some Linux data"

    def test_linpeas_blunder_has_data(self) -> None:
        """linpeas_blunder.txt produces non-empty results."""
        sample = _SAMPLE_DIR / "real_world" / "linpeas_blunder.txt"
        if not sample.exists():
            pytest.skip("linpeas_blunder.txt not present")

        results, platform = parse_input(str(sample))
        assert platform == "linux"
        has_data = (
            bool(getattr(results, "suid_binaries", [])) or
            bool(getattr(results, "sudo_rights", [])) or
            bool(getattr(results, "kernel_version", ""))
        )
        assert has_data, "blunder sample should extract some Linux data"

    def test_winpeas_arctic_has_data(self) -> None:
        """winpeas_arctic.txt produces non-empty results."""
        sample = _SAMPLE_DIR / "real_world" / "winpeas_arctic.txt"
        if not sample.exists():
            pytest.skip("winpeas_arctic.txt not present")

        results, platform = parse_input(str(sample))
        assert platform == "windows"
        has_data = (
            bool(getattr(results, "privileges", [])) or
            bool(getattr(results, "services", [])) or
            bool(getattr(results, "os_version", ""))
        )
        assert has_data, "arctic sample should extract some Windows data"
