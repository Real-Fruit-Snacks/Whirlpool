"""Tests for the Analyzer._version_in_range() private method.

Tests are driven both directly (via the private method) and indirectly
through _analyze_kernel_linux() where the private method is exercised
end-to-end.
"""

from __future__ import annotations

import pytest

from whirlpool.engine.analyzer import Analyzer


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def analyzer() -> Analyzer:
    """Return a fresh Analyzer instance."""
    return Analyzer()


# ---------------------------------------------------------------------------
# Direct unit tests of _version_in_range()
# ---------------------------------------------------------------------------

class TestVersionInRangeBoundaries:

    def test_exact_min_boundary(self, analyzer: Analyzer) -> None:
        """Version == min should return True (inclusive lower bound)."""
        assert analyzer._version_in_range("5.4.0", "5.4.0", "5.8.0") is True

    def test_exact_max_boundary(self, analyzer: Analyzer) -> None:
        """Version == max should return True (inclusive upper bound)."""
        assert analyzer._version_in_range("5.8.0", "5.4.0", "5.8.0") is True

    def test_within_range(self, analyzer: Analyzer) -> None:
        """Version strictly between min and max returns True."""
        assert analyzer._version_in_range("5.6.0", "5.4.0", "5.8.0") is True

    def test_below_range(self, analyzer: Analyzer) -> None:
        """Version below min returns False."""
        assert analyzer._version_in_range("5.3.9", "5.4.0", "5.8.0") is False

    def test_above_range(self, analyzer: Analyzer) -> None:
        """Version above max returns False."""
        assert analyzer._version_in_range("5.9.0", "5.4.0", "5.8.0") is False


class TestVersionInRangeSuffixes:

    def test_version_with_generic_suffix(self, analyzer: Analyzer) -> None:
        """5.4.0-42-generic within range 5.4.0 to 5.8.0 returns True."""
        assert analyzer._version_in_range("5.4.0-42-generic", "5.4.0", "5.8.0") is True

    def test_version_with_ubuntu_suffix(self, analyzer: Analyzer) -> None:
        """4.15.0-213-Ubuntu should be handled without crashing and return correct result."""
        # 4.15.0 is below 5.4.0, so should be False for the 5.x range
        result = analyzer._version_in_range("4.15.0-213-Ubuntu", "5.4.0", "5.8.0")
        assert result is False

    def test_version_with_ubuntu_suffix_in_range(self, analyzer: Analyzer) -> None:
        """4.15.0-213-Ubuntu within 4.x range returns True."""
        assert analyzer._version_in_range("4.15.0-213-Ubuntu", "4.4.0", "4.15.255") is True

    def test_version_with_build_suffix(self, analyzer: Analyzer) -> None:
        """Version with build number suffix is parsed correctly."""
        # 5.15.0-58 -> numeric part 5.15.0, within 5.10.0 to 5.15.255
        assert analyzer._version_in_range("5.15.0-58", "5.10.0", "5.15.255") is True

    def test_max_with_generic_suffix(self, analyzer: Analyzer) -> None:
        """Suffixes in min/max boundaries are also handled."""
        assert analyzer._version_in_range("5.4.0", "5.4.0-0", "5.8.0-99") is True


class TestVersionInRangeEdgeCases:

    def test_malformed_version_returns_false(self, analyzer: Analyzer) -> None:
        """Completely malformed version string should return False gracefully."""
        assert analyzer._version_in_range("not-a-version", "5.4.0", "5.8.0") is False

    def test_malformed_version_garbage_chars(self, analyzer: Analyzer) -> None:
        """Garbage input should return False without raising."""
        assert analyzer._version_in_range("abc.def.ghi", "5.4.0", "5.8.0") is False

    def test_empty_version_returns_false(self, analyzer: Analyzer) -> None:
        """Empty version string should return False."""
        assert analyzer._version_in_range("", "5.4.0", "5.8.0") is False

    def test_single_component_version_within(self, analyzer: Analyzer) -> None:
        """Single-component version 5 within range 4 to 6 returns True."""
        assert analyzer._version_in_range("5", "4", "6") is True

    def test_single_component_version_below(self, analyzer: Analyzer) -> None:
        """Single-component version 3 below range 4 to 6 returns False."""
        assert analyzer._version_in_range("3", "4", "6") is False

    def test_single_component_version_above(self, analyzer: Analyzer) -> None:
        """Single-component version 7 above range 4 to 6 returns False."""
        assert analyzer._version_in_range("7", "4", "6") is False

    def test_equal_min_max_version_matches(self, analyzer: Analyzer) -> None:
        """When min == max, version == min/max returns True."""
        assert analyzer._version_in_range("5.4.0", "5.4.0", "5.4.0") is True

    def test_equal_min_max_version_not_equal(self, analyzer: Analyzer) -> None:
        """When min == max, version != min/max returns False."""
        assert analyzer._version_in_range("5.4.1", "5.4.0", "5.4.0") is False

    def test_all_sentinel_returns_true(self, analyzer: Analyzer) -> None:
        """min='all' and max='all' means any version is affected."""
        assert analyzer._version_in_range("1.0.0", "all", "all") is True

    def test_zero_version(self, analyzer: Analyzer) -> None:
        """Version 0.0.0 at boundary 0.0.0 returns True."""
        assert analyzer._version_in_range("0.0.0", "0.0.0", "0.0.0") is True

    def test_four_part_version(self, analyzer: Analyzer) -> None:
        """Four-part version within a range is handled correctly."""
        assert analyzer._version_in_range("5.4.0.1", "5.4.0.0", "5.4.0.9") is True

    def test_four_part_version_exceeds_max(self, analyzer: Analyzer) -> None:
        """Four-part version exceeding max returns False."""
        assert analyzer._version_in_range("5.4.0.10", "5.4.0.0", "5.4.0.9") is False


# ---------------------------------------------------------------------------
# Indirect tests through _analyze_kernel_linux()
# ---------------------------------------------------------------------------

class TestVersionRangeViaKernelAnalysis:
    """Exercise _version_in_range indirectly by providing mock results to
    _analyze_kernel_linux() and checking whether kernel paths are generated."""

    class _MockLinuxResults:
        """Minimal mock with just a kernel_version attribute."""
        def __init__(self, kernel_version: str) -> None:
            self.kernel_version = kernel_version
            self.suid_binaries = []
            self.capabilities = []
            self.sudo_rights = []
            self.cron_jobs = []
            self.docker = None
            self.nfs_no_root_squash = []

    def test_kernel_analysis_with_valid_version_no_crash(self, analyzer: Analyzer) -> None:
        """_analyze_kernel_linux() with a valid version string does not raise."""
        mock = self._MockLinuxResults("5.4.0")
        paths = analyzer._analyze_kernel_linux(mock)  # type: ignore[arg-type]
        assert isinstance(paths, list)

    def test_kernel_analysis_with_suffixed_version_no_crash(self, analyzer: Analyzer) -> None:
        """_analyze_kernel_linux() with a suffixed version does not raise."""
        mock = self._MockLinuxResults("5.4.0-42-generic")
        paths = analyzer._analyze_kernel_linux(mock)  # type: ignore[arg-type]
        assert isinstance(paths, list)

    def test_kernel_analysis_with_malformed_version_no_crash(self, analyzer: Analyzer) -> None:
        """_analyze_kernel_linux() with garbage version string does not raise."""
        mock = self._MockLinuxResults("garbage-version-xyz")
        paths = analyzer._analyze_kernel_linux(mock)  # type: ignore[arg-type]
        assert isinstance(paths, list)
        # May still match exploits with "all" version range (e.g., PwnKit)

    def test_kernel_analysis_with_empty_version(self, analyzer: Analyzer) -> None:
        """_analyze_kernel_linux() with empty string returns empty list."""
        mock = self._MockLinuxResults("")
        paths = analyzer._analyze_kernel_linux(mock)  # type: ignore[arg-type]
        assert paths == []
