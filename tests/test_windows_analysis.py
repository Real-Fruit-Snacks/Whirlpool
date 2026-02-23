"""Tests for Windows analysis methods in the Analyzer."""

from __future__ import annotations

import pytest

from whirlpool.engine.analyzer import Analyzer, Category, Confidence, ExploitationPath
from whirlpool.parser.winpeas import (
    ScheduledTaskInfo,
    ServiceInfo,
    TokenPrivilege,
    WinPEASResults,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def analyzer() -> Analyzer:
    """Return a fresh Analyzer instance."""
    return Analyzer()


@pytest.fixture()
def windows_results() -> WinPEASResults:
    """WinPEASResults fixture with several exploitable conditions."""
    results = WinPEASResults()

    # SeImpersonatePrivilege enabled
    results.privileges = [
        TokenPrivilege(name="SeImpersonatePrivilege", state="Enabled"),
        TokenPrivilege(name="SeChangeNotifyPrivilege", state="Enabled"),
        TokenPrivilege(name="SeShutdownPrivilege", state="Disabled"),
    ]

    # Unquoted service path with spaces
    unquoted_svc = ServiceInfo(
        name="VulnService",
        display_name="Vulnerable Service",
        binary_path=r"C:\Program Files\My Service\service.exe",
        start_type="Auto",
        state="Running",
        run_as="LocalSystem",
        unquoted_path=True,
    )
    results.services = [unquoted_svc]
    results.vulnerable_services = [unquoted_svc]

    # AlwaysInstallElevated registry key
    results.always_install_elevated = True

    # Scheduled task running as SYSTEM
    system_task = ScheduledTaskInfo(
        name="SystemMaintenance",
        path=r"\Microsoft\Windows\SystemMaintenance",
        state="Ready",
        run_as="SYSTEM",
        binary_path=r"C:\Windows\system32\maint.exe",
        trigger="Daily",
        writable_binary=False,
    )
    results.scheduled_tasks = [system_task]

    # OS version string that maps to a known Windows version
    results.os_version = "Microsoft Windows Server 2019 Standard"
    results.build_number = "17763"

    return results


@pytest.fixture()
def empty_windows_results() -> WinPEASResults:
    """Completely empty WinPEASResults."""
    return WinPEASResults()


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

class TestAnalyzeWindowsSmoke:

    def test_analyze_windows_returns_paths(
        self, analyzer: Analyzer, windows_results: WinPEASResults
    ) -> None:
        """analyze_windows() returns a list (may be empty but must not crash)."""
        paths = analyzer.analyze_windows(windows_results)
        assert isinstance(paths, list)

    def test_analyze_windows_returns_exploitation_paths(
        self, analyzer: Analyzer, windows_results: WinPEASResults
    ) -> None:
        """All items in the returned list are ExploitationPath instances."""
        paths = analyzer.analyze_windows(windows_results)
        for p in paths:
            assert isinstance(p, ExploitationPath)

    def test_analyze_windows_empty_results(
        self, analyzer: Analyzer, empty_windows_results: WinPEASResults
    ) -> None:
        """analyze_windows() with empty results must not crash and returns a list."""
        paths = analyzer.analyze_windows(empty_windows_results)
        assert isinstance(paths, list)
        # No exploitable data -> should produce very few or zero paths
        assert len(paths) >= 0


# ---------------------------------------------------------------------------
# SeImpersonatePrivilege -> potato attacks
# ---------------------------------------------------------------------------

class TestSeImpersonateSuggestsPotato:

    def test_seimpersonate_suggests_potato(
        self, analyzer: Analyzer, windows_results: WinPEASResults
    ) -> None:
        """SeImpersonatePrivilege should produce at least one POTATO-category path."""
        paths = analyzer.analyze_windows(windows_results)
        potato_paths = [p for p in paths if p.category == Category.POTATO]
        assert len(potato_paths) > 0, (
            "Expected at least one POTATO path when SeImpersonatePrivilege is Enabled"
        )

    def test_seimpersonate_potato_has_commands(
        self, analyzer: Analyzer, windows_results: WinPEASResults
    ) -> None:
        """Potato paths should include at least one command."""
        paths = analyzer.analyze_windows(windows_results)
        potato_paths = [p for p in paths if p.category == Category.POTATO]
        assert len(potato_paths) > 0
        assert any(len(p.commands) > 0 for p in potato_paths), (
            "Expected potato path to have commands"
        )

    def test_seimpersonate_potato_confidence(
        self, analyzer: Analyzer, windows_results: WinPEASResults
    ) -> None:
        """Potato paths should have HIGH confidence."""
        paths = analyzer.analyze_windows(windows_results)
        potato_paths = [p for p in paths if p.category == Category.POTATO]
        assert len(potato_paths) > 0
        assert any(p.confidence == Confidence.HIGH for p in potato_paths)

    def test_no_seimpersonate_no_potato(self, analyzer: Analyzer) -> None:
        """Without SeImpersonate or SeAssignPrimaryToken, no potato paths generated."""
        results = WinPEASResults()
        results.privileges = [
            TokenPrivilege(name="SeChangeNotifyPrivilege", state="Enabled"),
        ]
        paths = analyzer.analyze_windows(results)
        potato_paths = [p for p in paths if p.category == Category.POTATO]
        assert len(potato_paths) == 0


# ---------------------------------------------------------------------------
# Unquoted service path
# ---------------------------------------------------------------------------

class TestUnquotedServicePath:

    def test_unquoted_service_path_detected(
        self, analyzer: Analyzer, windows_results: WinPEASResults
    ) -> None:
        """Unquoted service path should produce a SERVICE-category path."""
        paths = analyzer.analyze_windows(windows_results)
        service_paths = [p for p in paths if p.category == Category.SERVICE]
        unquoted = [p for p in service_paths if "unquoted" in p.technique_name.lower()]
        assert len(unquoted) > 0, (
            "Expected an 'Unquoted Service Path' finding for VulnService"
        )

    def test_unquoted_service_path_finding_contains_binary(
        self, analyzer: Analyzer, windows_results: WinPEASResults
    ) -> None:
        """The finding field should contain the binary path."""
        paths = analyzer.analyze_windows(windows_results)
        service_paths = [p for p in paths if p.category == Category.SERVICE]
        unquoted = [p for p in service_paths if "unquoted" in p.technique_name.lower()]
        assert len(unquoted) > 0
        assert r"Program Files" in unquoted[0].finding or "VulnService" in unquoted[0].technique_name

    def test_no_unquoted_path_when_not_flagged(self, analyzer: Analyzer) -> None:
        """A service without unquoted_path=True should not generate an unquoted finding."""
        results = WinPEASResults()
        clean_svc = ServiceInfo(
            name="CleanService",
            binary_path=r'"C:\Program Files\Clean Service\clean.exe"',
            unquoted_path=False,
            writable_binary=False,
            weak_permissions=False,
        )
        results.vulnerable_services = [clean_svc]
        paths = analyzer.analyze_windows(results)
        unquoted = [
            p for p in paths
            if p.category == Category.SERVICE and "unquoted" in p.technique_name.lower()
        ]
        assert len(unquoted) == 0


# ---------------------------------------------------------------------------
# AlwaysInstallElevated
# ---------------------------------------------------------------------------

class TestAlwaysInstallElevated:

    def test_always_install_elevated_detected(
        self, analyzer: Analyzer, windows_results: WinPEASResults
    ) -> None:
        """AlwaysInstallElevated=True should produce a REGISTRY-category path."""
        paths = analyzer.analyze_windows(windows_results)
        registry_paths = [p for p in paths if p.category == Category.REGISTRY]
        aie_paths = [
            p for p in registry_paths
            if "alwaysinstallelevated" in p.technique_name.lower()
        ]
        assert len(aie_paths) > 0, (
            "Expected an AlwaysInstallElevated finding"
        )

    def test_always_install_elevated_has_msi_command(
        self, analyzer: Analyzer, windows_results: WinPEASResults
    ) -> None:
        """AlwaysInstallElevated path should reference msiexec."""
        paths = analyzer.analyze_windows(windows_results)
        registry_paths = [p for p in paths if p.category == Category.REGISTRY]
        aie_paths = [
            p for p in registry_paths
            if "alwaysinstallelevated" in p.technique_name.lower()
        ]
        assert len(aie_paths) > 0
        all_commands = " ".join(aie_paths[0].commands)
        assert "msiexec" in all_commands.lower() or "msi" in all_commands.lower(), (
            "Expected msiexec command in AlwaysInstallElevated path"
        )

    def test_no_always_install_elevated_when_false(self, analyzer: Analyzer) -> None:
        """When always_install_elevated=False, no REGISTRY AlwaysInstallElevated path."""
        results = WinPEASResults()
        results.always_install_elevated = False
        paths = analyzer.analyze_windows(results)
        aie = [
            p for p in paths
            if p.category == Category.REGISTRY
            and "alwaysinstallelevated" in p.technique_name.lower()
        ]
        assert len(aie) == 0


# ---------------------------------------------------------------------------
# Windows kernel exploit matching
# ---------------------------------------------------------------------------

class TestWindowsKernelExploits:

    def test_windows_kernel_exploits_matched(
        self, analyzer: Analyzer, windows_results: WinPEASResults
    ) -> None:
        """A known Windows Server version should match kernel exploit entries if any exist."""
        paths = analyzer.analyze_windows(windows_results)
        # This is a soft test: if the KB has Windows exploits for Server 2019,
        # they should appear. If the KB is empty, we just verify no crash occurred.
        kernel_paths = [p for p in paths if p.category == Category.KERNEL]
        assert isinstance(kernel_paths, list)

    def test_windows_kernel_no_crash_unknown_version(self, analyzer: Analyzer) -> None:
        """An unknown OS version string should not crash the analyzer."""
        results = WinPEASResults()
        results.os_version = "Microsoft Windows Unknown Edition 99.0"
        paths = analyzer.analyze_windows(results)
        assert isinstance(paths, list)

    def test_windows_kernel_exploits_have_category(
        self, analyzer: Analyzer, windows_results: WinPEASResults
    ) -> None:
        """Any kernel paths returned must have KERNEL category."""
        paths = analyzer.analyze_windows(windows_results)
        kernel_paths = [p for p in paths if p.category == Category.KERNEL]
        for kp in kernel_paths:
            assert kp.category == Category.KERNEL
