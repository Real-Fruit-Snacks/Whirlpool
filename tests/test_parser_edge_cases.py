"""Edge case tests for parsers.

Tests for empty input, malformed input, ANSI-only content, and other
boundary conditions that real-world tool output may produce.
"""

import pytest
from whirlpool.parser.linpeas import LinPEASParser
from whirlpool.parser.winpeas import WinPEASParser
from whirlpool.parser.manual_linux import ManualLinuxParser
from whirlpool.parser.manual_windows import ManualWindowsParser


class TestLinPEASEdgeCases:
    """Edge case tests for LinPEAS parser."""

    def test_parse_empty_input(self):
        """Test parsing empty string."""
        parser = LinPEASParser()
        results = parser.parse("")
        assert results.current_user == ""
        assert len(results.suid_binaries) == 0
        assert len(results.capabilities) == 0
        assert len(results.sudo_rights) == 0

    def test_parse_only_ansi_codes(self):
        """Test parsing input that is only ANSI escape codes."""
        parser = LinPEASParser()
        results = parser.parse("\x1b[31m\x1b[0m\x1b[32m\x1b[0m")
        assert results.current_user == ""
        assert len(results.suid_binaries) == 0

    def test_parse_only_whitespace(self):
        """Test parsing whitespace-only input."""
        parser = LinPEASParser()
        results = parser.parse("   \n\n\t\t\n   ")
        assert results.current_user == ""

    def test_parse_only_section_headers(self):
        """Test parsing input with only section headers, no data."""
        parser = LinPEASParser()
        content = """
╔══════════╣ Basic information
╔══════════╣ SUID - Check easy privesc
╔══════════╣ Capabilities
        """
        results = parser.parse(content)
        assert len(results.suid_binaries) == 0

    def test_strip_ansi_preserves_content(self):
        """Test that ANSI stripping preserves actual text content."""
        parser = LinPEASParser()
        text = "\x1b[1;31m/usr/bin/passwd\x1b[0m"
        clean = parser._strip_ansi(text)
        assert clean == "/usr/bin/passwd"

    def test_parse_large_ansi_blocks(self):
        """Test parsing content with heavy ANSI formatting."""
        parser = LinPEASParser()
        ansi_line = "\x1b[31;1m" + "A" * 500 + "\x1b[0m"
        content = f"""
╔══════════╣ Basic information
{ansi_line}
uid=1000(testuser) gid=1000(testuser)
        """
        results = parser.parse(content)
        assert results.current_user == "testuser"


class TestWinPEASEdgeCases:
    """Edge case tests for WinPEAS parser."""

    def test_parse_empty_input(self):
        """Test parsing empty string."""
        parser = WinPEASParser()
        results = parser.parse("")
        assert results.current_user == ""
        assert len(results.privileges) == 0
        assert len(results.services) == 0

    def test_parse_only_whitespace(self):
        """Test parsing whitespace-only input."""
        parser = WinPEASParser()
        results = parser.parse("   \n\n\t\t\n   ")
        assert results.current_user == ""

    def test_parse_only_separators(self):
        """Test parsing input with only separator lines."""
        parser = WinPEASParser()
        content = """
═══════════════════════════════════════════════════════
╔══════════╣ Some Section
═══════════════════════════════════════════════════════
        """
        results = parser.parse(content)
        assert len(results.privileges) == 0


class TestManualLinuxEdgeCases:
    """Edge case tests for manual Linux parser."""

    def test_parse_id_empty(self):
        """Test parsing empty id output."""
        parser = ManualLinuxParser()
        parser.parse_id("")
        assert parser.results.current_user == ""

    def test_parse_id_malformed(self):
        """Test parsing malformed id output."""
        parser = ManualLinuxParser()
        parser.parse_id("not a valid id output")
        assert parser.results.current_user == ""

    def test_parse_find_suid_empty(self):
        """Test parsing empty find output."""
        parser = ManualLinuxParser()
        parser.parse_find_suid("")
        assert len(parser.results.suid_binaries) == 0

    def test_parse_find_suid_with_errors(self):
        """Test parsing find output that includes error lines."""
        parser = ManualLinuxParser()
        output = """
find: '/proc/1/fd': Permission denied
/usr/bin/passwd
find: '/root': Permission denied
/usr/bin/sudo
        """
        parser.parse_find_suid(output)
        paths = [s.path for s in parser.results.suid_binaries]
        assert "/usr/bin/passwd" in paths
        assert "/usr/bin/sudo" in paths
        # Error lines should not appear
        assert not any("find:" in p for p in paths)

    def test_parse_getcap_empty(self):
        """Test parsing empty getcap output."""
        parser = ManualLinuxParser()
        parser.parse_getcap("")
        assert len(parser.results.capabilities) == 0

    def test_parse_getcap_with_errors(self):
        """Test parsing getcap output with error lines."""
        parser = ManualLinuxParser()
        output = """
getcap: /proc/1/exe: Permission denied
/usr/bin/python3.8 = cap_setuid+ep
        """
        parser.parse_getcap(output)
        assert len(parser.results.capabilities) == 1

    def test_parse_sudo_l_empty(self):
        """Test parsing empty sudo -l output."""
        parser = ManualLinuxParser()
        parser.parse_sudo_l("")
        assert len(parser.results.sudo_rights) == 0

    def test_parse_uname_empty(self):
        """Test parsing empty uname output."""
        parser = ManualLinuxParser()
        parser.parse_uname("")
        assert parser.results.kernel_version == ""

    def test_parse_exports_empty(self):
        """Test parsing empty exports."""
        parser = ManualLinuxParser()
        parser.parse_exports("")
        assert len(parser.results.nfs_exports) == 0
        assert len(parser.results.nfs_no_root_squash) == 0

    def test_parse_exports_comments_only(self):
        """Test parsing exports file with only comments."""
        parser = ManualLinuxParser()
        output = """
# /etc/exports - NFS configuration
# This file is empty
        """
        parser.parse_exports(output)
        assert len(parser.results.nfs_exports) == 0

    def test_parse_all_with_empty_commands(self):
        """Test parse_all with empty command outputs."""
        parser = ManualLinuxParser()
        results = parser.parse_all({
            "id": "",
            "whoami": "",
            "find_suid": "",
        })
        assert results.current_user == ""

    def test_parse_all_with_unknown_command(self):
        """Test parse_all ignores unknown command names."""
        parser = ManualLinuxParser()
        results = parser.parse_all({
            "unknown_command": "some output",
            "id": "uid=0(root) gid=0(root)",
        })
        assert results.current_user == "root"


class TestManualWindowsEdgeCases:
    """Edge case tests for manual Windows parser."""

    def test_parse_whoami_empty(self):
        """Test parsing empty whoami output."""
        parser = ManualWindowsParser()
        parser.parse_whoami("")
        assert parser.results.current_user == ""

    def test_parse_whoami_no_domain(self):
        """Test parsing whoami without domain prefix."""
        parser = ManualWindowsParser()
        parser.parse_whoami("localuser")
        assert parser.results.current_user == "localuser"

    def test_parse_whoami_priv_empty(self):
        """Test parsing empty whoami /priv output."""
        parser = ManualWindowsParser()
        parser.parse_whoami_priv("")
        assert len(parser.results.privileges) == 0

    def test_parse_systeminfo_empty(self):
        """Test parsing empty systeminfo output."""
        parser = ManualWindowsParser()
        parser.parse_systeminfo("")
        assert parser.results.hostname == ""
        assert parser.results.os_version == ""

    def test_parse_systeminfo_partial(self):
        """Test parsing systeminfo with only hostname."""
        parser = ManualWindowsParser()
        parser.parse_systeminfo("Host Name:                 TESTPC")
        assert parser.results.hostname == "TESTPC"
        assert parser.results.os_version == ""

    def test_parse_all_with_empty_commands(self):
        """Test parse_all with empty command outputs."""
        parser = ManualWindowsParser()
        results = parser.parse_all({
            "whoami": "",
            "systeminfo": "",
        })
        assert results.current_user == ""
