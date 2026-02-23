"""Tests for enumeration output parsers."""

import pytest
from whirlpool.parser.linpeas import LinPEASParser
from whirlpool.parser.winpeas import WinPEASParser
from whirlpool.parser.manual_linux import ManualLinuxParser
from whirlpool.parser.manual_windows import ManualWindowsParser


class TestLinPEASParser:
    """Tests for LinPEAS parser."""

    def test_strip_ansi_codes(self):
        """Test ANSI code stripping."""
        parser = LinPEASParser()
        text = "\x1b[31mred text\x1b[0m normal"
        clean = parser._strip_ansi(text)
        assert "\x1b" not in clean
        assert "red text" in clean
        assert "normal" in clean

    def test_parse_id_output(self):
        """Test parsing id command output in LinPEAS."""
        parser = LinPEASParser()
        content = """
╔══════════╣ Basic information
uid=1000(testuser) gid=1000(testuser) groups=1000(testuser),27(sudo),999(docker)
        """
        results = parser.parse(content)
        assert results.current_user == "testuser"
        assert results.current_uid == 1000
        assert results.current_gid == 1000
        assert "sudo" in results.current_groups
        assert "docker" in results.current_groups

    def test_parse_suid_binaries(self):
        """Test parsing SUID binaries."""
        parser = LinPEASParser()
        content = """
╔══════════╣ SUID - Check easy privesc
-rwsr-xr-x 1 root root 54256 Jul 21 2020 /usr/bin/passwd
-rwsr-xr-x 1 root root 85064 Jul 14 2021 /usr/bin/sudo
-rwsr-xr-x 1 root root 67816 Jul 21 2020 /usr/bin/su
        """
        results = parser.parse(content)
        # Should find SUID binaries
        suid_paths = [s.path for s in results.suid_binaries]
        assert len(results.suid_binaries) > 0, "Expected SUID binaries to be parsed"
        assert "/usr/bin/passwd" in suid_paths, f"Expected /usr/bin/passwd in {suid_paths}"

    def test_parse_capabilities(self):
        """Test parsing capabilities."""
        parser = LinPEASParser()
        content = """
╔══════════╣ Capabilities
/usr/bin/python3.8 = cap_setuid+ep
/usr/bin/ping = cap_net_raw+ep
        """
        results = parser.parse(content)
        assert len(results.capabilities) > 0, "Expected capabilities to be parsed"

    def test_parse_sudo_rights(self):
        """Test parsing sudo -l output."""
        parser = LinPEASParser()
        content = """
╔══════════╣ Checking 'sudo -l'
User testuser may run the following commands:
    (ALL : ALL) NOPASSWD: /usr/bin/vim
    (root) /usr/bin/find
        """
        results = parser.parse(content)
        assert len(results.sudo_rights) > 0, "Expected sudo rights to be parsed"

    def test_parse_kernel_version(self):
        """Test parsing kernel version."""
        parser = LinPEASParser()
        content = """
╔══════════╣ System Information
Linux version 5.4.0-42-generic (buildd@lgw01-amd64-038)
        """
        results = parser.parse(content)
        assert results.kernel_version == "5.4.0"
        assert "5.4.0-42-generic" in results.kernel_release

    def test_sudo_noise_filter_rejects_common_words(self):
        """Test that sudo noise filter rejects false-positive runas words."""
        parser = LinPEASParser()
        content = "\n(proxy) /usr/sbin/something\n(echo) /bin/something\n(self) /usr/lib/something\n"
        results = parser.parse(content)
        assert len(results.sudo_rights) == 0, f"Expected 0 sudo entries, got {len(results.sudo_rights)}"

    def test_sudo_noise_filter_rejects_grep_results(self):
        """Test that sudo noise filter rejects grep/source file results."""
        parser = LinPEASParser()
        content = "\n(root) /usr/lib/python3.py:/some/path\n"
        results = parser.parse(content)
        assert len(results.sudo_rights) == 0, f"Expected 0 sudo entries, got {len(results.sudo_rights)}"

    def test_sudo_noise_filter_rejects_version_patterns(self):
        """Test that sudo noise filter rejects version-like runas patterns."""
        parser = LinPEASParser()
        content = "\n(03-2006) /path/to/something\n"
        results = parser.parse(content)
        assert len(results.sudo_rights) == 0, f"Expected 0 sudo entries, got {len(results.sudo_rights)}"

    def test_sudo_preserves_real_entries(self):
        """Test that real sudo entries are preserved through noise filtering."""
        parser = LinPEASParser()
        content = "\n(ALL : ALL) NOPASSWD: /usr/bin/vim\n(root) /usr/bin/find\n"
        results = parser.parse(content)
        assert len(results.sudo_rights) == 2, f"Expected 2 sudo entries, got {len(results.sudo_rights)}"


class TestWinPEASParser:
    """Tests for WinPEAS parser."""

    def test_parse_privileges(self):
        """Test parsing Windows privileges."""
        parser = WinPEASParser()
        content = """
═══════════════════════════════════════════════════════════════════════════════════════════════════
╔══════════╣ Token Privileges
SeImpersonatePrivilege        Enabled
SeAssignPrimaryTokenPrivilege Disabled
SeDebugPrivilege              Enabled
        """
        results = parser.parse(content)
        priv_names = [p.name for p in results.privileges]
        assert "SeImpersonatePrivilege" in priv_names, f"Expected SeImpersonatePrivilege in {priv_names}"
        assert "SeDebugPrivilege" in priv_names, f"Expected SeDebugPrivilege in {priv_names}"

    def test_parse_services(self):
        """Test parsing Windows services."""
        parser = WinPEASParser()
        content = """
═══════════════════════════════════════════════════════════════════════════════════════════════════
╔══════════╣ Services
SERVICE_NAME: VulnService
        TYPE               : 10  WIN32_OWN_PROCESS
        BINARY_PATH_NAME   : C:\\Program Files\\Vulnerable\\service.exe
        SERVICE_START_NAME : LocalSystem
        """
        results = parser.parse(content)
        assert len(results.services) > 0, "Expected services to be parsed"


class TestManualLinuxParser:
    """Tests for manual Linux command parser."""

    def test_parse_id(self):
        """Test parsing id command output."""
        parser = ManualLinuxParser()
        parser.parse_id("uid=1000(user) gid=1000(user) groups=1000(user),27(sudo)")
        assert parser.results.current_user == "user"
        assert parser.results.current_uid == 1000
        assert "sudo" in parser.results.current_groups

    def test_parse_find_suid(self):
        """Test parsing find -perm -4000 output."""
        parser = ManualLinuxParser()
        output = """
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/su
/usr/bin/pkexec
        """
        parser.parse_find_suid(output)
        paths = [s.path for s in parser.results.suid_binaries]
        assert "/usr/bin/passwd" in paths
        assert "/usr/bin/sudo" in paths

    def test_parse_getcap(self):
        """Test parsing getcap output."""
        parser = ManualLinuxParser()
        output = """
/usr/bin/python3.8 = cap_setuid+ep
/usr/bin/ping = cap_net_raw+ep
        """
        parser.parse_getcap(output)
        assert len(parser.results.capabilities) == 2
        cap_paths = [c.path for c in parser.results.capabilities]
        assert "/usr/bin/python3.8" in cap_paths

    def test_parse_sudo_l(self):
        """Test parsing sudo -l output."""
        parser = ManualLinuxParser()
        output = """
User user may run the following commands:
    (ALL : ALL) NOPASSWD: /usr/bin/vim
    (root) /usr/bin/find
        """
        parser.parse_sudo_l(output)
        assert len(parser.results.sudo_rights) == 2
        # Check NOPASSWD flag
        nopasswd_entries = [s for s in parser.results.sudo_rights if s.nopasswd]
        assert len(nopasswd_entries) == 1

    def test_parse_uname(self):
        """Test parsing uname -a output."""
        parser = ManualLinuxParser()
        parser.parse_uname("Linux hostname 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux")
        assert parser.results.kernel_version == "5.4.0"
        assert parser.results.hostname == "hostname"
        assert parser.results.architecture == "x86_64"

    def test_parse_exports(self):
        """Test parsing /etc/exports content."""
        parser = ManualLinuxParser()
        output = """
/shared *(rw,no_root_squash)
/backup *(rw,root_squash)
        """
        parser.parse_exports(output)
        assert len(parser.results.nfs_exports) == 2
        assert len(parser.results.nfs_no_root_squash) == 1
        assert "/shared" in parser.results.nfs_no_root_squash[0]


class TestManualWindowsParser:
    """Tests for manual Windows command parser."""

    def test_parse_whoami(self):
        """Test parsing whoami output."""
        parser = ManualWindowsParser()
        parser.parse_whoami("DOMAIN\\username")
        assert parser.results.current_user == "username"
        assert parser.results.user_info.domain == "DOMAIN"

    def test_parse_whoami_priv(self):
        """Test parsing whoami /priv output."""
        parser = ManualWindowsParser()
        output = """
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeImpersonatePrivilege        Impersonate a client after auth      Enabled
SeDebugPrivilege              Debug programs                       Disabled
        """
        parser.parse_whoami_priv(output)
        priv_names = [p.name for p in parser.results.privileges]
        assert "SeImpersonatePrivilege" in priv_names
        assert "SeDebugPrivilege" in priv_names

    def test_parse_systeminfo(self):
        """Test parsing systeminfo output."""
        parser = ManualWindowsParser()
        output = """
Host Name:                 TESTPC
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19041 N/A Build 19041
System Type:               x64-based PC
        """
        parser.parse_systeminfo(output)
        assert parser.results.hostname == "TESTPC"
        assert "Windows 10" in parser.results.os_version
        assert parser.results.architecture == "x64"
