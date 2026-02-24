"""LinPEAS output parser.

Parses LinPEAS enumeration output and extracts structured data for analysis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# ANSI escape code pattern - handles all common sequences
ANSI_PATTERN = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[^[]]')

# Module-level compiled regex patterns for reuse
_LS_SUID_PATTERN = re.compile(
    r'^(-[rwxsStT-]{9})\s+'  # permissions starting with -
    r'(\d+)\s+'               # links
    r'(\S+)\s+'               # owner
    r'(\S+)\s+'               # size (or group)
    r'(\d+)\s+'               # size
    r'(.+?)\s+'               # date
    r'(/\S+)$',               # path starting with /
    re.MULTILINE
)

_LS_FULL_PATTERN = re.compile(
    r'^([drwxsStT-]{10})\s+'  # permissions
    r'(\d+)\s+'               # links
    r'(\S+)\s+'               # owner
    r'(\S+)\s+'               # group
    r'(\d+)\s+'               # size
    r'(.{10,12})\s+'          # date
    r'(.+)$'                  # filename
)

_CAP_PATTERN = re.compile(r'^(/\S+)\s*=\s*(cap_\S+)', re.MULTILINE)

_SUDO_PATTERN = re.compile(
    r'\(((?:ALL|root|[\w-]+)(?:\s*:\s*(?:ALL|[\w-]+))?)\)\s*(NOPASSWD:)?\s*(/\S+)',
    re.MULTILINE
)

_NFS_PATTERN = re.compile(r'^(/\S+)\s+\S*\([^)]*no_root_squash[^)]*\)', re.MULTILINE | re.IGNORECASE)

# Capability entry pattern: /path/to/binary = cap_xxx+ep
_CAP_ENTRY_PATTERN = re.compile(r'^(\S+)\s*[=:]\s*(.+)$')

# Cron entry pattern: 5 time fields + user + command
_CRON_ENTRY_PATTERN = re.compile(
    r'^([\d\*,/-]+\s+[\d\*,/-]+\s+[\d\*,/-]+\s+[\d\*,/-]+\s+[\d\*,/-]+)\s+'
    r'(\S+)\s+'
    r'(.+)$'
)

# Network service pattern: netstat/ss output
_SERVICE_PATTERN = re.compile(
    r'(tcp|udp)\S*\s+'
    r'\d+\s+\d+\s+'
    r'([\d\.\*:]+):(\d+)\s+'
    r'([\d\.\*:]+):(\S+)\s+'
    r'(\S+)?'
)

# Frequently used inline patterns promoted to module-level compiled constants
_CAP_WORD_PATTERN = re.compile(r'cap_\w+')
_UID_PATTERN = re.compile(r'uid=(\d+)\(([^)]+)\)')
_GID_PATTERN = re.compile(r'gid=(\d+)')
_GROUPS_PATTERN = re.compile(r'groups=([^\n]+)')
_LINUX_VERSION_PATTERN = re.compile(r'Linux version\s+(\S+)')

# Words that appear in parentheses but aren't sudo runas specs
_NOISE_RUNAS = frozenset({
    'self', 'proxy', 'username', 'password', 'output', 'limit',
    'echo', 'prep', 'getent', 'type', 'in', 'input', 'button',
})


@dataclass
class SUIDEntry:
    """Represents a SUID binary found on the system."""
    path: str
    owner: str = ""
    group: str = ""
    permissions: str = ""
    size: str = ""
    date: str = ""


@dataclass
class CapabilityEntry:
    """Represents a binary with Linux capabilities."""
    path: str
    capabilities: list[str] = field(default_factory=list)
    cap_string: str = ""


@dataclass
class CronEntry:
    """Represents a cron job."""
    schedule: str = ""
    command: str = ""
    user: str = ""
    file_path: str = ""
    writable: bool = False


@dataclass
class SudoEntry:
    """Represents sudo privileges for a user."""
    user: str = ""
    host: str = ""
    runas: str = ""
    commands: list[str] = field(default_factory=list)
    nopasswd: bool = False
    raw_line: str = ""


@dataclass
class NetworkService:
    """Represents a listening network service."""
    protocol: str = ""
    local_address: str = ""
    local_port: int = 0
    foreign_address: str = ""
    state: str = ""
    pid: str = ""
    program: str = ""


@dataclass
class UserInfo:
    """Represents user account information."""
    username: str
    uid: int = 0
    gid: int = 0
    groups: list[str] = field(default_factory=list)
    home: str = ""
    shell: str = ""
    password_status: str = ""


@dataclass
class WritableFile:
    """Represents a writable file or directory."""
    path: str
    permissions: str = ""
    owner: str = ""
    file_type: str = ""


@dataclass
class DockerInfo:
    """Docker-related information."""
    in_container: bool = False
    docker_socket_accessible: bool = False
    docker_group_member: bool = False
    container_escape_possible: bool = False


@dataclass
class LinPEASResults:
    """Container for all parsed LinPEAS results."""
    # System info
    kernel_version: str = ""
    kernel_release: str = ""
    hostname: str = ""
    os_release: str = ""
    architecture: str = ""

    # User info
    current_user: str = ""
    current_uid: int = 0
    current_gid: int = 0
    current_groups: list[str] = field(default_factory=list)
    users: list[UserInfo] = field(default_factory=list)

    # Privilege escalation vectors
    suid_binaries: list[SUIDEntry] = field(default_factory=list)
    sgid_binaries: list[SUIDEntry] = field(default_factory=list)
    capabilities: list[CapabilityEntry] = field(default_factory=list)
    cron_jobs: list[CronEntry] = field(default_factory=list)
    sudo_rights: list[SudoEntry] = field(default_factory=list)

    # Network
    network_services: list[NetworkService] = field(default_factory=list)

    # Writable paths
    writable_files: list[WritableFile] = field(default_factory=list)
    writable_dirs: list[str] = field(default_factory=list)
    path_writable: list[str] = field(default_factory=list)

    # Container info
    docker: DockerInfo = field(default_factory=DockerInfo)
    lxc_lxd: bool = False

    # Special configs
    nfs_exports: list[str] = field(default_factory=list)
    nfs_no_root_squash: list[str] = field(default_factory=list)

    # Interesting files
    ssh_keys: list[str] = field(default_factory=list)
    password_files: list[str] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)

    # Raw sections for manual review
    raw_sections: dict[str, str] = field(default_factory=dict)


class LinPEASParser:
    """Parser for LinPEAS enumeration output."""

    def __init__(self):
        self.results: LinPEASResults = LinPEASResults()
        self._current_section = ""
        self._current_subsection = ""
        self._section_content: dict[str, list[str]] = {}

    def parse(self, content: str) -> LinPEASResults:
        """Parse LinPEAS output and return structured results.

        Args:
            content: Raw LinPEAS output (with or without ANSI codes)

        Returns:
            LinPEASResults containing all extracted data
        """
        # Reset state for reusability
        self.results = LinPEASResults()
        self._current_section = ""
        self._current_subsection = ""
        self._section_content = {}

        # Strip ANSI codes
        clean_content = self._strip_ansi(content)

        # Split into lines and process
        lines = clean_content.splitlines()

        # First pass: identify sections
        self._identify_sections(lines)

        # Second pass: extract data from each section
        self._parse_system_info()
        self._parse_user_info()
        self._parse_suid_binaries()
        self._parse_capabilities()
        self._parse_cron_jobs()
        # Sudo is handled by _extract_from_all_lines with proper noise filtering
        self._parse_network_services()
        self._parse_writable_paths()
        self._parse_docker_info()
        self._parse_nfs_exports()
        self._parse_interesting_files()

        return self.results

    def parse_file(self, path: str | Path) -> LinPEASResults:
        """Parse LinPEAS output from a file.

        Args:
            path: Path to the LinPEAS output file

        Returns:
            LinPEASResults containing all extracted data

        Raises:
            ValueError: If file exceeds 100MB size limit
        """
        path = Path(path)
        max_size = 100 * 1024 * 1024  # 100 MB
        file_size = path.stat().st_size
        if file_size > max_size:
            raise ValueError(f"File exceeds {max_size // (1024 * 1024)}MB limit ({file_size // (1024 * 1024)}MB)")

        # Try different encodings
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                content = path.read_text(encoding=encoding)
                return self.parse(content)
            except UnicodeDecodeError:
                continue

        # Fallback: read as bytes and decode with errors ignored
        content = path.read_bytes().decode('utf-8', errors='replace')
        return self.parse(content)

    def _strip_ansi(self, text: str) -> str:
        """Remove ANSI escape codes from text."""
        return ANSI_PATTERN.sub('', text)

    def _identify_sections(self, lines: list[str]) -> None:
        """Identify and group lines by section."""
        current_section = "preamble"
        current_lines: list[str] = []

        for line in lines:
            # Check for various section header patterns
            # Pattern 1: ╔══════════╣ Section Name
            # Pattern 2: ═══════════════╣ Section Name
            is_header = False
            section_name = ""

            if '╔' in line and '╣' in line:
                # Extract text between ╣ and end
                match = re.search(r'[╔╠╚][═]+╣\s*(.+?)\s*$', line)
                if match:
                    section_name = match.group(1).strip()
                    is_header = True

            elif '╣' in line and '═' in line:
                match = re.search(r'═+╣\s*(.+?)\s*$', line)
                if match:
                    section_name = match.group(1).strip()
                    is_header = True

            elif line.count('═') > 10:
                # Full separator line - check previous line for section name
                pass

            if is_header and section_name:
                # Save previous section
                if current_lines:
                    self._section_content[current_section] = current_lines

                # Start new section
                current_section = section_name
                current_lines = []
                continue

            current_lines.append(line)

        # Save last section
        if current_lines:
            self._section_content[current_section] = current_lines

        # Also do a simple pass to extract data regardless of sections
        # This ensures we catch data even with formatting variations
        self._extract_from_all_lines(lines)

        # Store raw sections for reference
        self.results.raw_sections = {k: '\n'.join(v) for k, v in self._section_content.items()}

    def _extract_from_all_lines(self, lines: list[str]) -> None:
        """Extract key data from all lines regardless of sections."""
        all_text = '\n'.join(lines)

        # Extract uid/gid/groups from anywhere in output
        uid_match = _UID_PATTERN.search(all_text)
        if uid_match:
            self.results.current_uid = int(uid_match.group(1))
            self.results.current_user = uid_match.group(2)

        gid_match = _GID_PATTERN.search(all_text)
        if gid_match:
            self.results.current_gid = int(gid_match.group(1))

        groups_match = _GROUPS_PATTERN.search(all_text)
        if groups_match:
            groups_str = groups_match.group(1)
            for g in groups_str.split(','):
                match = re.search(r'\(([^)]+)\)', g)
                if match and match.group(1) not in self.results.current_groups:
                    self.results.current_groups.append(match.group(1))

        # Extract kernel version
        version_match = _LINUX_VERSION_PATTERN.search(all_text)
        if version_match:
            self.results.kernel_release = version_match.group(1)
            ver_match = re.search(r'(\d+\.\d+\.\d+)', version_match.group(1))
            if ver_match:
                self.results.kernel_version = ver_match.group(1)

        # Extract SUID binaries from ls -la format
        seen_suid_paths: set[str] = {s.path for s in self.results.suid_binaries}
        seen_cap_paths: set[str] = {c.path for c in self.results.capabilities}
        for match in _LS_SUID_PATTERN.finditer(all_text):
            perms, _, owner, group, size, date, path = match.groups()
            if 's' in perms.lower():
                stripped_path = path.strip()
                entry = SUIDEntry(
                    path=stripped_path,
                    owner=owner,
                    group=group,
                    permissions=perms,
                    size=size,
                    date=date.strip()
                )
                # Avoid duplicates using set lookup
                if stripped_path not in seen_suid_paths:
                    seen_suid_paths.add(stripped_path)
                    self.results.suid_binaries.append(entry)

        # Extract capabilities
        for match in _CAP_PATTERN.finditer(all_text):
            path, cap_str = match.groups()
            caps = _CAP_WORD_PATTERN.findall(cap_str.lower())
            if caps and path not in seen_cap_paths:
                seen_cap_paths.add(path)
                cap_entry = CapabilityEntry(path=path, capabilities=caps, cap_string=cap_str)
                self.results.capabilities.append(cap_entry)

        # Extract sudo rights - only match valid sudo runas specs
        # Valid runas: (root), (ALL), (ALL : ALL), (user : group), (pepper : ALL)
        # Command must be an executable path, not a grep result or source file
        for match in _SUDO_PATTERN.finditer(all_text):
            runas, nopasswd, command = match.groups()
            # Filter noise: skip common false-positive runas words
            runas_lower = runas.lower().split(':')[0].strip()
            if runas_lower in _NOISE_RUNAS:
                continue
            # Filter noise: skip grep/source file results (path:content patterns)
            if re.search(r'\.\w{1,4}:', command):
                continue
            # Filter noise: skip version-like patterns e.g. (03-2006)/Solaris_8
            if re.match(r'\d{2}-\d{4}$', runas):
                continue
            sudo_entry = SudoEntry(
                user=self.results.current_user,
                runas=runas,
                commands=[command],
                nopasswd=bool(nopasswd),
                raw_line=match.group(0)
            )
            if not any(s.raw_line == sudo_entry.raw_line for s in self.results.sudo_rights):
                self.results.sudo_rights.append(sudo_entry)

        # Check for docker group
        if 'docker' in self.results.current_groups:
            self.results.docker.docker_group_member = True

        # Check for lxd/lxc group
        if 'lxd' in self.results.current_groups or 'lxc' in self.results.current_groups:
            self.results.lxc_lxd = True

        # Extract NFS no_root_squash
        for match in _NFS_PATTERN.finditer(all_text):
            path = match.group(1)
            if path not in self.results.nfs_no_root_squash:
                self.results.nfs_no_root_squash.append(path)
                self.results.nfs_exports.append(match.group(0))

    def _get_section_lines(self, *keywords: str) -> list[str]:
        """Get lines from sections matching any keyword."""
        result = []
        for section_name, lines in self._section_content.items():
            if any(kw.lower() in section_name.lower() for kw in keywords):
                result.extend(lines)
        return result

    def _parse_system_info(self) -> None:
        """Extract system information."""
        lines = self._get_section_lines("System Information", "Basic information")

        for line in lines:
            line = line.strip()

            # Kernel version
            if "Linux version" in line or "uname" in line.lower():
                match = re.search(r'Linux\s+\S+\s+(\S+)', line)
                if match:
                    self.results.kernel_release = match.group(1)
                # Try to extract just the version number
                version_match = re.search(r'(\d+\.\d+\.\d+)', line)
                if version_match:
                    self.results.kernel_version = version_match.group(1)

            # OS Release
            if "PRETTY_NAME" in line or "DISTRIB_DESCRIPTION" in line:
                match = re.search(r'["\']([^"\']+)["\']', line)
                if match:
                    self.results.os_release = match.group(1)

            # Hostname
            if "Hostname:" in line or "hostname" in line.lower():
                parts = line.split(":")
                if len(parts) >= 2:
                    self.results.hostname = parts[-1].strip()

            # Architecture
            if "x86_64" in line:
                self.results.architecture = "x86_64"
            elif "i686" in line or "i386" in line:
                self.results.architecture = "i386"
            elif "aarch64" in line or "arm64" in line:
                self.results.architecture = "aarch64"

    def _parse_user_info(self) -> None:
        """Extract current user and groups information."""
        lines = self._get_section_lines("User", "Group", "uid=", "Current")

        for line in lines:
            line = line.strip()

            # Parse id output: uid=1000(user) gid=1000(user) groups=...
            if "uid=" in line:
                # Extract uid
                uid_match = _UID_PATTERN.search(line)
                if uid_match:
                    self.results.current_uid = int(uid_match.group(1))
                    self.results.current_user = uid_match.group(2)

                # Extract gid
                gid_match = _GID_PATTERN.search(line)
                if gid_match:
                    self.results.current_gid = int(gid_match.group(1))

                # Extract groups
                groups_match = _GROUPS_PATTERN.search(line)
                if groups_match:
                    groups_str = groups_match.group(1)
                    # Parse groups like "1000(user),27(sudo),..."
                    for g in groups_str.split(','):
                        match = re.search(r'\(([^)]+)\)', g)
                        if match:
                            group_name = match.group(1)
                            if group_name not in self.results.current_groups:
                                self.results.current_groups.append(group_name)
                        else:
                            # Just the gid
                            g = g.strip()
                            if g and g not in self.results.current_groups:
                                self.results.current_groups.append(g)

    def _parse_suid_binaries(self) -> None:
        """Extract SUID and SGID binaries."""
        lines = self._get_section_lines("SUID", "SGID", "Interesting Files", "4000", "2000")

        for line in lines:
            line = line.strip()

            # Skip empty lines and headers
            if not line or line.startswith('═') or line.startswith('╔'):
                continue

            # Check for SUID bit in permissions or filename
            match = _LS_FULL_PATTERN.match(line)
            if match:
                perms, _, owner, group, size, date, path = match.groups()

                # Check for SUID (s in position 3) or SGID (s in position 6)
                if 's' in perms.lower() or 'S' in perms:
                    entry = SUIDEntry(
                        path=path.strip(),
                        owner=owner,
                        group=group,
                        permissions=perms,
                        size=size,
                        date=date.strip()
                    )

                    if perms[3].lower() == 's':
                        self.results.suid_binaries.append(entry)
                    if perms[6].lower() == 's':
                        self.results.sgid_binaries.append(entry)
            else:
                # Simple path-only format
                if line.startswith('/') and not line.startswith('//'):
                    # Check context to determine if SUID or SGID
                    entry = SUIDEntry(path=line)
                    # Add to SUID by default for simple paths (avoid duplicates from global pass)
                    if not any(s.path == entry.path for s in self.results.suid_binaries):
                        self.results.suid_binaries.append(entry)

    def _parse_capabilities(self) -> None:
        """Extract binaries with capabilities."""
        lines = self._get_section_lines("Capabilities", "cap_")

        for line in lines:
            line = line.strip()

            if not line or not ('cap_' in line.lower() or '+' in line):
                continue

            # Try to match path = capabilities format
            match = _CAP_ENTRY_PATTERN.match(line)
            if match:
                path, cap_str = match.groups()

                # Skip if it's a header or not a path
                if not path.startswith('/'):
                    continue

                # Parse individual capabilities
                caps = []
                cap_str = cap_str.strip()
                # Split by comma and extract cap names
                for part in re.split(r'[,\s]+', cap_str):
                    cap_match = re.search(r'(cap_\w+)', part.lower())
                    if cap_match:
                        caps.append(cap_match.group(1))

                if caps:
                    entry = CapabilityEntry(
                        path=path,
                        capabilities=caps,
                        cap_string=cap_str
                    )
                    # Avoid duplicates from global pass
                    if not any(c.path == entry.path for c in self.results.capabilities):
                        self.results.capabilities.append(entry)

    def _parse_cron_jobs(self) -> None:
        """Extract cron job information."""
        lines = self._get_section_lines("Cron", "crontab", "Scheduled")

        current_file = ""

        for line in lines:
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            # Track current crontab file
            if line.startswith('/') and ('cron' in line or 'crontab' in line):
                current_file = line.rstrip(':')
                continue

            # Check for WRITABLE indicator
            writable = "writable" in line.lower() or "WRITABLE" in line

            # Try to parse cron entry
            match = _CRON_ENTRY_PATTERN.match(line)
            if match:
                schedule, user, command = match.groups()
                entry = CronEntry(
                    schedule=schedule,
                    user=user,
                    command=command,
                    file_path=current_file,
                    writable=writable
                )
                self.results.cron_jobs.append(entry)
            elif '@' in line and not line.startswith('@'):
                # Handle @reboot, @daily, etc. formats
                parts = line.split(None, 2)
                if len(parts) >= 2:
                    entry = CronEntry(
                        schedule=parts[0],
                        command=' '.join(parts[1:]) if len(parts) > 1 else "",
                        file_path=current_file,
                        writable=writable
                    )
                    self.results.cron_jobs.append(entry)

    def _parse_network_services(self) -> None:
        """Extract listening network services."""
        lines = self._get_section_lines("Network", "Listening", "Active", "netstat", "ss -")

        for line in lines:
            line = line.strip()

            if not line or not any(x in line.lower() for x in ['listen', 'tcp', 'udp']):
                continue

            match = _SERVICE_PATTERN.search(line)
            if match:
                proto, local_addr, local_port, foreign_addr, foreign_port, state = match.groups()

                # Extract PID/program if present
                pid = ""
                program = ""
                pid_match = re.search(r'(\d+)/(\S+)', line)
                if pid_match:
                    pid = pid_match.group(1)
                    program = pid_match.group(2)

                entry = NetworkService(
                    protocol=proto,
                    local_address=local_addr,
                    local_port=int(local_port),
                    foreign_address=foreign_addr,
                    state=state or "",
                    pid=pid,
                    program=program
                )
                self.results.network_services.append(entry)

    def _parse_writable_paths(self) -> None:
        """Extract writable files and directories."""
        lines = self._get_section_lines("Writable", "PATH", "Interesting")

        all_text = ''.join(lines)
        has_path_reference = "$PATH" in all_text or "PATH=" in all_text

        for line in lines:
            line = line.strip()

            if not line or not line.startswith('/'):
                continue

            # Check if it's a PATH hijack opportunity
            if has_path_reference:
                if "writable" in line.lower():
                    self.results.path_writable.append(line.split()[0])

            # Check for writable directories/files
            if "writable" in line.lower():
                parts = line.split()
                if parts:
                    path = parts[0]
                    if path.startswith('/'):
                        self.results.writable_dirs.append(path)

    def _parse_docker_info(self) -> None:
        """Extract Docker and container information."""
        lines = self._get_section_lines("Docker", "Container", "LXC", "LXD")
        all_text = '\n'.join(lines).lower()

        # Check for container indicators
        self.results.docker.in_container = (
            ("docker" in all_text and "inside" in all_text)
            or "container" in all_text
            or ("cgroup" in all_text and "docker" in all_text)
            or "/.dockerenv" in all_text
        )

        # Check for docker.sock access
        self.results.docker.docker_socket_accessible = "docker.sock" in all_text and "writable" in all_text

        # Check for docker group membership
        self.results.docker.docker_group_member = "docker" in self.results.current_groups

        # Check for LXC/LXD
        self.results.lxc_lxd = "lxd" in self.results.current_groups or "lxc" in self.results.current_groups

        # Escape possibility
        self.results.docker.container_escape_possible = (
            self.results.docker.docker_socket_accessible or
            self.results.docker.docker_group_member or
            self.results.lxc_lxd
        )

    def _parse_nfs_exports(self) -> None:
        """Extract NFS export information."""
        lines = self._get_section_lines("NFS", "exports", "no_root_squash")

        for line in lines:
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            # Look for export entries
            if line.startswith('/') and '(' in line:
                self.results.nfs_exports.append(line)

                # Check for no_root_squash
                if "no_root_squash" in line.lower():
                    # Extract the path
                    path = line.split('(')[0].strip()
                    self.results.nfs_no_root_squash.append(path)

    def _parse_interesting_files(self) -> None:
        """Extract interesting files (SSH keys, passwords, configs)."""
        lines = self._get_section_lines("SSH", "Key", "Password", "Credential", "Interesting")

        for line in lines:
            line = line.strip()

            if not line.startswith('/'):
                continue

            path = parts[0] if (parts := line.split()) else line

            # SSH keys
            if any(x in path.lower() for x in ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'authorized_keys']):
                self.results.ssh_keys.append(path)

            # Password files
            elif any(x in path.lower() for x in ['password', 'passwd', 'shadow', 'credentials', '.htpasswd']):
                self.results.password_files.append(path)

            # Config files
            elif any(x in path.lower() for x in ['.conf', '.config', '.ini', '.xml', '.json', '.yaml', '.yml']):
                self.results.config_files.append(path)
