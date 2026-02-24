"""WinPEAS output parser.

Parses WinPEAS enumeration output and extracts structured data for analysis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# ANSI escape code pattern
ANSI_PATTERN = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[^[]]')


@dataclass
class ServiceInfo:
    """Represents a Windows service."""
    name: str
    display_name: str = ""
    binary_path: str = ""
    start_type: str = ""
    state: str = ""
    run_as: str = ""
    writable_binary: bool = False
    unquoted_path: bool = False
    weak_permissions: bool = False
    permissions: list[str] = field(default_factory=list)


@dataclass
class ScheduledTaskInfo:
    """Represents a Windows scheduled task."""
    name: str
    path: str = ""
    state: str = ""
    run_as: str = ""
    binary_path: str = ""
    trigger: str = ""
    writable_binary: bool = False


@dataclass
class TokenPrivilege:
    """Represents a Windows token privilege."""
    name: str
    state: str = ""  # Enabled, Disabled
    description: str = ""


@dataclass
class RegistryKey:
    """Represents an interesting registry key."""
    path: str
    name: str = ""
    value: str = ""
    type: str = ""


@dataclass
class UserInfo:
    """Represents Windows user information."""
    username: str
    domain: str = ""
    sid: str = ""
    groups: list[str] = field(default_factory=list)
    privileges: list[TokenPrivilege] = field(default_factory=list)


@dataclass
class WinPEASResults:
    """Container for all parsed WinPEAS results."""
    # System info
    hostname: str = ""
    os_version: str = ""
    build_number: str = ""
    architecture: str = ""
    domain: str = ""
    domain_joined: bool = False

    # User info
    current_user: str = ""
    user_info: UserInfo | None = None
    privileges: list[TokenPrivilege] = field(default_factory=list)

    # Services
    services: list[ServiceInfo] = field(default_factory=list)
    vulnerable_services: list[ServiceInfo] = field(default_factory=list)

    # Scheduled tasks
    scheduled_tasks: list[ScheduledTaskInfo] = field(default_factory=list)
    vulnerable_tasks: list[ScheduledTaskInfo] = field(default_factory=list)

    # Registry
    always_install_elevated: bool = False
    autologon_creds: dict | None = None
    interesting_registry: list[RegistryKey] = field(default_factory=list)

    # Credentials
    cached_credentials: list[dict] = field(default_factory=list)
    dpapi_keys: list[str] = field(default_factory=list)

    # File permissions
    writable_paths: list[str] = field(default_factory=list)
    writable_services: list[str] = field(default_factory=list)

    # Network
    listening_ports: list[dict] = field(default_factory=list)
    connections: list[dict] = field(default_factory=list)

    # Defender/AV status
    av_products: list[str] = field(default_factory=list)
    defender_status: dict = field(default_factory=dict)

    # Missing patches (from .bat version)
    missing_patches: list[dict] = field(default_factory=list)

    # Raw sections
    raw_sections: dict[str, str] = field(default_factory=dict)


class WinPEASParser:
    """Parser for WinPEAS enumeration output."""

    def __init__(self):
        self.results: WinPEASResults = WinPEASResults()
        self._section_content: dict[str, list[str]] = {}

    def parse(self, content: str) -> WinPEASResults:
        """Parse WinPEAS output and return structured results.

        Args:
            content: Raw WinPEAS output

        Returns:
            WinPEASResults containing all extracted data
        """
        # Reset state for reusability
        self.results = WinPEASResults()
        self._section_content = {}

        # Strip ANSI codes
        clean_content = self._strip_ansi(content)

        # Split into lines and identify sections
        lines = clean_content.splitlines()
        self._identify_sections(lines)

        # Parse each section
        self._parse_system_info()
        self._parse_user_info()
        self._parse_privileges()
        self._parse_services()
        self._parse_scheduled_tasks()
        self._parse_registry()
        self._parse_credentials()
        self._parse_network()
        self._parse_missing_patches()

        return self.results

    def parse_file(self, path: str | Path) -> WinPEASResults:
        """Parse WinPEAS output from a file.

        Args:
            path: Path to the WinPEAS output file

        Returns:
            WinPEASResults containing all extracted data

        Raises:
            ValueError: If file exceeds 100MB size limit
        """
        path = Path(path)
        max_size = 100 * 1024 * 1024  # 100 MB
        file_size = path.stat().st_size
        if file_size > max_size:
            raise ValueError(f"File exceeds {max_size // (1024 * 1024)}MB limit ({file_size // (1024 * 1024)}MB)")

        for encoding in ['utf-8', 'utf-16', 'latin-1', 'cp1252']:
            try:
                content = path.read_text(encoding=encoding)
                return self.parse(content)
            except UnicodeDecodeError:
                continue

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
            # Check for section headers:
            # WinPEAS .exe format: ═══════════════╣ Section Name ╠═══════════════
            # WinPEAS .bat format: _-_-_-_-_-> [+] SECTION NAME <_-_-_-_-_-
            # WinPEAS .exe beta:   [+] Section Name(T1082&T1124)
            is_section = False
            section_name = ""

            if '═══' in line:
                is_section = True
                section_name = re.sub(r'[═╔╗╚╝╠╣\[\]\+\*\!]', '', line).strip()
            elif '_-_-_' in line and ('[' in line or '<' in line):
                is_section = True
                # Extract text between [+]/[*] markers
                match = re.search(r'\[\S\]\s*(.+?)\s*<', line)
                if match:
                    section_name = match.group(1).strip()
                else:
                    section_name = re.sub(r'[_\-<>\[\]\+\*]', ' ', line).strip()
            elif re.match(r'^\s+\[\+\]\s+\S', line):
                # Beta .exe format: "  [+] Section Name(T1082)"
                is_section = True
                match = re.search(r'\[\+\]\s+(.+?)(?:\(T\d|$)', line)
                if match:
                    section_name = match.group(1).strip()
                else:
                    section_name = re.sub(r'[\[\]\+]', '', line).strip()

            if is_section:
                if current_lines:
                    self._section_content[current_section] = current_lines
                if section_name:
                    current_section = section_name
                current_lines = []
                continue

            current_lines.append(line)

        if current_lines:
            self._section_content[current_section] = current_lines

        self.results.raw_sections = {k: '\n'.join(v) for k, v in self._section_content.items()}

    def _get_section_lines(self, *keywords: str) -> list[str]:
        """Get lines from sections matching any keyword."""
        result = []
        for section_name, lines in self._section_content.items():
            if any(kw.lower() in section_name.lower() for kw in keywords):
                result.extend(lines)
        return result

    def _parse_system_info(self) -> None:
        """Extract system information."""
        lines = self._get_section_lines(
            "System Information", "Basic", "Computer", "WINDOWS OS",
            "BASIC SYSTEM INFO",
        )

        for line in lines:
            line = line.strip()

            # OS Version - handle both registry and systeminfo formats
            # Registry: ProductName    REG_SZ    Windows 10 Pro
            # Systeminfo: OS Name:  Microsoft Windows Server 2008 R2 Standard
            if "ProductName" in line or "OS Name" in line:
                match = re.search(r'(?:Microsoft\s+)?Windows[^,\n]+', line)
                if match:
                    self.results.os_version = match.group(0).strip()
            elif not self.results.os_version and "Windows" in line:
                match = re.search(r'(?:Microsoft\s+)?Windows[^,\n"]+', line)
                if match:
                    self.results.os_version = match.group(0).strip()

            # Build number - systeminfo: "6.1.7600 N/A Build 7600"
            if "BuildNumber" in line or "Build" in line or "OS Version" in line:
                match = re.search(r'Build\s+(\d{4,5})', line)
                if match:
                    self.results.build_number = match.group(1)
                elif not self.results.build_number:
                    match = re.search(r'(\d{4,5})', line)
                    if match:
                        self.results.build_number = match.group(1)

            # Hostname - handle "ComputerName", "Hostname", "Host Name"
            if "ComputerName" in line or "Hostname" in line or "Host Name" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    self.results.hostname = parts[-1].strip()

            # Architecture
            if "x64" in line or "AMD64" in line:
                self.results.architecture = "x64"
            elif "x86" in line or "i386" in line:
                self.results.architecture = "x86"

            # Domain
            if "Domain" in line and "Domain:" in line:
                match = re.search(r':\s*(\S+)', line)
                if match:
                    domain = match.group(1)
                    if domain.lower() not in ['workgroup', 'n/a']:
                        self.results.domain = domain
                        self.results.domain_joined = True

    def _parse_user_info(self) -> None:
        """Extract current user and groups information."""
        lines = self._get_section_lines("User", "whoami", "Current", "CURRENT USER")

        user_info = UserInfo(username="")

        for line in lines:
            line = line.strip()

            # Username - handle both formats:
            # .exe: "User Name: DOMAIN\user"
            # .bat: "User name                    tolis"
            if ("User Name" in line or "User name" in line or "USERNAME" in line) and not self.results.current_user:
                # Try colon-separated first
                match = re.search(r':\s*(\S+)', line)
                if not match:
                    # Try whitespace-separated (bat format)
                    match = re.search(r'(?:User [Nn]ame)\s{2,}(\S+)', line)
                if match:
                    full_user = match.group(1)
                    if '\\' in full_user:
                        domain, user = full_user.split('\\', 1)
                        user_info.domain = domain
                        user_info.username = user
                    else:
                        user_info.username = full_user
                    self.results.current_user = user_info.username

            # SID
            if "SID" in line:
                match = re.search(r'S-\d-\d+-[\d-]+', line)
                if match:
                    user_info.sid = match.group(0)

            # Groups
            if "Group Name" in line or "BUILTIN\\" in line or "\\Domain" in line:
                match = re.search(r'([A-Z]+\\[\w\s]+)', line)
                if match:
                    user_info.groups.append(match.group(1))

        self.results.user_info = user_info

    def _parse_privileges(self) -> None:
        """Extract token privileges."""
        lines = self._get_section_lines(
            "Privilege", "Token", "whoami /priv", "CURRENT USER",
            "BASIC USER INFO",
        )

        # Known dangerous privileges
        dangerous_privs = [
            "SeImpersonatePrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeDebugPrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
            "SeCreateTokenPrivilege",
            "SeTcbPrivilege",
        ]

        for line in lines:
            line = line.strip()

            for priv_name in dangerous_privs:
                if priv_name in line:
                    line_lower = line.lower()
                    state = "Enabled" if "enabled" in line_lower and "disabled" not in line_lower else "Disabled"
                    priv = TokenPrivilege(
                        name=priv_name,
                        state=state
                    )
                    self.results.privileges.append(priv)

    def _parse_services(self) -> None:
        """Extract service information."""
        lines = self._get_section_lines(
            "Service", "sc query", "SERVICES VULNERABILITIES",
            "SERVICE BINARY", "UNQUOTED SERVICE",
        )

        current_service: ServiceInfo | None = None

        for line in lines:
            line = line.strip()

            if not line:
                if current_service and current_service.name:
                    self.results.services.append(current_service)
                    # Check for vulnerabilities
                    if current_service.writable_binary or current_service.unquoted_path or current_service.weak_permissions:
                        self.results.vulnerable_services.append(current_service)
                current_service = None
                continue

            # Service name
            if "SERVICE_NAME" in line or line.startswith("Name:"):
                match = re.search(r':\s*(\S+)', line)
                if match:
                    current_service = ServiceInfo(name=match.group(1))

            if not current_service:
                continue

            # Binary path
            if "BINARY_PATH_NAME" in line or "PathName" in line or "ImagePath" in line:
                match = re.search(r':\s*(.+)$', line)
                if match:
                    path = match.group(1).strip()
                    current_service.binary_path = path

                    # Check for unquoted path with spaces
                    if ' ' in path and not path.startswith('"') and not path.startswith("'"):
                        # Check if it's actually unquoted (not just arguments)
                        first_space = path.find(' ')
                        if first_space > 0 and not path[:first_space].endswith('.exe'):
                            current_service.unquoted_path = True

            # Start type
            if "START_TYPE" in line:
                match = re.search(r':\s*(.+)$', line)
                if match:
                    current_service.start_type = match.group(1).strip()

            # Run as
            if "SERVICE_START_NAME" in line or "LogOnAs" in line:
                match = re.search(r':\s*(.+)$', line)
                if match:
                    current_service.run_as = match.group(1).strip()

            # Writable indicators
            if "writable" in line.lower() or "full control" in line.lower() or "(F)" in line or "(M)" in line:
                if "binary" in line.lower() or "path" in line.lower():
                    current_service.writable_binary = True
                else:
                    current_service.weak_permissions = True

        # Don't forget the last service
        if current_service and current_service.name:
            self.results.services.append(current_service)
            if current_service.writable_binary or current_service.unquoted_path or current_service.weak_permissions:
                self.results.vulnerable_services.append(current_service)

    def _parse_scheduled_tasks(self) -> None:
        """Extract scheduled task information."""
        lines = self._get_section_lines("Scheduled", "Task", "schtasks")

        current_task: ScheduledTaskInfo | None = None

        for line in lines:
            line = line.strip()

            if not line:
                if current_task and current_task.name:
                    self.results.scheduled_tasks.append(current_task)
                    if current_task.writable_binary:
                        self.results.vulnerable_tasks.append(current_task)
                current_task = None
                continue

            # Task name
            if "TaskName" in line or line.startswith("\\"):
                match = re.search(r'[:\\]?\s*([\\\w\s-]+)$', line)
                if match:
                    current_task = ScheduledTaskInfo(name=match.group(1).strip())

            if not current_task:
                continue

            # Task path / action
            if "Task To Run" in line or "Actions" in line:
                match = re.search(r':\s*(.+)$', line)
                if match:
                    current_task.binary_path = match.group(1).strip()

            # Run as
            if "Run As User" in line or "UserId" in line:
                match = re.search(r':\s*(.+)$', line)
                if match:
                    current_task.run_as = match.group(1).strip()

            # Writable binary
            if "writable" in line.lower():
                current_task.writable_binary = True

        # Last task
        if current_task and current_task.name:
            self.results.scheduled_tasks.append(current_task)
            if current_task.writable_binary:
                self.results.vulnerable_tasks.append(current_task)

    def _parse_registry(self) -> None:
        """Extract interesting registry information."""
        lines = self._get_section_lines("Registry", "AlwaysInstallElevated", "AutoLogon", "Winlogon")

        for line in lines:
            line = line.strip()

            # AlwaysInstallElevated
            if "AlwaysInstallElevated" in line:
                if "1" in line or "enabled" in line.lower():
                    self.results.always_install_elevated = True

            # AutoLogon credentials
            if "DefaultUserName" in line:
                if self.results.autologon_creds is None:
                    self.results.autologon_creds = {}
                match = re.search(r':\s*(\S+)', line)
                if match:
                    self.results.autologon_creds["user"] = match.group(1)

            if "DefaultPassword" in line:
                if self.results.autologon_creds is None:
                    self.results.autologon_creds = {}
                match = re.search(r':\s*(.+)$', line)
                if match:
                    self.results.autologon_creds["password"] = match.group(1).strip()

            if "DefaultDomainName" in line:
                if self.results.autologon_creds is None:
                    self.results.autologon_creds = {}
                match = re.search(r':\s*(\S+)', line)
                if match:
                    self.results.autologon_creds["domain"] = match.group(1)

    def _parse_credentials(self) -> None:
        """Extract cached credentials and DPAPI information."""
        lines = self._get_section_lines("Credential", "DPAPI", "Vault", "Password")

        for line in lines:
            line = line.strip()

            # DPAPI master keys
            if "DPAPI" in line and ("key" in line.lower() or "master" in line.lower()):
                self.results.dpapi_keys.append(line)

            # Windows Vault credentials
            if "Credential" in line and ":" in line:
                self.results.cached_credentials.append({"raw": line})

    def _parse_network(self) -> None:
        """Extract network information."""
        lines = self._get_section_lines("Network", "Listening", "netstat", "TCP", "UDP",
                                        "USED PORTS", "INTERFACES")

        for line in lines:
            line = line.strip()

            # Listening ports pattern
            match = re.search(r'(TCP|UDP)\s+[\d\.\:]+:(\d+)\s+[\d\.\:\*]+\s+(\w+)?', line)
            if match:
                proto, port, state = match.groups()
                self.results.listening_ports.append({
                    "protocol": proto,
                    "port": int(port),
                    "state": state or "LISTENING"
                })

    def _parse_missing_patches(self) -> None:
        """Extract missing patches from .bat version output.

        Parses lines like: MS16-032 patch is NOT installed! (Vulns: 2K8/SP1/2,Vista/SP2,7/SP1-secondary logon)
        """
        lines = self._get_section_lines("WINDOWS OS", "BASIC SYSTEM INFO", "patch")

        patch_pattern = re.compile(r'(MS\d{2}-\d{3})\s+patch is NOT installed!\s*\(Vulns:\s*([^)]+)\)')

        for line in lines:
            match = patch_pattern.search(line)
            if match:
                ms_id = match.group(1)
                vulns = match.group(2).strip()
                self.results.missing_patches.append({
                    "id": ms_id,
                    "description": vulns,
                })
