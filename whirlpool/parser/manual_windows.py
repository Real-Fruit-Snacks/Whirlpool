"""Parser for manual Windows enumeration commands.

Parses output from common Windows enumeration commands like whoami /priv, systeminfo, etc.
"""

from __future__ import annotations

import logging
import re
from typing import Callable

from .winpeas import (
    ScheduledTaskInfo,
    ServiceInfo,
    TokenPrivilege,
    UserInfo,
    WinPEASResults,
)


class ManualWindowsParser:
    """Parser for manual Windows enumeration command outputs."""

    def __init__(self):
        self.results: WinPEASResults = WinPEASResults()

    def parse_whoami(self, output: str) -> None:
        """Parse 'whoami' command output.

        Example: DOMAIN\\username
        """
        output = output.strip()
        if '\\' in output:
            domain, user = output.rsplit('\\', 1)
            self.results.current_user = user
            if self.results.user_info is None:
                self.results.user_info = UserInfo(username=user, domain=domain)
            else:
                self.results.user_info.username = user
                self.results.user_info.domain = domain
        else:
            self.results.current_user = output
            if self.results.user_info is None:
                self.results.user_info = UserInfo(username=output)

    def parse_whoami_priv(self, output: str) -> None:
        """Parse 'whoami /priv' command output.

        Example:
        PRIVILEGES INFORMATION
        ----------------------

        Privilege Name                Description                          State
        ============================= ==================================== ========
        SeImpersonatePrivilege        Impersonate a client after auth      Enabled
        """
        dangerous_privs = {
            "SeImpersonatePrivilege": "Impersonate a client after authentication",
            "SeAssignPrimaryTokenPrivilege": "Replace a process level token",
            "SeBackupPrivilege": "Back up files and directories",
            "SeRestorePrivilege": "Restore files and directories",
            "SeDebugPrivilege": "Debug programs",
            "SeTakeOwnershipPrivilege": "Take ownership of files or objects",
            "SeLoadDriverPrivilege": "Load and unload device drivers",
            "SeCreateTokenPrivilege": "Create a token object",
            "SeTcbPrivilege": "Act as part of the operating system",
        }

        for line in output.strip().splitlines():
            line = line.strip()

            for priv_name, description in dangerous_privs.items():
                if priv_name in line:
                    state = "Enabled" if "Enabled" in line else "Disabled"
                    priv = TokenPrivilege(
                        name=priv_name,
                        state=state,
                        description=description
                    )
                    self.results.privileges.append(priv)

    def parse_whoami_groups(self, output: str) -> None:
        """Parse 'whoami /groups' command output.

        Example:
        GROUP INFORMATION
        -----------------

        Group Name                             Type             SID
        ====================================== ================ ============
        BUILTIN\\Administrators                Alias            S-1-5-32-544
        """
        if self.results.user_info is None:
            self.results.user_info = UserInfo(username=self.results.current_user)

        for line in output.strip().splitlines():
            line = line.strip()

            # Skip headers and separators
            if not line or '====' in line or 'Group Name' in line:
                continue

            # Look for group entries
            if 'BUILTIN\\' in line or 'NT AUTHORITY\\' in line or '\\' in line:
                parts = line.split()
                if parts:
                    group_name = parts[0]
                    self.results.user_info.groups.append(group_name)

    def parse_systeminfo(self, output: str) -> None:
        """Parse 'systeminfo' command output."""
        for line in output.strip().splitlines():
            line = line.strip()

            # Host Name
            if line.startswith("Host Name:"):
                self.results.hostname = line.split(":", 1)[1].strip()

            # OS Name
            elif line.startswith("OS Name:"):
                self.results.os_version = line.split(":", 1)[1].strip()

            # OS Version (includes build number)
            elif line.startswith("OS Version:"):
                version = line.split(":", 1)[1].strip()
                # Extract build number
                build_match = re.search(r'Build\s+(\d+)', version)
                if build_match:
                    self.results.build_number = build_match.group(1)

            # System Type
            elif line.startswith("System Type:"):
                sys_type = line.split(":", 1)[1].strip()
                if "x64" in sys_type:
                    self.results.architecture = "x64"
                elif "x86" in sys_type:
                    self.results.architecture = "x86"

            # Domain
            elif line.startswith("Domain:"):
                domain = line.split(":", 1)[1].strip()
                if domain.lower() not in ['workgroup']:
                    self.results.domain = domain
                    self.results.domain_joined = True

    def parse_icacls(self, output: str, path: str = "") -> None:
        """Parse 'icacls' command output.

        Example:
        C:\\Program Files\\Service\\binary.exe BUILTIN\\Users:(I)(F)
                                                NT AUTHORITY\\SYSTEM:(I)(F)
        """
        # Look for dangerous permissions
        dangerous_perms = ['(F)', '(M)', '(W)', 'FULL', 'MODIFY', 'WRITE']

        for line in output.strip().splitlines():
            line = line.strip()

            # Check if line has path info
            if line.startswith('C:\\') or line.startswith('\\\\'):
                parts = line.split(None, 1)
                if parts:
                    path = parts[0]
                    continue

            # Check for dangerous permissions for non-admin users
            if any(perm in line.upper() for perm in dangerous_perms):
                if any(user in line for user in ['Users', 'Everyone', 'Authenticated Users']):
                    if path:
                        self.results.writable_paths.append(path)

    def parse_sc_query(self, output: str) -> None:
        """Parse 'sc query' or 'sc qc <service>' output.

        Example:
        SERVICE_NAME: ServiceName
                TYPE               : 10  WIN32_OWN_PROCESS
                STATE              : 4  RUNNING
                ...
        """
        current_service: ServiceInfo | None = None

        for line in output.strip().splitlines():
            line = line.strip()

            if line.startswith("SERVICE_NAME:"):
                if current_service:
                    self.results.services.append(current_service)
                name = line.split(":", 1)[1].strip()
                current_service = ServiceInfo(name=name)

            elif current_service:
                if "BINARY_PATH_NAME" in line:
                    path = line.split(":", 1)[1].strip()
                    current_service.binary_path = path

                    # Check for unquoted path
                    if ' ' in path and not path.startswith('"'):
                        current_service.unquoted_path = True

                elif "START_TYPE" in line:
                    current_service.start_type = line.split(":", 1)[1].strip()

                elif "SERVICE_START_NAME" in line:
                    current_service.run_as = line.split(":", 1)[1].strip()

                elif "STATE" in line:
                    state = line.split(":", 1)[1].strip()
                    current_service.state = state

        if current_service:
            self.results.services.append(current_service)

    def parse_schtasks(self, output: str) -> None:
        """Parse 'schtasks /query /fo LIST /v' output.

        Example:
        Folder: \\
        HostName:      HOSTNAME
        TaskName:      \\TaskName
        Task To Run:   C:\\path\\to\\binary.exe
        """
        current_task: ScheduledTaskInfo | None = None

        for line in output.strip().splitlines():
            line = line.strip()

            if not line:
                if current_task and current_task.name:
                    self.results.scheduled_tasks.append(current_task)
                current_task = None
                continue

            if "TaskName:" in line:
                name = line.split(":", 1)[1].strip()
                current_task = ScheduledTaskInfo(name=name)

            elif current_task:
                if "Task To Run:" in line:
                    path = line.split(":", 1)[1].strip()
                    current_task.binary_path = path

                elif "Run As User:" in line:
                    user = line.split(":", 1)[1].strip()
                    current_task.run_as = user

                elif "Status:" in line:
                    state = line.split(":", 1)[1].strip()
                    current_task.state = state

        if current_task and current_task.name:
            self.results.scheduled_tasks.append(current_task)

    def parse_netstat(self, output: str) -> None:
        """Parse 'netstat -ano' output.

        Example:
        Proto  Local Address          Foreign Address        State           PID
        TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234
        """
        for line in output.strip().splitlines():
            line = line.strip()

            if not line or 'Proto' in line:
                continue

            parts = line.split()
            if len(parts) >= 4 and parts[0].upper() in ['TCP', 'UDP']:
                proto = parts[0].upper()
                local = parts[1]
                state = parts[3] if len(parts) > 3 else ""

                # Extract port
                port_match = re.search(r':(\d+)$', local)
                if port_match:
                    port = int(port_match.group(1))
                    self.results.listening_ports.append({
                        "protocol": proto,
                        "port": port,
                        "state": state
                    })

    def parse_reg_query(self, output: str, key_type: str = "") -> None:
        """Parse 'reg query' output.

        Args:
            output: reg query output
            key_type: Type of key being queried (alwaysinstallelevated, autologon, etc.)
        """
        for line in output.strip().splitlines():
            line = line.strip()

            if key_type == "alwaysinstallelevated":
                if "AlwaysInstallElevated" in line and "0x1" in line:
                    self.results.always_install_elevated = True

            elif key_type == "autologon":
                if "DefaultUserName" in line:
                    match = re.search(r'REG_SZ\s+(\S+)', line)
                    if match:
                        if self.results.autologon_creds is None:
                            self.results.autologon_creds = {}
                        self.results.autologon_creds["user"] = match.group(1)

                elif "DefaultPassword" in line:
                    match = re.search(r'REG_SZ\s+(.+)$', line)
                    if match:
                        if self.results.autologon_creds is None:
                            self.results.autologon_creds = {}
                        self.results.autologon_creds["password"] = match.group(1).strip()

    def parse_all(self, commands: dict[str, str]) -> WinPEASResults:
        """Parse multiple command outputs.

        Args:
            commands: Dictionary mapping command names to their output.
                     Supported keys: whoami, whoami_priv, whoami_groups,
                     systeminfo, icacls, sc_query, schtasks, netstat,
                     reg_alwaysinstall, reg_autologon

        Returns:
            WinPEASResults with all parsed data
        """
        parsers: dict[str, Callable[[str], None]] = {
            'whoami': self.parse_whoami,
            'whoami_priv': self.parse_whoami_priv,
            'whoami_groups': self.parse_whoami_groups,
            'systeminfo': self.parse_systeminfo,
            'netstat': self.parse_netstat,
            'icacls': self.parse_icacls,
            'sc_query': self.parse_sc_query,
            'schtasks': self.parse_schtasks,
            'reg_alwaysinstall': lambda output: self.parse_reg_query(output, 'alwaysinstallelevated'),
            'reg_autologon': lambda output: self.parse_reg_query(output, 'autologon'),
        }

        for cmd_name, output in commands.items():
            if cmd_name in parsers and output:
                try:
                    parsers[cmd_name](output)
                except (ValueError, KeyError, IndexError):
                    logging.getLogger(__name__).warning(f"Failed to parse {cmd_name}")
                except Exception:
                    logging.getLogger(__name__).error(f"Unexpected error parsing {cmd_name}", exc_info=True)

        return self.results

    def get_results(self) -> WinPEASResults:
        """Get the current parsed results."""
        return self.results
