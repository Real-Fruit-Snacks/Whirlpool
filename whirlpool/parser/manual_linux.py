"""Parser for manual Linux enumeration commands.

Parses output from common manual enumeration commands like id, sudo -l, etc.
"""

from __future__ import annotations

import logging
import re

from .linpeas import (
    LinPEASResults,
    SUIDEntry,
    CapabilityEntry,
    CronEntry,
    SudoEntry,
    NetworkService,
    UserInfo,
)


class ManualLinuxParser:
    """Parser for manual Linux enumeration command outputs."""

    def __init__(self):
        self.results = LinPEASResults()

    def parse_id(self, output: str) -> None:
        """Parse 'id' command output.

        Example: uid=1000(user) gid=1000(user) groups=1000(user),27(sudo),999(docker)
        """
        output = output.strip()

        # Parse uid
        uid_match = re.search(r'uid=(\d+)\(([^)]+)\)', output)
        if uid_match:
            self.results.current_uid = int(uid_match.group(1))
            self.results.current_user = uid_match.group(2)

        # Parse gid
        gid_match = re.search(r'gid=(\d+)', output)
        if gid_match:
            self.results.current_gid = int(gid_match.group(1))

        # Parse groups
        groups_match = re.search(r'groups=(.+)$', output)
        if groups_match:
            groups_str = groups_match.group(1)
            for g in groups_str.split(','):
                match = re.search(r'\(([^)]+)\)', g)
                if match:
                    self.results.current_groups.append(match.group(1))

    def parse_whoami(self, output: str) -> None:
        """Parse 'whoami' command output."""
        self.results.current_user = output.strip()

    def parse_groups(self, output: str) -> None:
        """Parse 'groups' command output.

        Example: user sudo docker lxd
        """
        groups = output.strip().split()
        # First element might be username
        if groups and groups[0] == self.results.current_user:
            groups = groups[1:]
        self.results.current_groups.extend(groups)

    def parse_find_suid(self, output: str) -> None:
        """Parse 'find -perm -4000' output.

        Expected input: List of SUID binary paths, one per line.
        """
        for line in output.strip().splitlines():
            line = line.strip()
            if line.startswith('/') and not line.startswith('find:'):
                entry = SUIDEntry(path=line)
                self.results.suid_binaries.append(entry)

    def parse_find_sgid(self, output: str) -> None:
        """Parse 'find -perm -2000' output."""
        for line in output.strip().splitlines():
            line = line.strip()
            if line.startswith('/') and not line.startswith('find:'):
                entry = SUIDEntry(path=line)
                self.results.sgid_binaries.append(entry)

    def parse_getcap(self, output: str) -> None:
        """Parse 'getcap -r /' output.

        Example: /usr/bin/python3.8 = cap_setuid+ep
        """
        for line in output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith('getcap:'):
                continue

            # Pattern: /path/to/binary = capabilities
            match = re.match(r'^(\S+)\s*[=:]\s*(.+)$', line)
            if match:
                path, cap_str = match.groups()

                # Parse individual capabilities
                caps = []
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
                    self.results.capabilities.append(entry)

    def parse_crontab(self, output: str, file_path: str = "/etc/crontab") -> None:
        """Parse crontab file content.

        Example:
        # m h dom mon dow user command
        17 * * * * root cd / && run-parts --report /etc/cron.hourly
        """
        cron_pattern = re.compile(
            r'^([\d\*,/-]+\s+[\d\*,/-]+\s+[\d\*,/-]+\s+[\d\*,/-]+\s+[\d\*,/-]+)\s+'
            r'(\S+)\s+'
            r'(.+)$'
        )

        for line in output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            match = cron_pattern.match(line)
            if match:
                schedule, user, command = match.groups()
                entry = CronEntry(
                    schedule=schedule,
                    user=user,
                    command=command,
                    file_path=file_path
                )
                self.results.cron_jobs.append(entry)

    def parse_sudo_l(self, output: str) -> None:
        """Parse 'sudo -l' output.

        Example:
        User user may run the following commands on host:
            (ALL : ALL) NOPASSWD: /usr/bin/vim
            (root) /usr/bin/find
        """
        # Pattern for sudo entries
        sudo_pattern = re.compile(r'\(([^)]+)\)\s*(NOPASSWD:)?\s*(.+)$')

        for line in output.strip().splitlines():
            line = line.strip()

            match = sudo_pattern.search(line)
            if match:
                runas, nopasswd, commands = match.groups()
                entry = SudoEntry(
                    user=self.results.current_user,
                    runas=runas,
                    commands=[cmd.strip() for cmd in commands.split(',')],
                    nopasswd=bool(nopasswd),
                    raw_line=line
                )
                self.results.sudo_rights.append(entry)

    def parse_uname(self, output: str) -> None:
        """Parse 'uname -a' output.

        Example: Linux hostname 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux
        """
        output = output.strip()

        # Extract kernel version
        version_match = re.search(r'(\d+\.\d+\.\d+)', output)
        if version_match:
            self.results.kernel_version = version_match.group(1)

        # Full kernel release
        release_match = re.search(r'Linux\s+\S+\s+(\S+)', output)
        if release_match:
            self.results.kernel_release = release_match.group(1)

        # Hostname
        parts = output.split()
        if len(parts) >= 2:
            self.results.hostname = parts[1]

        # Architecture
        if 'x86_64' in output:
            self.results.architecture = 'x86_64'
        elif 'i686' in output or 'i386' in output:
            self.results.architecture = 'i386'
        elif 'aarch64' in output or 'arm64' in output:
            self.results.architecture = 'aarch64'

    def parse_netstat(self, output: str) -> None:
        """Parse 'netstat -tulpn' or 'ss -tulpn' output.

        Example:
        tcp  0  0 0.0.0.0:22  0.0.0.0:*  LISTEN  1234/sshd
        """
        service_pattern = re.compile(
            r'(tcp|udp)\S*\s+'
            r'\d+\s+\d+\s+'
            r'([\d\.\*:]+):(\d+)\s+'
            r'([\d\.\*:]+):(\S+)\s+'
            r'(\S+)?'
        )

        for line in output.strip().splitlines():
            line = line.strip()
            if not line or 'Proto' in line:
                continue

            match = service_pattern.search(line)
            if match:
                proto, local_addr, local_port, foreign_addr, foreign_port, state = match.groups()

                # Extract PID/program
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

    def parse_passwd(self, output: str) -> None:
        """Parse /etc/passwd content.

        Example: root:x:0:0:root:/root:/bin/bash
        """
        for line in output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split(':')
            if len(parts) >= 7:
                username, _, uid, gid, _, home, shell = parts[:7]
                user = UserInfo(
                    username=username,
                    uid=int(uid) if uid.isdigit() else 0,
                    gid=int(gid) if gid.isdigit() else 0,
                    home=home,
                    shell=shell
                )
                self.results.users.append(user)

    def parse_exports(self, output: str) -> None:
        """Parse /etc/exports content.

        Example: /shared *(rw,no_root_squash)
        """
        for line in output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if '(' in line:
                self.results.nfs_exports.append(line)

                if 'no_root_squash' in line.lower():
                    path = line.split('(')[0].strip()
                    self.results.nfs_no_root_squash.append(path)

    def parse_ls_la(self, output: str, context: str = "suid") -> None:
        """Parse 'ls -la' output and extract file information.

        Args:
            output: ls -la output
            context: What type of files (suid, sgid, writable, etc.)
        """
        ls_pattern = re.compile(
            r'^([drwxsStT-]{10})\s+'
            r'(\d+)\s+'
            r'(\S+)\s+'
            r'(\S+)\s+'
            r'(\d+)\s+'
            r'(.{10,12})\s+'
            r'(.+)$'
        )

        for line in output.strip().splitlines():
            line = line.strip()

            match = ls_pattern.match(line)
            if match:
                perms, _, owner, group, size, date, path = match.groups()

                entry = SUIDEntry(
                    path=path,
                    owner=owner,
                    group=group,
                    permissions=perms,
                    size=size,
                    date=date.strip()
                )

                if context == "suid" and 's' in perms[3].lower():
                    self.results.suid_binaries.append(entry)
                elif context == "sgid" and 's' in perms[6].lower():
                    self.results.sgid_binaries.append(entry)

    def parse_all(self, commands: dict[str, str]) -> LinPEASResults:
        """Parse multiple command outputs.

        Args:
            commands: Dictionary mapping command names to their output.
                     Supported keys: id, whoami, groups, find_suid, find_sgid,
                     getcap, crontab, sudo_l, uname, netstat, passwd, exports

        Returns:
            LinPEASResults with all parsed data
        """
        parsers = {
            'id': self.parse_id,
            'whoami': self.parse_whoami,
            'groups': self.parse_groups,
            'find_suid': self.parse_find_suid,
            'find_sgid': self.parse_find_sgid,
            'getcap': self.parse_getcap,
            'crontab': self.parse_crontab,
            'sudo_l': self.parse_sudo_l,
            'uname': self.parse_uname,
            'netstat': self.parse_netstat,
            'passwd': self.parse_passwd,
            'exports': self.parse_exports,
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

    def get_results(self) -> LinPEASResults:
        """Get the current parsed results."""
        return self.results
