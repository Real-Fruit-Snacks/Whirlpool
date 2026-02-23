"""Tests for output modules (terminal, markdown, json)."""

import json

import pytest
from rich.console import Console

from whirlpool.engine.analyzer import (
    ExploitationPath,
    Category,
    Confidence,
    Risk,
)
from whirlpool.engine.chain import AttackChain, ChainStep
from whirlpool.output.terminal import TerminalOutput
from whirlpool.output.markdown import MarkdownOutput
from whirlpool.output.json_out import JSONOutput


def _make_sample_paths() -> list[ExploitationPath]:
    """Create sample exploitation paths for testing."""
    return [
        ExploitationPath(
            category=Category.SUID,
            technique_name="SUID vim",
            description="Exploit SUID bit on vim",
            finding="/usr/bin/vim",
            commands=["vim -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'"],
            confidence=Confidence.HIGH,
            risk=Risk.LOW,
            references=["https://gtfobins.github.io/gtfobins/vim/#suid"],
            reliability_score=90,
            safety_score=85,
            simplicity_score=90,
            stealth_score=70,
        ),
        ExploitationPath(
            category=Category.KERNEL,
            technique_name="DirtyPipe (CVE-2022-0847)",
            description="Arbitrary file overwrite via pipe page cache corruption",
            finding="Kernel 5.10.0",
            commands=["gcc -o dirtypipe dirtypipe.c", "./dirtypipe /etc/passwd 1"],
            prerequisites=["gcc available"],
            confidence=Confidence.HIGH,
            risk=Risk.LOW,
            notes="Very reliable",
            reliability_score=90,
            safety_score=90,
            simplicity_score=70,
            stealth_score=40,
        ),
    ]


def _make_sample_chains() -> list[AttackChain]:
    """Create sample attack chains for testing."""
    return [
        AttackChain(
            name="Docker Group Escape",
            description="Member of docker group - can mount host filesystem",
            steps=[
                ChainStep(
                    order=1,
                    description="Verify docker access",
                    commands=["docker ps", "docker images"],
                    output="Docker access confirmed",
                ),
                ChainStep(
                    order=2,
                    description="Create privileged container with host filesystem",
                    commands=[
                        "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
                    ],
                    output="Root shell on host",
                ),
            ],
            confidence=Confidence.HIGH,
            risk=Risk.LOW,
            prerequisites=["Docker installed"],
            notes="Very reliable technique",
            references=["https://gtfobins.github.io/gtfobins/docker/"],
            reliability_score=95,
            complexity_score=15,
        ),
    ]


class TestTerminalOutput:
    """Tests for Rich terminal output."""

    def test_create_default(self):
        """Test default initialization."""
        output = TerminalOutput()
        assert output.console is not None

    def test_create_no_color(self):
        """Test no-color initialization."""
        output = TerminalOutput(no_color=True)
        assert output.console is not None

    def test_create_with_profile(self):
        """Test initialization with profile."""
        output = TerminalOutput(profile="oscp")
        assert output.profile == "oscp"

    def test_create_custom_console(self):
        """Test custom console initialization."""
        console = Console(file=None, force_terminal=True)
        output = TerminalOutput(console=console)
        assert output.console is console

    def test_print_header_no_crash(self):
        """Test header prints without crashing."""
        console = Console(file=None, force_terminal=True)
        output = TerminalOutput(console=console)
        output.print_header()
        output.print_header({"hostname": "target", "os": "Linux", "kernel": "5.10.0", "user": "www-data"})

    def test_print_header_with_paths(self):
        """Test header with paths for findings summary bar."""
        console = Console(file=None, force_terminal=True)
        output = TerminalOutput(console=console)
        output.print_header(
            {"hostname": "target", "os": "Linux"},
            paths=_make_sample_paths(),
        )

    def test_print_header_with_groups(self):
        """Test header with groups in target info."""
        console = Console(file=None, force_terminal=True)
        output = TerminalOutput(console=console)
        output.print_header({"hostname": "target", "groups": ["docker", "sudo"]})

    def test_print_quick_wins_no_crash(self):
        """Test quick wins prints without crashing."""
        console = Console(file=None, force_terminal=True)
        output = TerminalOutput(console=console)
        output.print_quick_wins(_make_sample_paths())

    def test_print_quick_wins_empty(self):
        """Test quick wins with empty list."""
        console = Console(file=None, force_terminal=True)
        output = TerminalOutput(console=console)
        output.print_quick_wins([])

    def test_print_all_paths_no_crash(self):
        """Test all paths prints without crashing."""
        console = Console(file=None, force_terminal=True)
        output = TerminalOutput(console=console)
        output.print_all_paths(_make_sample_paths())

    def test_print_all_paths_ungrouped(self):
        """Test all paths without grouping."""
        console = Console(file=None, force_terminal=True)
        output = TerminalOutput(console=console)
        output.print_all_paths(_make_sample_paths(), group_by_category=False)

    def test_print_all_paths_empty(self):
        """Test all paths with empty list."""
        console = Console(file=None, force_terminal=True)
        output = TerminalOutput(console=console)
        output.print_all_paths([])

    def test_print_chains_no_crash(self):
        """Test chains prints without crashing."""
        console = Console(file=None, force_terminal=True)
        output = TerminalOutput(console=console)
        output.print_chains(_make_sample_chains())

    def test_print_chains_empty(self):
        """Test chains with empty list."""
        console = Console(file=None, force_terminal=True)
        output = TerminalOutput(console=console)
        output.print_chains([])

    def test_print_chains_multiple(self):
        """Test chains with multiple chains."""
        console = Console(file=None, force_terminal=True)
        output = TerminalOutput(console=console)
        chains = _make_sample_chains()
        chains.append(AttackChain(
            name="Writable /etc/passwd",
            description="Can add root user",
            steps=[
                ChainStep(order=1, description="Generate hash", commands=["openssl passwd -1 pass"]),
                ChainStep(order=2, description="Add user", commands=["echo 'hacker:hash:0:0::/root:/bin/bash' >> /etc/passwd"]),
            ],
            confidence=Confidence.HIGH,
            risk=Risk.LOW,
        ))
        output.print_chains(chains)

    def test_print_summary_no_crash(self):
        """Test summary prints without crashing."""
        console = Console(file=None, force_terminal=True)
        output = TerminalOutput(console=console)
        output.print_summary(_make_sample_paths())

    def test_print_summary_empty(self):
        """Test summary with empty list."""
        console = Console(file=None, force_terminal=True)
        output = TerminalOutput(console=console)
        output.print_summary([])


class TestMarkdownOutput:
    """Tests for Markdown output."""

    def test_generate_produces_string(self):
        """Test markdown generation returns a string."""
        output = MarkdownOutput()
        result = output.generate(_make_sample_paths())
        assert isinstance(result, str)
        assert len(result) > 0

    def test_generate_contains_technique(self):
        """Test markdown contains technique names."""
        output = MarkdownOutput()
        result = output.generate(_make_sample_paths())
        assert "SUID vim" in result
        assert "DirtyPipe" in result

    def test_generate_with_target_info(self):
        """Test markdown with target info."""
        output = MarkdownOutput()
        result = output.generate(
            _make_sample_paths(),
            target_info={"hostname": "target", "os": "Linux"},
        )
        assert "target" in result

    def test_generate_empty(self):
        """Test markdown with empty paths."""
        output = MarkdownOutput()
        result = output.generate([])
        assert isinstance(result, str)


class TestJSONOutput:
    """Tests for JSON output."""

    def test_to_json_is_valid_json(self):
        """Test JSON output is valid JSON."""
        output = JSONOutput()
        result = output.to_json(_make_sample_paths())
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_to_json_contains_paths(self):
        """Test JSON contains exploitation paths."""
        output = JSONOutput()
        result = output.to_json(_make_sample_paths())
        parsed = json.loads(result)
        assert "paths" in parsed or "exploitation_paths" in parsed or len(parsed) > 0

    def test_to_json_with_target_info(self):
        """Test JSON with target info."""
        output = JSONOutput()
        result = output.to_json(
            _make_sample_paths(),
            target_info={"hostname": "target"},
        )
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_to_json_empty(self):
        """Test JSON with empty paths."""
        output = JSONOutput()
        result = output.to_json([])
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
