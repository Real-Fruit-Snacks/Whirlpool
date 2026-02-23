"""Whirlpool CLI - Privilege Escalation Reasoning Engine.

Main command-line interface for analyzing enumeration output.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from . import __version__
from .engine.analyzer import Category
from .engine.chain import ChainDetector
from .engine.ranker import Ranker, RankingProfile
from .parser.linpeas import LinPEASParser
from .parser.winpeas import WinPEASParser

# Valid category names for --categories flag help text
_CATEGORY_NAMES = ", ".join(c.value for c in Category)


def detect_input_type(content: str) -> str:
    """Auto-detect the type of enumeration input.

    Args:
        content: File content to analyze

    Returns:
        One of: 'linpeas', 'winpeas', 'manual_linux', 'manual_windows', 'unknown'
    """
    content_lower = content.lower()

    # WinPEAS indicators - check BEFORE LinPEAS because WinPEAS .exe also uses ╔══════════╣
    if 'winpeas' in content_lower:
        return 'winpeas'
    # WinPEAS .bat format uses _-_-_-_-> markers
    if '_-_-_-_-_' in content:
        return 'winpeas'
    # WinPEAS .exe format uses ═══ with Windows-specific content
    if '═══' in content and ('privileges information' in content_lower or 'token privileges' in content_lower):
        return 'winpeas'

    # LinPEAS indicators - check for explicit name or distinctive section headers
    if 'linpeas' in content_lower or '╔══════════╣' in content:
        return 'linpeas'

    # Manual Linux indicators
    if 'uid=' in content_lower and 'gid=' in content_lower:
        return 'manual_linux'

    # Manual Windows indicators
    if 'privileges information' in content_lower or 'seimpersonate' in content_lower:
        return 'manual_windows'

    # Fallback heuristics with stricter matching
    if 'C:\\' in content or 'HKLM\\' in content:
        return 'manual_windows'

    return 'unknown'


def read_content(input_arg: str | None) -> str:
    """Read input content from a file path, '-' for stdin, or piped stdin.

    Args:
        input_arg: File path string, '-' for explicit stdin, or None to check
                   for piped stdin automatically.

    Returns:
        File content as a string.
    """
    if input_arg == '-' or (input_arg is None and not sys.stdin.isatty()):
        return sys.stdin.read()

    if input_arg is None:
        raise ValueError("input_arg must be a file path or '-' for stdin")

    path = Path(input_arg)

    # Guard against excessively large files
    max_size = 100 * 1024 * 1024  # 100 MB
    file_size = path.stat().st_size
    if file_size > max_size:
        raise ValueError(f"Input file exceeds {max_size // (1024 * 1024)}MB limit ({file_size // (1024 * 1024)}MB)")

    content = None
    for encoding in ['utf-8', 'utf-16', 'latin-1', 'cp1252']:
        try:
            content = path.read_text(encoding=encoding)
            break
        except UnicodeDecodeError:
            continue

    if content is None:
        content = path.read_bytes().decode('utf-8', errors='replace')

    return content


def parse_input(input_arg: str, input_type: str | None = None):
    """Parse input (file path or '-' for stdin) and return results.

    Args:
        input_arg: File path string or '-' for stdin
        input_type: Type of input (auto-detected if None)

    Returns:
        Tuple of (parsed results object, platform string)
    """
    content = read_content(input_arg)

    # Auto-detect type if not specified
    if input_type is None or input_type == 'auto':
        input_type = detect_input_type(content)

    # Parse based on type.
    # manual_linux and manual_windows use the same broad-pattern parsers as
    # linpeas/winpeas respectively, since those parsers handle arbitrary raw
    # text via _extract_from_all_lines(). The ManualLinuxParser/ManualWindowsParser
    # classes require a structured dict of individual command outputs and are
    # intended for programmatic use, not raw text blobs from the CLI.
    if input_type == 'linpeas':
        return LinPEASParser().parse(content), 'linux'
    elif input_type == 'winpeas':
        return WinPEASParser().parse(content), 'windows'
    elif input_type == 'manual_linux':
        return LinPEASParser().parse(content), 'linux'
    elif input_type == 'manual_windows':
        return WinPEASParser().parse(content), 'windows'
    else:
        # Try LinPEAS parser as default
        print("Warning: Could not detect input type, defaulting to LinPEAS parser", file=sys.stderr)
        return LinPEASParser().parse(content), 'linux'


def list_techniques() -> None:
    """Print a summary of all knowledge base contents and exit."""
    data_dir = Path(__file__).parent / 'data'

    def load(filename: str) -> dict:
        path = data_dir / filename
        if not path.exists():
            return {}
        with path.open(encoding='utf-8') as f:
            result: dict = json.load(f)
            return result

    gtfobins = load('gtfobins.json')
    kernel = load('kernel_exploits.json')
    potato = load('potato_matrix.json')
    lolbas = load('lolbas.json')

    gtfobins_count = len(gtfobins.get('binaries', {}))
    kernel_linux_count = len(kernel.get('linux', {}))
    kernel_windows_count = len(kernel.get('windows', {}))
    potato_count = len(potato.get('attacks', {}))
    lolbas_bin_count = len(lolbas.get('binaries', {}))
    lolbas_script_count = len(lolbas.get('scripts', {}))

    print(f"Whirlpool Knowledge Base Summary (v{__version__})")
    print("=" * 50)
    print(f"  GTFOBins entries     : {gtfobins_count}")
    print(f"  Kernel exploits      : {kernel_linux_count} Linux, {kernel_windows_count} Windows")
    print(f"  Potato attacks       : {potato_count}")
    print(f"  LOLBAS binaries      : {lolbas_bin_count}")
    print(f"  LOLBAS scripts       : {lolbas_script_count}")
    print()
    print(f"  Total KB entries     : "
          f"{gtfobins_count + kernel_linux_count + kernel_windows_count + potato_count + lolbas_bin_count + lolbas_script_count}")


def parse_categories(categories_str: str) -> list[Category]:
    """Parse a comma-separated list of category names into Category enum values.

    Args:
        categories_str: Comma-separated category names (e.g. 'suid,sudo,docker')

    Returns:
        List of Category enum values

    Raises:
        argparse.ArgumentTypeError: If any category name is invalid
    """
    valid = {c.value: c for c in Category}
    result = []
    for name in categories_str.split(','):
        name = name.strip().lower()
        if name not in valid:
            raise argparse.ArgumentTypeError(
                f"Invalid category '{name}'. Valid categories: {_CATEGORY_NAMES}"
            )
        result.append(valid[name])
    return result


def _substitute_placeholders(paths: list, lhost: str | None, lport: int | None) -> None:
    """Substitute attacker IP/port placeholders in all path commands in-place.

    Uses word-boundary regex to avoid corrupting patterns like ``LHOST=ATTACKER_IP``
    (which would otherwise become ``10.10.14.1=10.10.14.1``).

    Args:
        paths: List of ExploitationPath objects
        lhost: Attacker IP address (replaces ATTACKER_IP and LHOST)
        lport: Attacker port (replaces LPORT and ATTACKER_PORT)
    """
    lport_str = str(lport) if lport is not None else None

    for path in paths:
        new_commands = []
        for cmd in path.commands:
            if lhost is not None:
                cmd = re.sub(r'\bATTACKER_IP\b', lhost, cmd)
                cmd = re.sub(r'\bLHOST\b', lhost, cmd)
            if lport_str is not None:
                cmd = re.sub(r'\bLPORT\b', lport_str, cmd)
                cmd = re.sub(r'\bATTACKER_PORT\b', lport_str, cmd)
            new_commands.append(cmd)
        path.commands = new_commands


def _substitute_chain_placeholders(chains: list, lhost: str | None, lport: int | None) -> None:
    """Substitute attacker IP/port placeholders in attack chain step commands in-place.

    Args:
        chains: List of AttackChain objects
        lhost: Attacker IP address
        lport: Attacker port
    """
    lport_str = str(lport) if lport is not None else None

    for chain in chains:
        for step in chain.steps:
            new_commands = []
            for cmd in step.commands:
                if lhost is not None:
                    cmd = re.sub(r'\bATTACKER_IP\b', lhost, cmd)
                    cmd = re.sub(r'\bLHOST\b', lhost, cmd)
                if lport_str is not None:
                    cmd = re.sub(r'\bLPORT\b', lport_str, cmd)
                    cmd = re.sub(r'\bATTACKER_PORT\b', lport_str, cmd)
                new_commands.append(cmd)
            step.commands = new_commands


def _diff_paths(paths1: list, paths2: list) -> tuple[list, list]:
    """Compare two lists of ExploitationPath objects by technique_name.

    Args:
        paths1: Paths from the first (baseline) scan
        paths2: Paths from the second (comparison) scan

    Returns:
        Tuple of (new_paths, removed_paths) where new_paths are in paths2
        but not paths1, and removed_paths are in paths1 but not paths2.
    """
    keys1 = {(p.technique_name, p.finding) for p in paths1}
    keys2 = {(p.technique_name, p.finding) for p in paths2}

    new_paths = [p for p in paths2 if (p.technique_name, p.finding) not in keys1]
    removed_paths = [p for p in paths1 if (p.technique_name, p.finding) not in keys2]

    return new_paths, removed_paths


def main(args: list[str] | None = None) -> int:
    """Main CLI entry point.

    Args:
        args: Command line arguments (defaults to sys.argv)

    Returns:
        Exit code
    """
    parser = argparse.ArgumentParser(
        prog='whirlpool',
        description='Privilege Escalation Reasoning Engine - Analyze enumeration output and generate exploitation playbooks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  whirlpool linpeas_output.txt
  whirlpool -                                      # read from stdin
  cat linpeas.txt | whirlpool                      # pipe input
  whirlpool winpeas.txt --type winpeas --output report.md
  whirlpool enum.txt --format json --quick-wins
  whirlpool enum.txt --profile oscp --no-color
  whirlpool enum.txt --categories suid,sudo,docker
  whirlpool --list-techniques
        """
    )

    parser.add_argument(
        'input',
        nargs='?',
        help='Input file path, or "-" to read from stdin (omit when piping or using --list-techniques)'
    )

    parser.add_argument(
        '--list-techniques',
        action='store_true',
        help='Print a summary of all knowledge base entries and exit'
    )

    parser.add_argument(
        '-t', '--type',
        choices=['auto', 'linpeas', 'winpeas', 'manual_linux', 'manual_windows'],
        default='auto',
        help='Input type (default: auto-detect)'
    )

    parser.add_argument(
        '-f', '--format',
        choices=['terminal', 'markdown', 'json'],
        default='terminal',
        help='Output format (default: terminal)'
    )

    parser.add_argument(
        '-o', '--output',
        type=Path,
        help='Output file (default: stdout for terminal, otherwise based on format)'
    )

    parser.add_argument(
        '-p', '--profile',
        choices=['default', 'oscp', 'ctf', 'stealth', 'safe'],
        default='default',
        help='Ranking profile (default: default)'
    )

    parser.add_argument(
        '--categories',
        metavar='CAT[,CAT...]',
        help=(
            f'Filter results to these categories (comma-separated). '
            f'Valid values: {_CATEGORY_NAMES}'
        )
    )

    parser.add_argument(
        '--quick-wins',
        action='store_true',
        help='Only show quick wins (top 5 techniques)'
    )

    parser.add_argument(
        '--no-chains',
        action='store_true',
        help='Disable attack chain detection'
    )

    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output (terminal only)'
    )

    parser.add_argument(
        '--min-confidence',
        choices=['theoretical', 'low', 'medium', 'high'],
        help='Minimum confidence level to include'
    )

    parser.add_argument(
        '--max-risk',
        choices=['low', 'medium', 'high'],
        help='Maximum risk level to include'
    )

    parser.add_argument(
        '--lhost',
        metavar='IP',
        help='Attacker IP address; substitutes ATTACKER_IP and LHOST placeholders in commands'
    )

    parser.add_argument(
        '--lport',
        metavar='PORT',
        type=int,
        help='Attacker port; substitutes LPORT and ATTACKER_PORT placeholders in commands'
    )

    parser.add_argument(
        '--diff',
        metavar='SECOND_FILE',
        type=Path,
        help='Compare two enumeration scans and show only new/removed findings'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )

    parsed_args = parser.parse_args(args)

    # Handle --list-techniques: print summary and exit immediately
    if parsed_args.list_techniques:
        list_techniques()
        return 0

    # Determine the effective input source
    input_arg = parsed_args.input

    # Support piped stdin when no input argument is given
    if input_arg is None and not sys.stdin.isatty():
        input_arg = '-'

    if input_arg is None:
        parser.error('the following arguments are required: input (or pipe data via stdin, or use --list-techniques)')

    # Validate file path when not reading from stdin
    if input_arg != '-':
        input_path = Path(input_arg)
        if not input_path.exists():
            print(f"Error: Input file not found: {input_arg}", file=sys.stderr)
            return 1
        if not input_path.is_file():
            print(f"Error: Input is not a file: {input_arg}", file=sys.stderr)
            return 1

    # Parse --categories
    categories = None
    if parsed_args.categories:
        try:
            categories = parse_categories(parsed_args.categories)
        except argparse.ArgumentTypeError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    try:
        # Parse input
        if parsed_args.verbose:
            source = 'stdin' if input_arg == '-' else input_arg
            print(f"Parsing input: {source}", file=sys.stderr)

        results, platform = parse_input(input_arg, parsed_args.type)

        if parsed_args.verbose:
            print(f"Detected platform: {platform}", file=sys.stderr)

        # Analyze
        from .engine.analyzer import Analyzer
        analyzer = Analyzer()

        if platform == 'linux':
            paths = analyzer.analyze_linux(results)
        else:
            paths = analyzer.analyze_windows(results)

        if parsed_args.verbose:
            print(f"Found {len(paths)} exploitation paths", file=sys.stderr)

        # Detect chains
        chains = []
        if not parsed_args.no_chains:
            chain_detector = ChainDetector()
            chains = chain_detector.detect_chains(results)

            if parsed_args.verbose:
                print(f"Found {len(chains)} attack chains", file=sys.stderr)

        # Rank with profile
        profile = RankingProfile[parsed_args.profile.upper()]
        ranker = Ranker(profile=profile)

        # Apply filters
        from .engine.analyzer import Confidence, Risk

        min_conf = None
        if parsed_args.min_confidence:
            min_conf = Confidence[parsed_args.min_confidence.upper()]

        max_risk = None
        if parsed_args.max_risk:
            max_risk = Risk[parsed_args.max_risk.upper()]

        paths = ranker.rank(
            paths,
            quick_wins_only=parsed_args.quick_wins,
            min_confidence=min_conf,
            max_risk=max_risk,
            categories=categories
        )

        # Handle --diff mode: parse second file, analyze, compare
        diff_new: list | None = None
        diff_removed: list | None = None
        if parsed_args.diff:
            diff_path = parsed_args.diff
            if not diff_path.exists():
                print(f"Error: Diff file not found: {diff_path}", file=sys.stderr)
                return 1
            if not diff_path.is_file():
                print(f"Error: Diff path is not a file: {diff_path}", file=sys.stderr)
                return 1

            results2, platform2 = parse_input(str(diff_path), parsed_args.type)
            if platform2 == 'linux':
                paths2 = analyzer.analyze_linux(results2)
            else:
                paths2 = analyzer.analyze_windows(results2)

            paths2 = ranker.rank(
                paths2,
                min_confidence=min_conf,
                max_risk=max_risk,
                categories=categories
            )

            diff_new, diff_removed = _diff_paths(paths, paths2)

        # Substitute --lhost / --lport placeholders
        lhost = parsed_args.lhost
        lport = parsed_args.lport
        if lhost is not None or lport is not None:
            _substitute_placeholders(paths, lhost, lport)
            _substitute_chain_placeholders(chains, lhost, lport)
            if diff_new:
                _substitute_placeholders(diff_new, lhost, lport)
            if diff_removed:
                _substitute_placeholders(diff_removed, lhost, lport)

        # Build target info
        target_info = {}
        if hasattr(results, 'hostname') and results.hostname:
            target_info['hostname'] = results.hostname
        if hasattr(results, 'os_release') and results.os_release:
            target_info['os'] = results.os_release
        elif hasattr(results, 'os_version') and results.os_version:
            target_info['os'] = results.os_version
        if hasattr(results, 'kernel_version') and results.kernel_version:
            target_info['kernel'] = results.kernel_version
        if hasattr(results, 'current_user') and results.current_user:
            target_info['user'] = results.current_user
        if hasattr(results, 'current_groups') and results.current_groups:
            target_info['groups'] = results.current_groups

        # Generate output
        if parsed_args.format == 'terminal':
            try:
                from .output.terminal import TerminalOutput

                output = TerminalOutput(
                    no_color=parsed_args.no_color,
                    profile=parsed_args.profile,
                )
                output.print_header(target_info, paths=paths)

                if diff_new is not None or diff_removed is not None:
                    # Diff mode: show new and removed findings
                    if diff_new:
                        print("\n=== NEW FINDINGS ===")
                        output.print_all_paths(diff_new)
                    else:
                        print("\n=== NEW FINDINGS: none ===")

                    if diff_removed:
                        print("\n=== REMOVED FINDINGS ===")
                        output.print_all_paths(diff_removed)
                    else:
                        print("\n=== REMOVED FINDINGS: none ===")
                else:
                    output.print_quick_wins(paths)
                    if not parsed_args.quick_wins:
                        output.print_all_paths(paths)
                        if chains:
                            output.print_chains(chains)
                        output.print_summary(paths)

            except ImportError:
                # Fallback to simple output
                print("=" * 60)
                print("WHIRLPOOL - Privilege Escalation Analysis")
                print("=" * 60)
                print()

                if target_info:
                    print("Target Information:")
                    for k, v in target_info.items():
                        print(f"  {k}: {v}")
                    print()

                if diff_new is not None or diff_removed is not None:
                    print("\n=== NEW FINDINGS ===")
                    for i, path in enumerate(diff_new or [], 1):
                        print(f"[{i}] {path.technique_name}")
                        print(f"    {path.description}")
                        print()
                    print("\n=== REMOVED FINDINGS ===")
                    for i, path in enumerate(diff_removed or [], 1):
                        print(f"[{i}] {path.technique_name}")
                        print(f"    {path.description}")
                        print()
                else:
                    print(f"Found {len(paths)} exploitation paths")
                    print()

                    for i, path in enumerate(paths[:10], 1):
                        score = ranker.get_score(path)
                        print(f"[{i}] {path.technique_name} (Score: {score:.0f})")
                        print(f"    {path.description}")
                        print(f"    Finding: {path.finding}")
                        if path.commands:
                            print("    Commands:")
                            for cmd in path.commands[:3]:
                                print(f"      {cmd}")
                        print()

        elif parsed_args.format == 'markdown':
            from .output.markdown import MarkdownOutput

            md_output = MarkdownOutput()
            content = md_output.generate(paths, chains=chains, target_info=target_info)

            if parsed_args.output:
                parsed_args.output.write_text(content, encoding='utf-8')
                print(f"Report saved to: {parsed_args.output}", file=sys.stderr)
            else:
                print(content)

        elif parsed_args.format == 'json':
            from .output.json_out import JSONOutput

            json_output = JSONOutput()
            content = json_output.to_json(paths, chains=chains, target_info=target_info)

            if parsed_args.output:
                parsed_args.output.write_text(content, encoding='utf-8')
                print(f"Report saved to: {parsed_args.output}", file=sys.stderr)
            else:
                print(content)

        return 0

    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 130
    except (MemoryError, RecursionError):
        raise
    except Exception as e:
        print(f"Error ({type(e).__name__}): {e}", file=sys.stderr)
        if parsed_args.verbose:
            import traceback
            traceback.print_exc()
        else:
            print("Use --verbose for full traceback", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
