"""Whirlpool CLI - Privilege Escalation Reasoning Engine.

Main command-line interface for analyzing enumeration output.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine.analyzer import Analyzer
from .engine.chain import ChainDetector
from .engine.ranker import Ranker, RankingProfile
from .parser.linpeas import LinPEASParser
from .parser.winpeas import WinPEASParser


def detect_input_type(content: str) -> str:
    """Auto-detect the type of enumeration input.

    Args:
        content: File content to analyze

    Returns:
        One of: 'linpeas', 'winpeas', 'manual_linux', 'manual_windows', 'unknown'
    """
    content_lower = content.lower()

    # LinPEAS indicators - check for explicit name or distinctive section headers
    if 'linpeas' in content_lower or '╔══════════╣' in content:
        return 'linpeas'

    # WinPEAS indicators - check for explicit name or distinctive format markers
    if 'winpeas' in content_lower:
        return 'winpeas'
    # WinPEAS .bat format uses _-_-_-_-> markers
    if '_-_-_-_-_' in content:
        return 'winpeas'
    # WinPEAS .exe format uses ═══ with Windows-specific content
    if '═══' in content and ('privileges information' in content_lower or 'token privileges' in content_lower):
        return 'winpeas'

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


def parse_input(file_path: Path, input_type: str | None = None):
    """Parse input file and return results.

    Args:
        file_path: Path to the input file
        input_type: Type of input (auto-detected if None)

    Returns:
        Parsed results object
    """
    # Read file content
    content = None
    for encoding in ['utf-8', 'utf-16', 'latin-1', 'cp1252']:
        try:
            content = file_path.read_text(encoding=encoding)
            break
        except UnicodeDecodeError:
            continue

    if content is None:
        content = file_path.read_bytes().decode('utf-8', errors='replace')

    # Auto-detect type if not specified
    if input_type is None or input_type == 'auto':
        input_type = detect_input_type(content)

    # Parse based on type
    if input_type == 'linpeas':
        return LinPEASParser().parse(content), 'linux'
    elif input_type == 'winpeas':
        return WinPEASParser().parse(content), 'windows'
    elif input_type == 'manual_linux':
        # Use LinPEAS parser which handles arbitrary Linux enumeration output
        return LinPEASParser().parse(content), 'linux'
    elif input_type == 'manual_windows':
        # Use WinPEAS parser which handles arbitrary Windows enumeration output
        return WinPEASParser().parse(content), 'windows'
    else:
        # Try LinPEAS parser as default
        return LinPEASParser().parse(content), 'linux'


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
  whirlpool winpeas.txt --type winpeas --output report.md
  whirlpool enum.txt --format json --quick-wins
  whirlpool enum.txt --profile oscp --no-color
        """
    )

    parser.add_argument(
        'input',
        type=Path,
        help='Input file (LinPEAS, WinPEAS, or manual enumeration output)'
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

    # Validate input file
    if not parsed_args.input.exists():
        print(f"Error: Input file not found: {parsed_args.input}", file=sys.stderr)
        return 1

    if not parsed_args.input.is_file():
        print(f"Error: Input is not a file: {parsed_args.input}", file=sys.stderr)
        return 1

    try:
        # Parse input
        if parsed_args.verbose:
            print(f"Parsing input file: {parsed_args.input}", file=sys.stderr)

        results, platform = parse_input(parsed_args.input, parsed_args.type)

        if parsed_args.verbose:
            print(f"Detected platform: {platform}", file=sys.stderr)

        # Analyze
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
            max_risk=max_risk
        )

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
                parsed_args.output.write_text(content)
                print(f"Report saved to: {parsed_args.output}", file=sys.stderr)
            else:
                print(content)

        elif parsed_args.format == 'json':
            from .output.json_out import JSONOutput

            json_output = JSONOutput()
            content = json_output.to_json(paths, chains=chains, target_info=target_info)

            if parsed_args.output:
                parsed_args.output.write_text(content)
                print(f"Report saved to: {parsed_args.output}", file=sys.stderr)
            else:
                print(content)

        return 0

    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 130
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
