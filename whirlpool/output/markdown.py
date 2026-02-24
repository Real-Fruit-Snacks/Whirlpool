"""Markdown output formatter for analysis results.

Generates clean markdown for OSCP reports and CTF writeups.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ..engine.analyzer import Confidence, ExploitationPath, Risk
from ..engine.chain import AttackChain
from ..engine.ranker import Ranker

_MD_SPECIAL = re.compile(r'([\\`*_\{\}\[\]()#+\-.!|])')


def _escape_md(text: str) -> str:
    """Escape markdown special characters in user-derived text."""
    return _MD_SPECIAL.sub(r'\\\1', text)


def _safe_code_block(text: str) -> str:
    """Escape triple backticks inside text placed in fenced code blocks."""
    return text.replace('```', '` ` `')


class MarkdownOutput:
    """Markdown output formatter."""

    def __init__(self, ranker: Ranker | None = None):
        self.ranker = ranker or Ranker()

    def generate(
        self,
        paths: list[ExploitationPath],
        chains: list[AttackChain] | None = None,
        target_info: dict | None = None,
        include_toc: bool = True
    ) -> str:
        """Generate full markdown report.

        Args:
            paths: List of exploitation paths
            chains: Optional list of attack chains
            target_info: Optional target information
            include_toc: Whether to include table of contents

        Returns:
            Markdown formatted string
        """
        sections = []

        # Header
        sections.append(self._generate_header(target_info))

        # Table of contents
        if include_toc:
            sections.append(self._generate_toc(paths, chains))

        # Executive summary
        sections.append(self._generate_summary(paths))

        # Quick wins
        quick_wins = self.ranker.get_quick_wins(paths, top_n=5)
        if quick_wins:
            sections.append(self._generate_quick_wins(quick_wins))

        # Attack chains
        if chains:
            sections.append(self._generate_chains(chains))

        # Detailed findings by category
        sections.append(self._generate_findings(paths))

        # Appendix
        sections.append(self._generate_appendix(target_info))

        return "\n\n".join(sections)

    def save(
        self,
        paths: list[ExploitationPath],
        output_path: str | Path,
        **kwargs
    ) -> None:
        """Save markdown report to file.

        Args:
            paths: List of exploitation paths
            output_path: Path to save the report
            **kwargs: Additional arguments passed to generate()
        """
        content = self.generate(paths, **kwargs)
        Path(output_path).write_text(content, encoding='utf-8')

    def _generate_header(self, target_info: dict | None) -> str:
        """Generate report header."""
        lines = [
            "# Privilege Escalation Analysis Report",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "**Tool:** Whirlpool Privilege Escalation Analyzer",
        ]

        if target_info:
            lines.append("")
            lines.append("## Target Information")
            lines.append("")
            if "hostname" in target_info:
                lines.append(f"- **Hostname:** {_escape_md(target_info['hostname'])}")
            if "os" in target_info:
                lines.append(f"- **OS:** {_escape_md(target_info['os'])}")
            if "kernel" in target_info:
                lines.append(f"- **Kernel:** {_escape_md(target_info['kernel'])}")
            if "user" in target_info:
                lines.append(f"- **Current User:** {_escape_md(target_info['user'])}")
            if "groups" in target_info:
                lines.append(f"- **Groups:** {_escape_md(', '.join(target_info['groups']))}")

        return "\n".join(lines)

    def _generate_toc(
        self,
        paths: list[ExploitationPath],
        chains: list[AttackChain] | None
    ) -> str:
        """Generate table of contents."""
        lines = [
            "## Table of Contents",
            "",
            "1. [Executive Summary](#executive-summary)",
            "2. [Quick Wins](#quick-wins)",
        ]

        if chains:
            lines.append("3. [Attack Chains](#attack-chains)")
            lines.append("4. [Detailed Findings](#detailed-findings)")
        else:
            lines.append("3. [Detailed Findings](#detailed-findings)")

        # Add category sections
        categories = {p.category for p in paths}
        for cat in sorted(categories, key=lambda c: c.value):
            anchor = cat.value.lower().replace("_", "-")
            lines.append(f"   - [{cat.value.upper()}](#{anchor})")

        lines.append(f"{'5' if chains else '4'}. [Appendix](#appendix)")

        return "\n".join(lines)

    def _generate_summary(self, paths: list[ExploitationPath]) -> str:
        """Generate executive summary."""
        # Count by confidence and risk
        high_conf = sum(1 for p in paths if p.confidence == Confidence.HIGH)
        low_risk = sum(1 for p in paths if p.risk == Risk.LOW)
        categories = {p.category for p in paths}

        lines = [
            "## Executive Summary",
            "",
            f"The analysis identified **{len(paths)} potential privilege escalation vectors** "
            f"across **{len(categories)} categories**.",
            "",
            "### Key Findings",
            "",
            f"- **High Confidence Techniques:** {high_conf}",
            f"- **Low Risk Techniques:** {low_risk}",
            f"- **Categories Affected:** {', '.join(c.value for c in categories)}",
        ]

        # Top recommendation
        ranked = self.ranker.rank(paths)
        if ranked:
            top = ranked[0]
            score = self.ranker.get_score(top)
            lines.extend([
                "",
                "### Top Recommendation",
                "",
                f"**{top.technique_name}** (Score: {score:.0f}/100)",
                "",
                f"> {top.description}",
            ])

        return "\n".join(lines)

    def _generate_quick_wins(self, quick_wins: list[ExploitationPath]) -> str:
        """Generate quick wins section."""
        lines = [
            "## Quick Wins",
            "",
            "The following techniques have the highest probability of success:",
            "",
        ]

        for i, path in enumerate(quick_wins, 1):
            score = self.ranker.get_score(path)
            lines.extend([
                f"### {i}. {_escape_md(path.technique_name)}",
                "",
                f"**Score:** {score:.0f}/100 | "
                f"**Confidence:** {path.confidence.value} | "
                f"**Risk:** {path.risk.value}",
                "",
                f"{_escape_md(path.description)}",
                "",
                "**Finding:**",
                "```",
                f"{_safe_code_block(path.finding)}",
                "```",
                "",
            ])

            if path.commands:
                lines.append("**Exploitation:**")
                lines.append("```bash")
                for cmd in path.commands:
                    lines.append(_safe_code_block(cmd))
                lines.append("```")
                lines.append("")

        return "\n".join(lines)

    def _generate_chains(self, chains: list[AttackChain]) -> str:
        """Generate attack chains section."""
        lines = [
            "## Attack Chains",
            "",
            "The following multi-step attack paths were identified:",
            "",
        ]

        for chain in chains:
            lines.extend([
                f"### {chain.name}",
                "",
                f"{chain.description}",
                "",
                f"**Confidence:** {chain.confidence.value} | "
                f"**Risk:** {chain.risk.value} | "
                f"**Steps:** {chain.total_steps}",
                "",
            ])

            if chain.prerequisites:
                lines.append("**Prerequisites:**")
                for prereq in chain.prerequisites:
                    lines.append(f"- {prereq}")
                lines.append("")

            lines.append("**Steps:**")
            lines.append("")
            for step in chain.steps:
                lines.append(f"#### Step {step.order}: {step.description}")
                lines.append("")
                if step.commands:
                    lines.append("```bash")
                    for cmd in step.commands:
                        lines.append(_safe_code_block(cmd))
                    lines.append("```")
                    lines.append("")

            if chain.notes:
                lines.append(f"> **Note:** {chain.notes}")
                lines.append("")

        return "\n".join(lines)

    def _generate_findings(self, paths: list[ExploitationPath]) -> str:
        """Generate detailed findings by category."""
        lines = [
            "## Detailed Findings",
            "",
        ]

        # Group by category
        grouped = self.ranker.group_by_category(paths)

        for category, cat_paths in sorted(grouped.items(), key=lambda x: x[0].value):
            lines.extend([
                f"### {category.value.upper().replace('_', ' ')}",
                "",
                f"Found **{len(cat_paths)}** technique(s) in this category.",
                "",
            ])

            for path in cat_paths:
                score = self.ranker.get_score(path)
                lines.extend([
                    f"#### {path.technique_name}",
                    "",
                    "| Metric | Value |",
                    "|--------|-------|",
                    f"| Score | {score:.0f}/100 |",
                    f"| Confidence | {path.confidence.value} |",
                    f"| Risk | {path.risk.value} |",
                    "",
                    f"**Description:** {path.description}",
                    "",
                    "**Finding:**",
                    "```",
                    f"{_safe_code_block(path.finding)}",
                    "```",
                    "",
                ])

                if path.prerequisites:
                    lines.append("**Prerequisites:**")
                    for prereq in path.prerequisites:
                        lines.append(f"- {prereq}")
                    lines.append("")

                if path.commands:
                    lines.append("**Commands:**")
                    lines.append("```bash")
                    for cmd in path.commands:
                        lines.append(_safe_code_block(cmd))
                    lines.append("```")
                    lines.append("")

                if path.references:
                    lines.append("**References:**")
                    for ref in path.references:
                        lines.append(f"- {ref}")
                    lines.append("")

                if path.notes:
                    lines.append(f"> {path.notes}")
                    lines.append("")

                lines.append("---")
                lines.append("")

        return "\n".join(lines)

    def _generate_appendix(self, target_info: dict | None) -> str:
        """Generate appendix."""
        lines = [
            "## Appendix",
            "",
            "### Scoring Methodology",
            "",
            "Each technique is scored using a weighted composite system:",
            "",
            "| Component | Weight | Description |",
            "|-----------|--------|-------------|",
            "| Reliability | 40% | Likelihood of successful exploitation |",
            "| Safety | 30% | System stability and detection risk |",
            "| Simplicity | 20% | Ease of execution |",
            "| Stealth | 10% | Detection avoidance capability |",
            "",
            "### Risk Levels",
            "",
            "- **Low:** Safe to attempt, unlikely to cause issues",
            "- **Medium:** May leave traces or require cleanup",
            "- **High:** Could cause instability or trigger alerts",
            "",
            "### Confidence Levels",
            "",
            "- **High:** Well-documented technique, high success rate",
            "- **Medium:** Known technique, may require adjustment",
            "- **Low:** Theoretical or situational technique",
            "",
        ]

        return "\n".join(lines)
