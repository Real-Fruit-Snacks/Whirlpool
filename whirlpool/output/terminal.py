"""Rich terminal output for analysis results.

Provides formatted, color-coded terminal output using the Rich library.
Theme: Catppuccin Mocha (https://catppuccin.com/palette/)
"""

from __future__ import annotations

from typing import Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.box import ROUNDED, HEAVY, DOUBLE
    from rich.style import Style
    from rich.padding import Padding
    from rich.theme import Theme
    from rich.rule import Rule
    from rich.tree import Tree
    from rich.columns import Columns
    from rich.align import Align
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from .. import __version__
from ..engine.analyzer import ExploitationPath, Category, Confidence, Risk
from ..engine.ranker import Ranker, RankingProfile


# Catppuccin Mocha palette
MOCHA = {
    "rosewater": "#f5e0dc",
    "flamingo": "#f2cdcd",
    "pink": "#f5c2e7",
    "mauve": "#cba6f7",
    "red": "#f38ba8",
    "maroon": "#eba0ac",
    "peach": "#fab387",
    "yellow": "#f9e2af",
    "green": "#a6e3a1",
    "teal": "#94e2d5",
    "sky": "#89dceb",
    "sapphire": "#74c7ec",
    "blue": "#89b4fa",
    "lavender": "#b4befe",
    "text": "#cdd6f4",
    "subtext1": "#bac2de",
    "subtext0": "#a6adc8",
    "overlay2": "#9399b2",
    "overlay1": "#7f849c",
    "overlay0": "#6c7086",
    "surface2": "#585b70",
    "surface1": "#45475a",
    "surface0": "#313244",
    "base": "#1e1e2e",
    "mantle": "#181825",
    "crust": "#11111b",
}

# Semantic color scheme mapped to Catppuccin Mocha
COLORS = {
    "critical": f"bold {MOCHA['red']}",
    "high": MOCHA["maroon"],
    "medium": MOCHA["yellow"],
    "low": MOCHA["green"],
    "info": MOCHA["sapphire"],
    "success": f"bold {MOCHA['green']}",
    "warning": f"bold {MOCHA['peach']}",
    "muted": MOCHA["overlay1"],
    "command": f"{MOCHA['text']} on {MOCHA['surface0']}",
    "header": f"bold {MOCHA['blue']}",
    "category": MOCHA["mauve"],
}

# Rich theme for markup tags
MOCHA_THEME = Theme({
    "info": MOCHA["sapphire"],
    "warning": MOCHA["peach"],
    "danger": MOCHA["red"],
    "success": MOCHA["green"],
})

# Category icons (text symbols for terminal)
CATEGORY_ICONS = {
    Category.SUID: ">>",
    Category.SUDO: "##",
    Category.CAPABILITIES: "<>",
    Category.CRON: "@@",
    Category.KERNEL: "!!",
    Category.DOCKER: "[]",
    Category.LXC_LXD: "[]",
    Category.NFS: "//",
    Category.PATH_HIJACK: "->",
    Category.SERVICE: "::",
    Category.PERMISSIONS: "**",
    Category.CREDENTIALS: "~~",
    Category.POTATO: "%%",
    Category.REGISTRY: "{}",
    Category.TOKEN: "&&",
    Category.SCHEDULED_TASK: "@@",
    Category.WILDCARD: "**",
    Category.OTHER: "--",
}

# Color for each category
CATEGORY_COLORS = {
    Category.SUID: MOCHA["red"],
    Category.SUDO: MOCHA["yellow"],
    Category.CAPABILITIES: MOCHA["teal"],
    Category.CRON: MOCHA["blue"],
    Category.KERNEL: MOCHA["red"],
    Category.DOCKER: MOCHA["sky"],
    Category.LXC_LXD: MOCHA["sky"],
    Category.NFS: MOCHA["sapphire"],
    Category.PATH_HIJACK: MOCHA["peach"],
    Category.SERVICE: MOCHA["mauve"],
    Category.PERMISSIONS: MOCHA["yellow"],
    Category.CREDENTIALS: MOCHA["green"],
    Category.POTATO: MOCHA["peach"],
    Category.REGISTRY: MOCHA["mauve"],
    Category.TOKEN: MOCHA["flamingo"],
    Category.SCHEDULED_TASK: MOCHA["blue"],
    Category.WILDCARD: MOCHA["peach"],
    Category.OTHER: MOCHA["subtext1"],
}


def _score_bar(score: float, width: int = 20) -> Text:
    """Build a colored progress bar for a score value (0-100).

    Returns a Rich Text object like: ████████████████░░░░ 85
    """
    filled = int(round(score / 100 * width))
    empty = width - filled

    # Color gradient based on score
    if score >= 80:
        bar_color = MOCHA["green"]
    elif score >= 60:
        bar_color = MOCHA["yellow"]
    elif score >= 40:
        bar_color = MOCHA["peach"]
    else:
        bar_color = MOCHA["red"]

    bar = Text()
    bar.append("\u2588" * filled, style=bar_color)
    bar.append("\u2591" * empty, style=MOCHA["surface2"])
    bar.append(f" {score:.0f}", style=f"bold {bar_color}")
    return bar


def _confidence_badge(confidence: Confidence) -> Text:
    """Render a confidence level as an inline badge."""
    colors = {
        Confidence.HIGH: MOCHA["green"],
        Confidence.MEDIUM: MOCHA["yellow"],
        Confidence.LOW: MOCHA["red"],
        Confidence.THEORETICAL: MOCHA["overlay1"],
    }
    color = colors.get(confidence, MOCHA["subtext1"])
    badge = Text()
    badge.append(f" {confidence.value.upper()} ", style=f"bold {color}")
    return badge


def _risk_badge(risk: Risk) -> Text:
    """Render a risk level as an inline badge."""
    colors = {
        Risk.LOW: MOCHA["green"],
        Risk.MEDIUM: MOCHA["yellow"],
        Risk.HIGH: MOCHA["red"],
    }
    color = colors.get(risk, MOCHA["subtext1"])
    badge = Text()
    badge.append(f" {risk.value.upper()} RISK ", style=f"bold {color}")
    return badge


def _category_badge(category: Category) -> Text:
    """Render a category as an inline badge."""
    color = CATEGORY_COLORS.get(category, MOCHA["subtext1"])
    badge = Text()
    badge.append(f" {category.value.upper().replace('_', ' ')} ", style=f"bold {color}")
    return badge


def _commands_panel(commands: list[str]) -> Panel:
    """Render all commands inside a single unified panel."""
    cmd_text = Text()
    for i, cmd in enumerate(commands):
        if cmd.startswith("#"):
            cmd_text.append(cmd, style=MOCHA["overlay1"])
        else:
            cmd_text.append("$ ", style=MOCHA["overlay2"])
            cmd_text.append(cmd, style=MOCHA["text"])
        if i < len(commands) - 1:
            cmd_text.append("\n")

    return Panel(
        cmd_text,
        title=f"[{MOCHA['overlay1']}]Commands[/{MOCHA['overlay1']}]",
        title_align="left",
        box=ROUNDED,
        border_style=MOCHA["surface2"],
        padding=(0, 1),
    )


class TerminalOutput:
    """Rich terminal output formatter."""

    def __init__(
        self,
        console: Optional[Console] = None,
        no_color: bool = False,
        profile: str = "default",
    ):
        """Initialize terminal output.

        Args:
            console: Optional Rich console instance
            no_color: If True, disable colored output
            profile: Active ranking profile name
        """
        if not RICH_AVAILABLE:
            raise ImportError(
                "Rich library is required for terminal output. "
                "Install it with: pip install rich"
            )

        if console:
            self.console = console
        elif no_color:
            self.console = Console(no_color=True, highlight=False)
        else:
            self.console = Console(theme=MOCHA_THEME)

        self.profile = profile
        self.ranker = Ranker()
        self._path_count = 0
        self._chain_count = 0

    def print_header(
        self,
        target_info: Optional[dict] = None,
        paths: Optional[list[ExploitationPath]] = None,
    ) -> None:
        """Print analysis header with branded banner and target information.

        Args:
            target_info: Optional dictionary with target details
            paths: Optional list of paths for the findings summary bar
        """
        self.console.print()
        self.console.print(
            Rule(
                title=f"[bold {MOCHA['mauve']}]WHIRLPOOL[/bold {MOCHA['mauve']}]",
                style=MOCHA["mauve"],
            )
        )
        self.console.print(
            Align.center(
                Text("Privilege Escalation Reasoning Engine", style=MOCHA["overlay1"])
            )
        )
        self.console.print()

        # Target info as a clean borderless table
        if target_info:
            info_table = Table(
                show_header=False,
                box=None,
                padding=(0, 2),
                show_edge=False,
            )
            info_table.add_column("Key", style=MOCHA["subtext0"], min_width=10)
            info_table.add_column("Value", style=f"bold {MOCHA['text']}")

            field_order = ["hostname", "os", "kernel", "user", "groups"]
            labels = {
                "hostname": "Hostname",
                "os": "OS",
                "kernel": "Kernel",
                "user": "User",
                "groups": "Groups",
            }
            for key in field_order:
                if key in target_info:
                    val = target_info[key]
                    if isinstance(val, (list, tuple)):
                        val = ", ".join(str(v) for v in val)
                    info_table.add_row(labels.get(key, key), str(val))

            self.console.print(info_table)
            self.console.print()

        # Profile badge
        profile_text = Text()
        profile_text.append("Profile: ", style=MOCHA["subtext0"])
        profile_text.append(
            f" {self.profile.upper()} ",
            style=f"bold {MOCHA['lavender']}",
        )

        # Findings summary bar
        if paths:
            high_conf = sum(
                1 for p in paths if p.confidence == Confidence.HIGH
            )
            low_risk = sum(1 for p in paths if p.risk == Risk.LOW)

            profile_text.append("  ")
            profile_text.append(f"{len(paths)} paths found", style=MOCHA["text"])
            profile_text.append(f" | ", style=MOCHA["surface2"])
            profile_text.append(f"{high_conf} high confidence", style=MOCHA["green"])
            profile_text.append(f" | ", style=MOCHA["surface2"])
            profile_text.append(f"{low_risk} low risk", style=MOCHA["green"])

        self.console.print(profile_text)
        self.console.print()

    def print_quick_wins(
        self,
        paths: list[ExploitationPath],
        top_n: int = 5,
    ) -> None:
        """Print quick wins section with high-impact cards.

        Args:
            paths: List of exploitation paths
            top_n: Number of quick wins to show
        """
        quick_wins = self.ranker.get_quick_wins(paths, top_n=top_n)

        if not quick_wins:
            self.console.print(
                f"[{MOCHA['yellow']}]No quick wins identified[/{MOCHA['yellow']}]"
            )
            return

        self.console.print(
            Rule(
                title=f"[bold {MOCHA['green']}]QUICK WINS[/bold {MOCHA['green']}]",
                style=MOCHA["green"],
            )
        )
        self.console.print()

        for i, path in enumerate(quick_wins, 1):
            score = self.ranker.get_score(path)
            self._print_path_card(path, rank=i, score=score)

            if i < len(quick_wins):
                self.console.print(
                    Rule(style=MOCHA["surface1"])
                )
                self.console.print()

        self.console.print()

    def print_all_paths(
        self,
        paths: list[ExploitationPath],
        group_by_category: bool = True,
        show_commands: bool = True,
    ) -> None:
        """Print all exploitation paths grouped by category.

        Args:
            paths: List of exploitation paths
            group_by_category: If True, group by category
            show_commands: If True, show exploitation commands
        """
        if not paths:
            self.console.print(
                f"[{MOCHA['yellow']}]No exploitation paths identified[/{MOCHA['yellow']}]"
            )
            return

        self._path_count = len(paths)

        # Rank paths
        ranked = self.ranker.rank(paths)

        if group_by_category:
            grouped = self.ranker.group_by_category(ranked)

            for category, cat_paths in grouped.items():
                self._print_category_section(category, cat_paths, show_commands)
        else:
            self.console.print(
                Rule(
                    title=f"[bold {MOCHA['blue']}]ALL PATHS ({len(ranked)})[/bold {MOCHA['blue']}]",
                    style=MOCHA["blue"],
                )
            )
            self.console.print()

            for i, path in enumerate(ranked, 1):
                score = self.ranker.get_score(path)
                self._print_path_entry(
                    path, rank=i, score=score, show_commands=show_commands
                )

    def print_path_detail(
        self,
        path: ExploitationPath,
        show_score_breakdown: bool = False,
    ) -> None:
        """Print detailed view of a single path.

        Args:
            path: Exploitation path to display
            show_score_breakdown: If True, show detailed score breakdown
        """
        score = self.ranker.get_score(path)
        self._print_path_card(path, score=score)

        if show_score_breakdown:
            breakdown = self.ranker.get_score_breakdown(path)
            self._print_score_breakdown(breakdown)

    def print_chains(self, chains: list) -> None:
        """Print attack chains section.

        Args:
            chains: List of AttackChain objects
        """
        if not chains:
            return

        self._chain_count = len(chains)

        self.console.print()
        self.console.print(
            Rule(
                title=f"[bold {MOCHA['red']}]ATTACK CHAINS[/bold {MOCHA['red']}]",
                style=MOCHA["red"],
            )
        )
        self.console.print()

        for i, chain in enumerate(chains, 1):
            self._print_chain(chain, number=i)

            if i < len(chains):
                self.console.print(
                    Rule(style=MOCHA["surface1"])
                )
                self.console.print()

    def print_summary(
        self,
        paths: list[ExploitationPath],
    ) -> None:
        """Print dashboard-style summary statistics.

        Args:
            paths: List of exploitation paths
        """
        if not paths:
            return

        self._path_count = len(paths)

        self.console.print()
        self.console.print(
            Rule(
                title=f"[bold {MOCHA['lavender']}]ANALYSIS SUMMARY[/bold {MOCHA['lavender']}]",
                style=MOCHA["lavender"],
            )
        )
        self.console.print()

        # Count breakdowns
        by_category: dict[Category, int] = {}
        by_confidence: dict[Confidence, int] = {}
        by_risk: dict[Risk, int] = {}
        scores: list[float] = []

        for path in paths:
            by_category[path.category] = by_category.get(path.category, 0) + 1
            by_confidence[path.confidence] = (
                by_confidence.get(path.confidence, 0) + 1
            )
            by_risk[path.risk] = by_risk.get(path.risk, 0) + 1
            scores.append(self.ranker.get_score(path))

        # Three-column layout
        # Left: Confidence breakdown
        conf_table = Table(
            title=f"[bold {MOCHA['sapphire']}]By Confidence[/bold {MOCHA['sapphire']}]",
            box=ROUNDED,
            show_header=False,
            border_style=MOCHA["surface2"],
            padding=(0, 1),
            min_width=22,
        )
        conf_table.add_column("Level", style=MOCHA["subtext0"])
        conf_table.add_column("Count", justify="right")

        conf_colors = {
            Confidence.HIGH: MOCHA["green"],
            Confidence.MEDIUM: MOCHA["yellow"],
            Confidence.LOW: MOCHA["red"],
            Confidence.THEORETICAL: MOCHA["overlay1"],
        }
        for level in [Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW, Confidence.THEORETICAL]:
            count = by_confidence.get(level, 0)
            if count > 0:
                color = conf_colors.get(level, MOCHA["text"])
                conf_table.add_row(
                    level.value.upper(),
                    f"[bold {color}]{count}[/bold {color}]",
                )

        # Center: Risk breakdown
        risk_table = Table(
            title=f"[bold {MOCHA['sapphire']}]By Risk[/bold {MOCHA['sapphire']}]",
            box=ROUNDED,
            show_header=False,
            border_style=MOCHA["surface2"],
            padding=(0, 1),
            min_width=22,
        )
        risk_table.add_column("Level", style=MOCHA["subtext0"])
        risk_table.add_column("Count", justify="right")

        risk_colors = {
            Risk.LOW: MOCHA["green"],
            Risk.MEDIUM: MOCHA["yellow"],
            Risk.HIGH: MOCHA["red"],
        }
        for level in [Risk.LOW, Risk.MEDIUM, Risk.HIGH]:
            count = by_risk.get(level, 0)
            if count > 0:
                color = risk_colors.get(level, MOCHA["text"])
                risk_table.add_row(
                    level.value.upper(),
                    f"[bold {color}]{count}[/bold {color}]",
                )

        # Right: Category breakdown (top categories)
        cat_table = Table(
            title=f"[bold {MOCHA['sapphire']}]By Category[/bold {MOCHA['sapphire']}]",
            box=ROUNDED,
            show_header=False,
            border_style=MOCHA["surface2"],
            padding=(0, 1),
            min_width=22,
        )
        cat_table.add_column("Category", style=MOCHA["mauve"])
        cat_table.add_column("Count", justify="right", style=f"bold {MOCHA['text']}")

        sorted_cats = sorted(by_category.items(), key=lambda x: x[1], reverse=True)
        for cat, count in sorted_cats[:8]:
            cat_table.add_row(cat.value.upper().replace("_", " "), str(count))

        self.console.print(
            Columns(
                [conf_table, risk_table, cat_table],
                padding=(0, 2),
                expand=True,
            )
        )
        self.console.print()

        # Score distribution histogram
        if scores:
            self._print_score_distribution(scores)
            self.console.print()

        # Top recommendation callout
        ranked = self.ranker.rank(paths)
        if ranked:
            top = ranked[0]
            top_score = self.ranker.get_score(top)
            rec_text = Text()
            rec_text.append("Top Recommendation: ", style=f"bold {MOCHA['green']}")
            rec_text.append(top.technique_name, style=f"bold {MOCHA['text']}")
            rec_text.append("  ")
            rec_text.append_text(_score_bar(top_score, width=15))
            rec_text.append("\n")
            rec_text.append(top.description, style=MOCHA["subtext0"])
            if top.commands:
                rec_text.append("\n")
                rec_text.append("$ ", style=MOCHA["overlay2"])
                rec_text.append(top.commands[0], style=MOCHA["text"])

            self.console.print(
                Panel(
                    rec_text,
                    border_style=MOCHA["green"],
                    box=ROUNDED,
                    padding=(0, 1),
                )
            )

        # Footer
        self.console.print()
        footer_parts = [f"whirlpool v{__version__}"]
        footer_parts.append(f"Profile: {self.profile}")
        footer_parts.append(f"{self._path_count} paths")
        if self._chain_count:
            footer_parts.append(f"{self._chain_count} chains")
        footer_text = f"[{MOCHA['overlay1']}]{' | '.join(footer_parts)}[/{MOCHA['overlay1']}]"

        self.console.print(Rule(style=MOCHA["surface2"]))
        self.console.print(Align.center(Text.from_markup(footer_text)))
        self.console.print()

    # ── Internal rendering methods ──────────────────────────────────────

    def _print_path_card(
        self,
        path: ExploitationPath,
        rank: int = 0,
        score: float = 0,
    ) -> None:
        """Print a path as a rich card (used for quick wins and detail views)."""
        # Title line: rank + name + score bar
        title_line = Text()
        if rank:
            title_line.append(f"[{rank}] ", style=f"bold {MOCHA['overlay2']}")
        title_line.append(path.technique_name, style=f"bold {MOCHA['text']}")
        title_line.append("  ")
        title_line.append_text(_score_bar(score))

        # Badges row
        badges = Text()
        badges.append_text(_confidence_badge(path.confidence))
        badges.append("  ")
        badges.append_text(_risk_badge(path.risk))
        badges.append("  ")
        badges.append_text(_category_badge(path.category))

        # Description
        desc = Text(path.description, style=MOCHA["subtext0"])

        # Finding
        finding = Text()
        finding.append("Finding: ", style=MOCHA["overlay1"])
        finding.append(path.finding, style=MOCHA["sapphire"])

        # Build card content
        card_content = Text()
        card_content.append_text(title_line)
        card_content.append("\n")
        card_content.append_text(badges)
        card_content.append("\n")
        card_content.append_text(desc)
        card_content.append("\n")
        card_content.append_text(finding)

        # Notes (highlighted)
        if path.notes:
            card_content.append("\n")
            card_content.append("Note: ", style=f"bold {MOCHA['peach']}")
            card_content.append(path.notes, style=MOCHA["peach"])

        self.console.print(
            Panel(
                card_content,
                box=ROUNDED,
                border_style=MOCHA["surface2"],
                padding=(0, 1),
            )
        )

        # Commands in unified block
        if path.commands:
            self.console.print(_commands_panel(path.commands))

        # Prerequisites
        if path.prerequisites:
            prereq_text = Text()
            prereq_text.append("Prerequisites: ", style=f"bold {MOCHA['yellow']}")
            prereq_text.append(
                ", ".join(path.prerequisites), style=MOCHA["subtext0"]
            )
            self.console.print(prereq_text)

        # References
        if path.references:
            for ref in path.references:
                self.console.print(
                    Text(f"  {ref}", style=f"{MOCHA['overlay1']} underline")
                )

        self.console.print()

    def _print_path_entry(
        self,
        path: ExploitationPath,
        rank: int = 0,
        score: float = 0,
        show_commands: bool = True,
    ) -> None:
        """Print a compact path entry (used in category listings)."""
        # Title: [rank] Name  ████░░ score  CONF  RISK
        title = Text()
        if rank:
            title.append(f"[{rank}] ", style=f"bold {MOCHA['overlay2']}")
        title.append(path.technique_name, style=f"bold {MOCHA['text']}")
        title.append("  ")
        title.append_text(_score_bar(score, width=15))
        title.append("  ")
        title.append_text(_confidence_badge(path.confidence))
        title.append(" ")
        title.append_text(_risk_badge(path.risk))

        self.console.print(title)

        # Description
        self.console.print(
            Text(f"  {path.description}", style=MOCHA["subtext0"])
        )

        # Finding
        finding = Text()
        finding.append("  Finding: ", style=MOCHA["overlay1"])
        finding.append(path.finding, style=MOCHA["sapphire"])
        self.console.print(finding)

        # Commands in one panel
        if show_commands and path.commands:
            self.console.print(
                Padding(_commands_panel(path.commands), (0, 0, 0, 2))
            )

        # Prerequisites inline
        if path.prerequisites:
            prereq = Text()
            prereq.append("  Prerequisites: ", style=MOCHA["yellow"])
            prereq.append(", ".join(path.prerequisites), style=MOCHA["subtext0"])
            self.console.print(prereq)

        # References
        if path.references:
            for ref in path.references:
                self.console.print(
                    Text(f"    {ref}", style=f"{MOCHA['overlay1']} underline")
                )

        # Notes
        if path.notes:
            note = Text()
            note.append("  Note: ", style=f"bold {MOCHA['peach']}")
            note.append(path.notes, style=MOCHA["peach"])
            self.console.print(note)

        self.console.print()

    def _print_category_section(
        self,
        category: Category,
        paths: list[ExploitationPath],
        show_commands: bool,
    ) -> None:
        """Print a category section with count badge."""
        icon = CATEGORY_ICONS.get(category, "--")
        color = CATEGORY_COLORS.get(category, MOCHA["subtext1"])
        cat_name = category.value.upper().replace("_", " ")
        title = f"[bold {color}]{icon} {cat_name} ({len(paths)})[/bold {color}]"

        self.console.print()
        self.console.print(Rule(title=title, style=color))
        self.console.print()

        for i, path in enumerate(paths, 1):
            score = self.ranker.get_score(path)
            self._print_path_entry(
                path, rank=i, score=score, show_commands=show_commands
            )

    def _print_chain(self, chain, number: int = 0) -> None:
        """Print a single attack chain as a tree."""
        # Root label with badges
        root_label = Text()
        if number:
            root_label.append(f"[{number}] ", style=f"bold {MOCHA['overlay2']}")
        root_label.append(chain.name, style=f"bold {MOCHA['text']}")
        root_label.append("  ")
        root_label.append_text(_confidence_badge(chain.confidence))
        root_label.append(" ")
        root_label.append_text(_risk_badge(chain.risk))

        tree = Tree(root_label)

        # Description branch
        tree.add(Text(chain.description, style=MOCHA["subtext0"]))

        # Prerequisites at chain level
        if chain.prerequisites:
            prereq_branch = tree.add(
                Text("Prerequisites", style=f"bold {MOCHA['yellow']}")
            )
            for prereq in chain.prerequisites:
                prereq_branch.add(Text(prereq, style=MOCHA["subtext0"]))

        # Steps as branches
        for step in chain.steps:
            step_label = Text()
            step_label.append(f"Step {step.order}: ", style=f"bold {MOCHA['sapphire']}")
            step_label.append(step.description, style=MOCHA["text"])

            step_branch = tree.add(step_label)

            # Commands under each step
            if step.commands:
                for cmd in step.commands:
                    if cmd.startswith("#"):
                        step_branch.add(Text(cmd, style=MOCHA["overlay1"]))
                    elif cmd == "":
                        continue
                    else:
                        cmd_text = Text()
                        cmd_text.append("$ ", style=MOCHA["overlay2"])
                        cmd_text.append(cmd, style=MOCHA["text"])
                        step_branch.add(cmd_text)

            # Step output
            if step.output:
                out_text = Text()
                out_text.append("-> ", style=MOCHA["green"])
                out_text.append(step.output, style=MOCHA["green"])
                step_branch.add(out_text)

        # Notes
        if chain.notes:
            note = Text()
            note.append("Note: ", style=f"bold {MOCHA['peach']}")
            note.append(chain.notes, style=MOCHA["peach"])
            tree.add(note)

        # References
        if chain.references:
            for ref in chain.references:
                tree.add(Text(ref, style=f"{MOCHA['overlay1']} underline"))

        self.console.print(tree)
        self.console.print()

    def _print_score_distribution(self, scores: list[float]) -> None:
        """Print a text histogram of score distribution."""
        buckets = {"90-100": 0, "70-89": 0, "50-69": 0, "30-49": 0, "0-29": 0}
        bucket_colors = {
            "90-100": MOCHA["green"],
            "70-89": MOCHA["green"],
            "50-69": MOCHA["yellow"],
            "30-49": MOCHA["peach"],
            "0-29": MOCHA["red"],
        }

        for s in scores:
            if s >= 90:
                buckets["90-100"] += 1
            elif s >= 70:
                buckets["70-89"] += 1
            elif s >= 50:
                buckets["50-69"] += 1
            elif s >= 30:
                buckets["30-49"] += 1
            else:
                buckets["0-29"] += 1

        max_count = max(buckets.values()) if buckets.values() else 1
        bar_max = 30

        dist_text = Text()
        dist_text.append("Score Distribution\n", style=f"bold {MOCHA['subtext1']}")

        for label, count in buckets.items():
            if count == 0:
                continue
            bar_len = max(1, int(count / max_count * bar_max)) if max_count else 0
            color = bucket_colors[label]

            dist_text.append(f"  {label:>6}  ", style=MOCHA["subtext0"])
            dist_text.append("\u2588" * bar_len, style=color)
            dist_text.append(f" {count}\n", style=f"bold {color}")

        self.console.print(dist_text)

    def _print_score_breakdown(self, breakdown: dict) -> None:
        """Print detailed score breakdown."""
        table = Table(
            title=f"[bold {MOCHA['lavender']}]Score Breakdown[/bold {MOCHA['lavender']}]",
            box=ROUNDED,
            border_style=MOCHA["surface2"],
        )
        table.add_column("Component", style=MOCHA["sapphire"])
        table.add_column("Raw", justify="right", style=MOCHA["text"])
        table.add_column("Weight", justify="right", style=MOCHA["subtext0"])
        table.add_column("Weighted", justify="right", style=MOCHA["text"])

        weights = breakdown.get("weights", {})

        table.add_row(
            "Reliability",
            f"{breakdown['reliability']:.0f}",
            f"{weights.get('reliability', 0):.0%}",
            f"{breakdown['reliability_weighted']:.1f}",
        )
        table.add_row(
            "Safety",
            f"{breakdown['safety']:.0f}",
            f"{weights.get('safety', 0):.0%}",
            f"{breakdown['safety_weighted']:.1f}",
        )
        table.add_row(
            "Simplicity",
            f"{breakdown['simplicity']:.0f}",
            f"{weights.get('simplicity', 0):.0%}",
            f"{breakdown['simplicity_weighted']:.1f}",
        )
        table.add_row(
            "Stealth",
            f"{breakdown['stealth']:.0f}",
            f"{weights.get('stealth', 0):.0%}",
            f"{breakdown['stealth_weighted']:.1f}",
        )

        table.add_section()
        table.add_row(
            f"[bold {MOCHA['text']}]Final Score[/bold {MOCHA['text']}]",
            "",
            "",
            f"[bold {MOCHA['green']}]{breakdown['final_score']:.1f}[/bold {MOCHA['green']}]",
        )

        self.console.print(table)


def print_results(
    paths: list[ExploitationPath],
    target_info: Optional[dict] = None,
    show_quick_wins: bool = True,
    show_all: bool = True,
    show_summary: bool = True,
    group_by_category: bool = True,
    chains: Optional[list] = None,
    profile: str = "default",
) -> None:
    """Convenience function to print analysis results.

    Args:
        paths: List of exploitation paths
        target_info: Optional target information
        show_quick_wins: Show quick wins section
        show_all: Show all paths
        show_summary: Show summary statistics
        group_by_category: Group paths by category
        chains: Optional attack chains
        profile: Active ranking profile name
    """
    output = TerminalOutput(profile=profile)

    output.print_header(target_info, paths=paths)

    if show_quick_wins:
        output.print_quick_wins(paths)

    if show_all:
        output.print_all_paths(paths, group_by_category=group_by_category)

    if chains:
        output.print_chains(chains)

    if show_summary:
        output.print_summary(paths)
