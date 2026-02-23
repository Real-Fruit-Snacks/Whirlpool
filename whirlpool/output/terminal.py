"""Rich terminal output for analysis results.

Provides formatted, color-coded terminal output using the Rich library.
Theme: Catppuccin Mocha (https://catppuccin.com/palette/)

Design matches the landing page mockup (docs/index.html) — bordered section
panels, compact score badges, outlined confidence/risk pills, and unified
dark command blocks.
"""

from __future__ import annotations

try:
    from rich.align import Align
    from rich.box import ROUNDED
    from rich.columns import Columns
    from rich.console import Console, Group, RenderableType
    from rich.padding import Padding
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
    from rich.theme import Theme
    from rich.tree import Tree
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from .. import __version__
from ..engine.analyzer import Category, Confidence, ExploitationPath, Risk
from ..engine.ranker import Ranker

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
    Category.LOLBAS: "LB",
    Category.OTHER: "--",
    Category.NETWORK: "NT",
    Category.WRITABLE_FILE: "WF",
    Category.GROUP: "GR",
    Category.UAC: "UA",
    Category.DLL: "DL",
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
    Category.LOLBAS: MOCHA["pink"],
    Category.OTHER: MOCHA["subtext1"],
    Category.NETWORK: MOCHA["blue"],
    Category.WRITABLE_FILE: MOCHA["red"],
    Category.GROUP: MOCHA["yellow"],
    Category.UAC: MOCHA["peach"],
    Category.DLL: MOCHA["maroon"],
}


# ── Badge / display helpers ──────────────────────────────────────────────


def _score_badge(score: float) -> Text:
    """Render a score as a compact colored pill: e.g. ``[95]``."""
    if score >= 80:
        color = MOCHA["green"]
    elif score >= 60:
        color = MOCHA["yellow"]
    elif score >= 40:
        color = MOCHA["peach"]
    else:
        color = MOCHA["red"]

    badge = Text()
    badge.append(f" {score:.0f} ", style=f"bold {MOCHA['crust']} on {color}")
    return badge


def _score_bar(score: float, width: int = 20) -> Text:
    """Build a colored progress bar for a score value (0-100).

    Returns a Rich Text object like: ████████████████░░░░ 85
    """
    filled = int(round(score / 100 * width))
    empty = width - filled

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
    """Render a confidence level as an outlined badge: ``[high]``."""
    colors = {
        Confidence.HIGH: MOCHA["green"],
        Confidence.MEDIUM: MOCHA["yellow"],
        Confidence.LOW: MOCHA["red"],
        Confidence.THEORETICAL: MOCHA["overlay1"],
    }
    color = colors.get(confidence, MOCHA["subtext1"])
    badge = Text()
    badge.append(f" {confidence.value} ", style=f"bold {color}")
    return badge


def _risk_badge(risk: Risk) -> Text:
    """Render a risk level as an outlined badge: ``[low risk]``."""
    colors = {
        Risk.LOW: MOCHA["green"],
        Risk.MEDIUM: MOCHA["yellow"],
        Risk.HIGH: MOCHA["red"],
    }
    color = colors.get(risk, MOCHA["subtext1"])
    badge = Text()
    badge.append(f" {risk.value} risk ", style=f"bold {color}")
    return badge


def _category_badge(category: Category) -> Text:
    """Render a category as an inline badge."""
    color = CATEGORY_COLORS.get(category, MOCHA["subtext1"])
    badge = Text()
    badge.append(f" {category.value.upper().replace('_', ' ')} ", style=f"bold {color}")
    return badge


def _commands_block(commands: list[str]) -> Panel:
    """Render all commands in a single dark code block.

    Matches the screenshot: dark background, green text, no ``$`` prefix,
    no title.  Comment lines (starting with ``#``) are rendered dimmer.
    """
    cmd_text = Text()
    for i, cmd in enumerate(commands):
        if cmd.startswith("#"):
            cmd_text.append(cmd, style=MOCHA["overlay1"])
        else:
            cmd_text.append(cmd, style=MOCHA["green"])
        if i < len(commands) - 1:
            cmd_text.append("\n")

    return Panel(
        cmd_text,
        box=ROUNDED,
        border_style=MOCHA["surface0"],
        padding=(0, 1),
    )


# ── Main output class ────────────────────────────────────────────────────


class TerminalOutput:
    """Rich terminal output formatter.

    Produces output matching the Whirlpool landing-page mockup:
    bordered panels for each section, compact score badges,
    outlined confidence/risk pills, and unified dark command blocks.
    """

    def __init__(
        self,
        console: Console | None = None,
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

    # ── Public API ────────────────────────────────────────────────────

    def print_header(
        self,
        target_info: dict | None = None,
        paths: list[ExploitationPath] | None = None,
    ) -> None:
        """Print the branded banner and target information panels.

        Args:
            target_info: Optional dictionary with target details
            paths: Optional list of paths for the findings summary bar
        """
        self.console.print()

        # ── Banner panel (mauve border, centered title) ──
        self.console.print(
            Panel(
                Align.center(
                    Text(
                        "WHIRLPOOL - Privilege Escalation Analysis",
                        style=f"bold {MOCHA['mauve']}",
                    )
                ),
                box=ROUNDED,
                border_style=MOCHA["mauve"],
                padding=(0, 1),
            )
        )
        self.console.print()

        # ── Target information panel ──
        if target_info:
            info_table = Table(
                show_header=False,
                box=None,
                padding=(0, 2),
                show_edge=False,
            )
            info_table.add_column("Key", style=MOCHA["subtext0"], min_width=12)
            info_table.add_column("Value", style=f"bold {MOCHA['text']}")

            field_order = ["hostname", "os", "kernel", "user", "groups"]
            labels = {
                "hostname": "Hostname:",
                "os": "OS:",
                "kernel": "Kernel:",
                "user": "User:",
                "groups": "Groups:",
            }
            for key in field_order:
                if key in target_info:
                    val = target_info[key]
                    if isinstance(val, (list, tuple)):
                        val = ", ".join(str(v) for v in val)
                    info_table.add_row(labels.get(key, key), str(val))

            self.console.print(
                Panel(
                    info_table,
                    title=f"[{MOCHA['overlay0']}]TARGET INFORMATION[/{MOCHA['overlay0']}]",
                    title_align="left",
                    box=ROUNDED,
                    border_style=MOCHA["surface1"],
                    padding=(0, 1),
                )
            )
            self.console.print()

        # ── Profile + findings summary ──
        profile_text = Text()
        profile_text.append("Profile: ", style=MOCHA["subtext0"])
        profile_text.append(
            f" {self.profile.upper()} ",
            style=f"bold {MOCHA['lavender']}",
        )

        if paths:
            high_conf = sum(
                1 for p in paths if p.confidence == Confidence.HIGH
            )
            low_risk = sum(1 for p in paths if p.risk == Risk.LOW)

            profile_text.append("  ")
            profile_text.append(f"{len(paths)} paths found", style=MOCHA["text"])
            profile_text.append(" | ", style=MOCHA["surface2"])
            profile_text.append(f"{high_conf} high confidence", style=MOCHA["green"])
            profile_text.append(" | ", style=MOCHA["surface2"])
            profile_text.append(f"{low_risk} low risk", style=MOCHA["green"])

        self.console.print(profile_text)
        self.console.print()

    def print_quick_wins(
        self,
        paths: list[ExploitationPath],
        top_n: int = 5,
    ) -> None:
        """Print quick wins inside a bordered panel with yellow header.

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

        # Build all quick-win entries as a group
        renderables: list[RenderableType] = []
        for i, path in enumerate(quick_wins, 1):
            score = self.ranker.get_score(path)
            renderables.append(self._build_quick_win(path, rank=i, score=score))

            # Separator between wins (not after last)
            if i < len(quick_wins):
                renderables.append(
                    Rule(style=MOCHA["surface0"])
                )

        self.console.print(
            Panel(
                Group(*renderables),
                title=(
                    f"[bold {MOCHA['yellow']}]"
                    "QUICK WINS - HIGHEST PROBABILITY TECHNIQUES"
                    f"[/bold {MOCHA['yellow']}]"
                ),
                title_align="left",
                box=ROUNDED,
                border_style=MOCHA["yellow"],
                padding=(1, 2),
            )
        )
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
        ranked = self.ranker.rank(paths)

        if group_by_category:
            grouped = self.ranker.group_by_category(ranked)

            for category, cat_paths in grouped.items():
                self._print_category_section(category, cat_paths, show_commands)
        else:
            renderables: list[RenderableType] = []
            for i, path in enumerate(ranked, 1):
                score = self.ranker.get_score(path)
                renderables.append(
                    self._build_path_entry(
                        path, rank=i, score=score, show_commands=show_commands
                    )
                )
                if i < len(ranked):
                    renderables.append(Rule(style=MOCHA["surface0"]))

            self.console.print()
            self.console.print(
                Panel(
                    Group(*renderables),
                    title=(
                        f"[bold {MOCHA['blue']}]"
                        f"ALL PATHS ({len(ranked)})"
                        f"[/bold {MOCHA['blue']}]"
                    ),
                    title_align="left",
                    box=ROUNDED,
                    border_style=MOCHA["blue"],
                    padding=(0, 1),
                )
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

        renderables: list[RenderableType] = []
        for i, chain in enumerate(chains, 1):
            renderables.append(self._build_chain(chain, number=i))
            if i < len(chains):
                renderables.append(Rule(style=MOCHA["surface0"]))

        self.console.print()
        self.console.print(
            Panel(
                Group(*renderables),
                title=(
                    f"[bold {MOCHA['red']}]"
                    "ATTACK CHAINS"
                    f"[/bold {MOCHA['red']}]"
                ),
                title_align="left",
                box=ROUNDED,
                border_style=MOCHA["red"],
                padding=(0, 1),
            )
        )

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
        for conf_level in [Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW, Confidence.THEORETICAL]:
            count = by_confidence.get(conf_level, 0)
            if count > 0:
                color = conf_colors.get(conf_level, MOCHA["text"])
                conf_table.add_row(
                    conf_level.value.upper(),
                    f"[bold {color}]{count}[/bold {color}]",
                )

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
        for risk_level in [Risk.LOW, Risk.MEDIUM, Risk.HIGH]:
            count = by_risk.get(risk_level, 0)
            if count > 0:
                color = risk_colors.get(risk_level, MOCHA["text"])
                risk_table.add_row(
                    risk_level.value.upper(),
                    f"[bold {color}]{count}[/bold {color}]",
                )

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

        summary_parts: list[RenderableType] = []
        summary_parts.append(
            Columns(
                [conf_table, risk_table, cat_table],
                padding=(0, 2),
                expand=True,
            )
        )
        summary_parts.append(Text(""))

        # Score distribution histogram
        if scores:
            summary_parts.append(self._build_score_distribution(scores))
            summary_parts.append(Text(""))

        # Top recommendation callout
        ranked = self.ranker.rank(paths)
        if ranked:
            top = ranked[0]
            top_score = self.ranker.get_score(top)
            rec_text = Text()
            rec_text.append("Top Recommendation: ", style=f"bold {MOCHA['green']}")
            rec_text.append(top.technique_name, style=f"bold {MOCHA['text']}")
            rec_text.append("  ")
            rec_text.append_text(_score_badge(top_score))
            rec_text.append("\n")
            rec_text.append(top.description, style=MOCHA["subtext0"])
            if top.commands:
                rec_text.append("\n")
                rec_text.append(top.commands[0], style=MOCHA["green"])

            summary_parts.append(
                Panel(
                    rec_text,
                    border_style=MOCHA["green"],
                    box=ROUNDED,
                    padding=(0, 1),
                )
            )

        self.console.print()
        self.console.print(
            Panel(
                Group(*summary_parts),
                title=(
                    f"[bold {MOCHA['lavender']}]"
                    "ANALYSIS SUMMARY"
                    f"[/bold {MOCHA['lavender']}]"
                ),
                title_align="left",
                box=ROUNDED,
                border_style=MOCHA["lavender"],
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

    def _build_quick_win(
        self,
        path: ExploitationPath,
        rank: int = 0,
        score: float = 0,
    ) -> Group:
        """Build a quick-win entry as a Rich Group (for embedding in panel)."""
        # Title line: [1]  [95]  Sudo systemctl  [high]  [low risk]
        title_line = Text()
        if rank:
            title_line.append(f"[{rank}]", style=f"bold {MOCHA['text']}")
            title_line.append("  ")
        title_line.append_text(_score_badge(score))
        title_line.append("  ")
        title_line.append(path.technique_name, style=f"bold {MOCHA['text']}")
        title_line.append("   ")
        title_line.append_text(_confidence_badge(path.confidence))
        title_line.append("  ")
        title_line.append_text(_risk_badge(path.risk))

        # Description
        desc = Text(path.description, style=MOCHA["subtext0"])

        # Finding
        finding = Text()
        finding.append("Finding: ", style=MOCHA["overlay1"])
        finding.append(path.finding, style=MOCHA["sapphire"])

        parts: list = [Text(""), title_line, Text(""), desc, finding]

        # Notes (highlighted)
        if path.notes:
            note = Text()
            note.append("Note: ", style=f"bold {MOCHA['peach']}")
            note.append(path.notes, style=MOCHA["peach"])
            parts.append(note)

        # Commands
        if path.commands:
            parts.append(Text(""))
            parts.append(_commands_block(path.commands))

        parts.append(Text(""))
        return Group(*parts)

    def _print_path_card(
        self,
        path: ExploitationPath,
        rank: int = 0,
        score: float = 0,
    ) -> None:
        """Print a path as a rich card (used for detail views)."""
        title_line = Text()
        if rank:
            title_line.append(f"[{rank}] ", style=f"bold {MOCHA['overlay2']}")
        title_line.append(path.technique_name, style=f"bold {MOCHA['text']}")
        title_line.append("  ")
        title_line.append_text(_score_badge(score))

        badges = Text()
        badges.append_text(_confidence_badge(path.confidence))
        badges.append("  ")
        badges.append_text(_risk_badge(path.risk))
        badges.append("  ")
        badges.append_text(_category_badge(path.category))

        desc = Text(path.description, style=MOCHA["subtext0"])

        finding = Text()
        finding.append("Finding: ", style=MOCHA["overlay1"])
        finding.append(path.finding, style=MOCHA["sapphire"])

        card_content = Text()
        card_content.append_text(title_line)
        card_content.append("\n")
        card_content.append_text(badges)
        card_content.append("\n")
        card_content.append_text(desc)
        card_content.append("\n")
        card_content.append_text(finding)

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

        if path.commands:
            self.console.print(_commands_block(path.commands))

        if path.prerequisites:
            prereq_text = Text()
            prereq_text.append("Prerequisites: ", style=f"bold {MOCHA['yellow']}")
            prereq_text.append(
                ", ".join(path.prerequisites), style=MOCHA["subtext0"]
            )
            self.console.print(prereq_text)

        if path.references:
            for ref in path.references:
                self.console.print(
                    Text(f"  {ref}", style=f"dim {MOCHA['overlay1']}")
                )

        self.console.print()

    def _build_path_entry(
        self,
        path: ExploitationPath,
        rank: int = 0,
        score: float = 0,
        show_commands: bool = True,
    ) -> Group:
        """Build a compact path entry as a Rich Group (for embedding in panels)."""
        parts: list[RenderableType] = []

        # Title: [rank]  [score]  Name  [conf]  [risk]
        title = Text()
        if rank:
            title.append(f"[{rank}]", style=f"bold {MOCHA['overlay2']}")
            title.append("  ")
        title.append_text(_score_badge(score))
        title.append("  ")
        title.append(path.technique_name, style=f"bold {MOCHA['text']}")
        title.append("   ")
        title.append_text(_confidence_badge(path.confidence))
        title.append(" ")
        title.append_text(_risk_badge(path.risk))
        parts.append(title)

        # Description
        parts.append(Text(f"  {path.description}", style=MOCHA["subtext0"]))

        # Finding
        finding = Text()
        finding.append("  Finding: ", style=MOCHA["overlay1"])
        finding.append(path.finding, style=MOCHA["sapphire"])
        parts.append(finding)

        # Commands in one block
        if show_commands and path.commands:
            parts.append(Padding(_commands_block(path.commands), (0, 0, 0, 2)))

        # Prerequisites inline
        if path.prerequisites:
            prereq = Text()
            prereq.append("  Prerequisites: ", style=MOCHA["yellow"])
            prereq.append(", ".join(path.prerequisites), style=MOCHA["subtext0"])
            parts.append(prereq)

        # References
        if path.references:
            for ref in path.references:
                parts.append(
                    Text(f"    {ref}", style=f"dim {MOCHA['overlay1']}")
                )

        # Notes
        if path.notes:
            note = Text()
            note.append("  Note: ", style=f"bold {MOCHA['peach']}")
            note.append(path.notes, style=MOCHA["peach"])
            parts.append(note)

        parts.append(Text(""))
        return Group(*parts)

    def _print_path_entry(
        self,
        path: ExploitationPath,
        rank: int = 0,
        score: float = 0,
        show_commands: bool = True,
    ) -> None:
        """Print a compact path entry (used in category listings)."""
        self.console.print(
            self._build_path_entry(path, rank, score, show_commands)
        )

    def _print_category_section(
        self,
        category: Category,
        paths: list[ExploitationPath],
        show_commands: bool,
    ) -> None:
        """Print a category section wrapped in a bordered panel."""
        color = CATEGORY_COLORS.get(category, MOCHA["subtext1"])
        cat_name = category.value.upper().replace("_", " ")
        title = f"[bold {color}]{cat_name} ({len(paths)})[/bold {color}]"

        renderables: list[RenderableType] = []
        for i, path in enumerate(paths, 1):
            score = self.ranker.get_score(path)
            renderables.append(
                self._build_path_entry(
                    path, rank=i, score=score, show_commands=show_commands
                )
            )
            if i < len(paths):
                renderables.append(Rule(style=MOCHA["surface0"]))

        self.console.print()
        self.console.print(
            Panel(
                Group(*renderables),
                title=title,
                title_align="left",
                box=ROUNDED,
                border_style=color,
                padding=(0, 1),
            )
        )

    def _build_chain(self, chain, number: int = 0) -> Group:
        """Build a single attack chain as a Rich Group (for embedding in panels)."""
        root_label = Text()
        if number:
            root_label.append(f"[{number}] ", style=f"bold {MOCHA['overlay2']}")
        root_label.append(chain.name, style=f"bold {MOCHA['text']}")
        root_label.append("  ")
        root_label.append_text(_confidence_badge(chain.confidence))
        root_label.append(" ")
        root_label.append_text(_risk_badge(chain.risk))

        tree = Tree(root_label)

        tree.add(Text(chain.description, style=MOCHA["subtext0"]))

        if chain.prerequisites:
            prereq_branch = tree.add(
                Text("Prerequisites", style=f"bold {MOCHA['yellow']}")
            )
            for prereq in chain.prerequisites:
                prereq_branch.add(Text(prereq, style=MOCHA["subtext0"]))

        for step in chain.steps:
            step_label = Text()
            step_label.append(f"Step {step.order}: ", style=f"bold {MOCHA['sapphire']}")
            step_label.append(step.description, style=MOCHA["text"])

            step_branch = tree.add(step_label)

            if step.commands:
                for cmd in step.commands:
                    if cmd.startswith("#"):
                        step_branch.add(Text(cmd, style=MOCHA["overlay1"]))
                    elif cmd == "":
                        continue
                    else:
                        step_branch.add(Text(cmd, style=MOCHA["green"]))

            if step.output:
                out_text = Text()
                out_text.append("-> ", style=MOCHA["green"])
                out_text.append(step.output, style=MOCHA["green"])
                step_branch.add(out_text)

        if chain.notes:
            note = Text()
            note.append("Note: ", style=f"bold {MOCHA['peach']}")
            note.append(chain.notes, style=MOCHA["peach"])
            tree.add(note)

        if chain.references:
            for ref in chain.references:
                tree.add(Text(ref, style=f"dim {MOCHA['overlay1']}"))

        return Group(tree, Text(""))

    def _build_score_distribution(self, scores: list[float]) -> Text:
        """Build a text histogram of score distribution."""
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

        return dist_text

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
    target_info: dict | None = None,
    show_quick_wins: bool = True,
    show_all: bool = True,
    show_summary: bool = True,
    group_by_category: bool = True,
    chains: list | None = None,
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
