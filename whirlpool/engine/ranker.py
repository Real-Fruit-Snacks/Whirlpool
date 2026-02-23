"""Exploitation path ranking engine.

Ranks exploitation paths using a composite scoring system.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .analyzer import Category, Confidence, ExploitationPath, Risk


class RankingProfile(Enum):
    """Predefined ranking profiles for different scenarios."""
    DEFAULT = "default"          # Balanced scoring
    OSCP = "oscp"               # Prioritize reliable, documented techniques
    CTF = "ctf"                 # Prioritize quick wins
    STEALTH = "stealth"         # Prioritize low-detection techniques
    SAFE = "safe"               # Prioritize stability over speed


@dataclass
class RankingWeights:
    """Weights for the composite scoring system."""
    reliability: float = 0.40   # How likely to succeed
    safety: float = 0.30        # System stability / risk of detection
    simplicity: float = 0.20    # Ease of execution
    stealth: float = 0.10       # Detection avoidance


# Predefined weight profiles
RANKING_PROFILES: dict[RankingProfile, RankingWeights] = {
    RankingProfile.DEFAULT: RankingWeights(
        reliability=0.40,
        safety=0.30,
        simplicity=0.20,
        stealth=0.10
    ),
    RankingProfile.OSCP: RankingWeights(
        reliability=0.50,
        safety=0.25,
        simplicity=0.20,
        stealth=0.05
    ),
    RankingProfile.CTF: RankingWeights(
        reliability=0.50,
        safety=0.10,
        simplicity=0.35,
        stealth=0.05
    ),
    RankingProfile.STEALTH: RankingWeights(
        reliability=0.25,
        safety=0.25,
        simplicity=0.10,
        stealth=0.40
    ),
    RankingProfile.SAFE: RankingWeights(
        reliability=0.30,
        safety=0.50,
        simplicity=0.15,
        stealth=0.05
    ),
}


# Category-based adjustments (bonus/penalty to reliability)
CATEGORY_RELIABILITY_BONUS: dict[Category, int] = {
    Category.SUDO: 10,          # Very reliable when available
    Category.SUID: 5,           # Usually reliable
    Category.CREDENTIALS: 10,   # Direct access
    Category.DOCKER: 5,         # Usually works
    Category.LXC_LXD: 5,
    Category.POTATO: 5,         # Well-documented
    Category.KERNEL: -10,       # Can be unreliable
    Category.WILDCARD: -5,      # Situational
    Category.LOLBAS: 5,         # Well-documented techniques
    Category.NETWORK: 0,        # Neutral
    Category.WRITABLE_FILE: 10, # Very reliable
    Category.GROUP: 5,          # Usually reliable
    Category.UAC: 5,
    Category.DLL: 0,            # Situational
}


# Confidence level score adjustments
CONFIDENCE_ADJUSTMENTS: dict[Confidence, dict[str, int]] = {
    Confidence.HIGH: {"reliability": 15, "simplicity": 10},
    Confidence.MEDIUM: {"reliability": 0, "simplicity": 0},
    Confidence.LOW: {"reliability": -15, "simplicity": -10},
    Confidence.THEORETICAL: {"reliability": -30, "simplicity": -20},
}


# Risk level score adjustments
RISK_ADJUSTMENTS: dict[Risk, dict[str, int]] = {
    Risk.LOW: {"safety": 15, "stealth": 10},
    Risk.MEDIUM: {"safety": 0, "stealth": 0},
    Risk.HIGH: {"safety": -20, "stealth": -15},
}


class Ranker:
    """Ranks exploitation paths using composite scoring."""

    def __init__(
        self,
        profile: RankingProfile = RankingProfile.DEFAULT,
        custom_weights: RankingWeights | None = None
    ):
        """Initialize ranker with scoring profile.

        Args:
            profile: Predefined ranking profile to use
            custom_weights: Optional custom weights (overrides profile)
        """
        self.profile = profile
        self.weights = custom_weights or RANKING_PROFILES[profile]

    def rank(
        self,
        paths: list[ExploitationPath],
        quick_wins_only: bool = False,
        min_confidence: Confidence | None = None,
        max_risk: Risk | None = None,
        categories: list[Category] | None = None
    ) -> list[ExploitationPath]:
        """Rank exploitation paths by composite score.

        Args:
            paths: List of exploitation paths to rank
            quick_wins_only: If True, only return paths with score >= 80
            min_confidence: Minimum confidence level to include
            max_risk: Maximum risk level to include
            categories: If provided, only include these categories

        Returns:
            Sorted list of exploitation paths (highest score first)
        """
        # Apply filters
        filtered = self._filter_paths(
            paths,
            min_confidence=min_confidence,
            max_risk=max_risk,
            categories=categories
        )

        # Calculate final scores
        scored = []
        for path in filtered:
            score = self._calculate_score(path)
            scored.append((path, score))

        # Sort by score (descending)
        scored.sort(key=lambda x: x[1], reverse=True)

        # Extract paths
        ranked = [p for p, s in scored]

        # Filter quick wins if requested
        if quick_wins_only:
            ranked = [p for p, s in scored if s >= 80]

        return ranked

    def get_quick_wins(
        self,
        paths: list[ExploitationPath],
        top_n: int = 5
    ) -> list[ExploitationPath]:
        """Get the top N quick wins.

        Quick wins are paths that:
        - Have high reliability
        - Are simple to execute
        - Have low risk

        Args:
            paths: List of exploitation paths
            top_n: Number of top results to return

        Returns:
            Top N quick wins
        """
        # Use CTF profile for quick wins (prioritizes speed)
        quick_win_weights = RANKING_PROFILES[RankingProfile.CTF]

        scored = []
        for path in paths:
            # Calculate quick win score
            adjusted_scores = self._apply_adjustments(path)

            score = (
                adjusted_scores["reliability"] * quick_win_weights.reliability +
                adjusted_scores["safety"] * quick_win_weights.safety +
                adjusted_scores["simplicity"] * quick_win_weights.simplicity +
                adjusted_scores["stealth"] * quick_win_weights.stealth
            )

            # Bonus for high confidence + low risk
            if path.confidence == Confidence.HIGH and path.risk == Risk.LOW:
                score += 10

            scored.append((path, score))

        # Sort and return top N
        scored.sort(key=lambda x: x[1], reverse=True)
        return [p for p, s in scored[:top_n]]

    def group_by_category(
        self,
        paths: list[ExploitationPath]
    ) -> dict[Category, list[ExploitationPath]]:
        """Group paths by category, ranked within each group.

        Args:
            paths: List of exploitation paths

        Returns:
            Dictionary mapping categories to ranked paths
        """
        groups: dict[Category, list[ExploitationPath]] = {}

        for path in paths:
            if path.category not in groups:
                groups[path.category] = []
            groups[path.category].append(path)

        # Rank within each group
        for category in groups:
            groups[category] = self.rank(groups[category])

        return groups

    def get_score(self, path: ExploitationPath) -> float:
        """Get the composite score for a single path.

        Args:
            path: Exploitation path to score

        Returns:
            Composite score (0-100)
        """
        return self._calculate_score(path)

    def get_score_breakdown(
        self,
        path: ExploitationPath
    ) -> dict[str, float | dict[str, float]]:
        """Get detailed score breakdown for a path.

        Args:
            path: Exploitation path to analyze

        Returns:
            Dictionary with component scores and final score
        """
        adjusted = self._apply_adjustments(path)

        return {
            "reliability": adjusted["reliability"],
            "safety": adjusted["safety"],
            "simplicity": adjusted["simplicity"],
            "stealth": adjusted["stealth"],
            "reliability_weighted": adjusted["reliability"] * self.weights.reliability,
            "safety_weighted": adjusted["safety"] * self.weights.safety,
            "simplicity_weighted": adjusted["simplicity"] * self.weights.simplicity,
            "stealth_weighted": adjusted["stealth"] * self.weights.stealth,
            "final_score": self._calculate_score(path),
            "weights": {
                "reliability": self.weights.reliability,
                "safety": self.weights.safety,
                "simplicity": self.weights.simplicity,
                "stealth": self.weights.stealth,
            }
        }

    def _filter_paths(
        self,
        paths: list[ExploitationPath],
        min_confidence: Confidence | None = None,
        max_risk: Risk | None = None,
        categories: list[Category] | None = None
    ) -> list[ExploitationPath]:
        """Filter paths based on criteria."""
        result = paths

        # Confidence ordering for comparison
        confidence_order = [
            Confidence.THEORETICAL,
            Confidence.LOW,
            Confidence.MEDIUM,
            Confidence.HIGH
        ]

        risk_order = [Risk.LOW, Risk.MEDIUM, Risk.HIGH]

        if min_confidence is not None:
            min_idx = confidence_order.index(min_confidence)
            result = [
                p for p in result
                if confidence_order.index(p.confidence) >= min_idx
            ]

        if max_risk is not None:
            max_idx = risk_order.index(max_risk)
            result = [
                p for p in result
                if risk_order.index(p.risk) <= max_idx
            ]

        if categories is not None:
            result = [p for p in result if p.category in categories]

        return result

    def _apply_adjustments(
        self,
        path: ExploitationPath
    ) -> dict[str, float]:
        """Apply all adjustments to base scores.

        Returns:
            Adjusted scores (clamped to 0-100)
        """
        # Start with base scores
        reliability = path.reliability_score
        safety = path.safety_score
        simplicity = path.simplicity_score
        stealth = path.stealth_score

        # Apply category bonus/penalty
        if path.category in CATEGORY_RELIABILITY_BONUS:
            reliability += CATEGORY_RELIABILITY_BONUS[path.category]

        # Apply confidence adjustments
        if path.confidence in CONFIDENCE_ADJUSTMENTS:
            adj = CONFIDENCE_ADJUSTMENTS[path.confidence]
            reliability += adj.get("reliability", 0)
            simplicity += adj.get("simplicity", 0)

        # Apply risk adjustments
        if path.risk in RISK_ADJUSTMENTS:
            adj = RISK_ADJUSTMENTS[path.risk]
            safety += adj.get("safety", 0)
            stealth += adj.get("stealth", 0)

        # Clamp all values to 0-100
        def clamp(val: float) -> float:
            return max(0, min(100, val))

        return {
            "reliability": clamp(reliability),
            "safety": clamp(safety),
            "simplicity": clamp(simplicity),
            "stealth": clamp(stealth),
        }

    def _calculate_score(self, path: ExploitationPath) -> float:
        """Calculate final composite score.

        Args:
            path: Exploitation path to score

        Returns:
            Final score (0-100)
        """
        adjusted = self._apply_adjustments(path)

        score = (
            adjusted["reliability"] * self.weights.reliability +
            adjusted["safety"] * self.weights.safety +
            adjusted["simplicity"] * self.weights.simplicity +
            adjusted["stealth"] * self.weights.stealth
        )

        return round(score, 2)


def rank_paths(
    paths: list[ExploitationPath],
    profile: RankingProfile = RankingProfile.DEFAULT
) -> list[ExploitationPath]:
    """Convenience function to rank paths with default settings.

    Args:
        paths: List of exploitation paths
        profile: Ranking profile to use

    Returns:
        Ranked list of paths
    """
    ranker = Ranker(profile=profile)
    return ranker.rank(paths)
