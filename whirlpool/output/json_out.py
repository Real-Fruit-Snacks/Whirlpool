"""JSON output formatter for analysis results.

Generates structured JSON for programmatic use.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .. import __version__
from ..engine.analyzer import ExploitationPath
from ..engine.chain import AttackChain
from ..engine.ranker import Ranker


class JSONOutput:
    """JSON output formatter."""

    def __init__(self, ranker: Ranker | None = None):
        self.ranker = ranker or Ranker()

    def generate(
        self,
        paths: list[ExploitationPath],
        chains: list[AttackChain] | None = None,
        target_info: dict | None = None,
        include_scores: bool = True,
        include_raw: bool = False
    ) -> dict:
        """Generate JSON-serializable dictionary.

        Args:
            paths: List of exploitation paths
            chains: Optional list of attack chains
            target_info: Optional target information
            include_scores: Whether to include detailed score breakdowns
            include_raw: Whether to include raw finding data

        Returns:
            Dictionary ready for JSON serialization
        """
        ranked = self.ranker.rank(paths)
        quick_wins = self.ranker.get_quick_wins(paths, top_n=5)

        result: dict[str, Any] = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "Whirlpool",
                "version": __version__,
                "total_findings": len(paths),
                "quick_wins_count": len(quick_wins)
            }
        }

        if target_info:
            result["target"] = target_info

        # Summary statistics
        result["summary"] = self._generate_summary(paths)

        # Quick wins
        result["quick_wins"] = [
            self._path_to_dict(p, include_scores) for p in quick_wins
        ]

        # All findings
        result["findings"] = [
            self._path_to_dict(p, include_scores) for p in ranked
        ]

        # Findings by category
        grouped = self.ranker.group_by_category(paths)
        result["by_category"] = {
            cat.value: [self._path_to_dict(p, include_scores) for p in cat_paths]
            for cat, cat_paths in grouped.items()
        }

        # Attack chains
        if chains:
            result["attack_chains"] = [
                self._chain_to_dict(c) for c in chains
            ]

        return result

    def to_json(
        self,
        paths: list[ExploitationPath],
        indent: int = 2,
        **kwargs
    ) -> str:
        """Generate JSON string.

        Args:
            paths: List of exploitation paths
            indent: JSON indentation level
            **kwargs: Additional arguments passed to generate()

        Returns:
            JSON formatted string
        """
        data = self.generate(paths, **kwargs)
        return json.dumps(data, indent=indent, default=str)

    def save(
        self,
        paths: list[ExploitationPath],
        output_path: str | Path,
        **kwargs
    ) -> None:
        """Save JSON report to file.

        Args:
            paths: List of exploitation paths
            output_path: Path to save the report
            **kwargs: Additional arguments passed to generate()
        """
        content = self.to_json(paths, **kwargs)
        Path(output_path).write_text(content, encoding='utf-8')

    def _generate_summary(self, paths: list[ExploitationPath]) -> dict:
        """Generate summary statistics."""
        by_confidence: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        by_category: dict[str, int] = {}

        for path in paths:
            # Confidence
            conf = path.confidence.value
            by_confidence[conf] = by_confidence.get(conf, 0) + 1

            # Risk
            risk = path.risk.value
            by_risk[risk] = by_risk.get(risk, 0) + 1

            # Category
            cat = path.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

        return {
            "total": len(paths),
            "by_confidence": by_confidence,
            "by_risk": by_risk,
            "by_category": by_category,
            "high_confidence_count": by_confidence.get("high", 0),
            "low_risk_count": by_risk.get("low", 0)
        }

    def _path_to_dict(
        self,
        path: ExploitationPath,
        include_scores: bool = True
    ) -> dict:
        """Convert ExploitationPath to dictionary."""
        result: dict[str, Any] = {
            "category": path.category.value,
            "technique_name": path.technique_name,
            "description": path.description,
            "finding": path.finding,
            "commands": path.commands,
            "prerequisites": path.prerequisites,
            "confidence": path.confidence.value,
            "risk": path.risk.value,
            "references": path.references,
            "notes": path.notes
        }

        if include_scores:
            result["scores"] = {
                "final": self.ranker.get_score(path),
                "reliability": path.reliability_score,
                "safety": path.safety_score,
                "simplicity": path.simplicity_score,
                "stealth": path.stealth_score
            }
            result["score_breakdown"] = self.ranker.get_score_breakdown(path)

        return result

    def _chain_to_dict(self, chain: AttackChain) -> dict:
        """Convert AttackChain to dictionary."""
        return {
            "name": chain.name,
            "description": chain.description,
            "total_steps": chain.total_steps,
            "confidence": chain.confidence.value,
            "risk": chain.risk.value,
            "prerequisites": chain.prerequisites,
            "notes": chain.notes,
            "references": chain.references,
            "steps": [
                {
                    "order": step.order,
                    "description": step.description,
                    "commands": step.commands,
                    "prerequisites": step.prerequisites,
                    "output": step.output
                }
                for step in chain.steps
            ],
            "scores": {
                "reliability": chain.reliability_score,
                "complexity": chain.complexity_score
            }
        }


def export_json(
    paths: list[ExploitationPath],
    output_path: str | Path | None = None,
    **kwargs
) -> str | None:
    """Convenience function to export paths to JSON.

    Args:
        paths: List of exploitation paths
        output_path: Optional path to save file. If None, returns string.
        **kwargs: Additional arguments passed to JSONOutput.generate()

    Returns:
        JSON string if no output_path, None otherwise
    """
    output = JSONOutput()

    if output_path:
        output.save(paths, output_path, **kwargs)
        return None
    else:
        return output.to_json(paths, **kwargs)
