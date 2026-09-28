"""Curriculum initialization from GD level metadata."""

import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional


class CurriculumInitializer:
    """
    Initialize empirical 8-stage curriculum from official GD level difficulty.

    Curriculum stages (grounded in actual GD mechanics progression):
    0. Reactive: single spikes, blocks, jump/no-jump
    1. Ballistic: jump timing, landing control
    2. Local Geometry: obstacle sequences, gap jumping
    3. State-Dependent: orbs, pads, gravity sensitivity
    4. Mode Transition: portals, gravity inversion, mode switches
    5. Continuous Control: ship, wave, robot modes
    6. Long Horizon: long sequences requiring planning
    7. Generalization: unseen content, physics perturbations

    Each stage is gated by empirical success metrics on curriculum content.
    """

    def __init__(self, levels_json_path: Optional[str] = None):
        """Initialize curriculum from GD level metadata."""
        if levels_json_path is None:
            # Default to data/gd_levels.json in repo
            levels_json_path = Path(__file__).parent.parent / "data" / "gd_levels.json"

        self.levels_json_path = levels_json_path
        self.levels_data = self._load_levels_data()
        self.curriculum = self._build_curriculum()

    def _load_levels_data(self) -> Dict[str, Any]:
        """Load GD level metadata from JSON."""
        with open(self.levels_json_path, 'r') as f:
            return json.load(f)

    def _build_curriculum(self) -> Dict[str, Any]:
        """Build curriculum structure from level data."""
        curriculum = {
            "phases": [],
            "level_assignments": {},
        }

        # Get phase definitions
        phase_defs = {p["phase"]: p for p in self.levels_data["phases"]}

        # Organize levels by phase
        for phase_idx in range(8):
            phase_def = phase_defs[phase_idx]

            # Find levels assigned to this phase
            phase_levels = [
                l for l in self.levels_data["official_levels"]
                if l["phase"] == phase_idx
            ]

            phase_info = {
                "phase": phase_idx,
                "name": phase_def["name"],
                "description": phase_def["description"],
                "goal": phase_def["goal"],
                "mechanics": phase_def["mechanics"],
                "levels": phase_levels,
                "num_levels": len(phase_levels),
                "total_difficulty": sum(l["difficulty"] for l in phase_levels),
                "gate_threshold": self._get_gate_threshold(phase_idx),
            }
            curriculum["phases"].append(phase_info)

            # Map levels to phase
            for level in phase_levels:
                curriculum["level_assignments"][level["id"]] = {
                    "level_name": level["name"],
                    "phase": phase_idx,
                    "phase_name": phase_def["name"],
                    "difficulty": level["difficulty"],
                }

        return curriculum

    def _get_gate_threshold(self, phase_idx: int) -> float:
        """Get success rate threshold for advancing to next phase."""
        # Gates are adaptive: easier phases need higher accuracy
        thresholds = {
            0: 0.95,  # Reactive: 95% (foundational)
            1: 0.93,  # Ballistic: 93%
            2: 0.90,  # Local Geometry: 90%
            3: 0.85,  # State-Dependent: 85%
            4: 0.80,  # Mode Transition: 80%
            5: 0.78,  # Continuous Control: 78%
            6: 0.75,  # Long Horizon: 75%
            7: 0.70,  # Generalization: 70% (external validation)
        }
        return thresholds.get(phase_idx, 0.75)

    def get_phase(self, phase_idx: int) -> Dict[str, Any]:
        """Get curriculum phase definition."""
        if 0 <= phase_idx < len(self.curriculum["phases"]):
            return self.curriculum["phases"][phase_idx]
        return None

    def get_level_phase(self, level_id: int) -> Optional[Dict[str, Any]]:
        """Get phase assignment for a specific level."""
        return self.curriculum["level_assignments"].get(level_id)

    def get_phase_levels(self, phase_idx: int) -> List[Dict[str, Any]]:
        """Get all levels assigned to a phase."""
        phase_info = self.get_phase(phase_idx)
        return phase_info["levels"] if phase_info else []

    def summary(self) -> str:
        """Return curriculum summary."""
        lines = ["8-Stage Empirical Curriculum:"]
        lines.append("")

        for phase in self.curriculum["phases"]:
            lines.append(f"Phase {phase['phase']}: {phase['name']}")
            lines.append(f"  Levels: {phase['num_levels']} ({[l['name'] for l in phase['levels']]})")
            lines.append(f"  Gate: {phase['gate_threshold']*100:.0f}% success rate")
            lines.append(f"  Goal: {phase['goal']}")
            lines.append("")

        return "\n".join(lines)

    def info(self):
        """Print curriculum info."""
        print(self.summary())
