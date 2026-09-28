"""Data inventory: discover and catalog all available training data sources."""

import os
import json
from pathlib import Path
from typing import Dict, List, Optional, Any


class DataInventory:
    """
    Discovers and catalogs all available training data sources:
    - gdsolver dumps (240-Hz game state ground truth)
    - geometry-dash-rl repo (calibrated physics, Gym environment)
    - game-bot repo (trained perception model, occupancy grid)
    - GD wiki (level metadata, difficulty ratings)
    """

    def __init__(self, repo_root: Optional[str] = None):
        """Initialize inventory with optional repo root."""
        self.repo_root = Path(repo_root or os.getcwd())
        self.discovered = {}
        self._discover_all()

    def _discover_all(self):
        """Run all discovery methods."""
        self.discovered["gdsolver"] = self._discover_gdsolver()
        self.discovered["geometry_dash_rl"] = self._discover_geometry_dash_rl()
        self.discovered["game_bot"] = self._discover_game_bot()
        self.discovered["gd_wiki"] = self._discover_gd_wiki()

    def _discover_gdsolver(self) -> Dict[str, Any]:
        """Discover gdsolver installation and available dumps."""
        result = {
            "found": False,
            "dumps_path": None,
            "available_dumps": [],
            "total_dumps": 0,
            "official_levels": 0,
            "custom_levels": 0,
        }

        # Check common locations for gdsolver
        possible_paths = [
            self.repo_root / "gdsolver",
            self.repo_root / "../gdsolver",
            Path.home() / ".local" / "share" / "gdsolver",
            Path("/opt/gdsolver"),
        ]

        for path in possible_paths:
            if path.exists():
                result["found"] = True
                dumps_dir = path / "dumps"
                if dumps_dir.exists():
                    result["dumps_path"] = str(dumps_dir)
                    dumps = list(dumps_dir.glob("*.csv"))
                    result["available_dumps"] = [d.name for d in dumps]
                    result["total_dumps"] = len(dumps)
                    break

        return result

    def _discover_geometry_dash_rl(self) -> Dict[str, Any]:
        """Discover geometry-dash-rl repository."""
        result = {
            "found": False,
            "repo_path": None,
            "physics_constants": None,
            "has_gym_env": False,
            "has_trained_models": False,
        }

        possible_paths = [
            self.repo_root / "geometry-dash-rl",
            self.repo_root / "../geometry-dash-rl",
            Path.home() / "projects" / "geometry-dash-rl",
        ]

        for path in possible_paths:
            if (path / "setup.py").exists() or (path / "pyproject.toml").exists():
                result["found"] = True
                result["repo_path"] = str(path)

                # Check for physics constants
                constants_file = path / "gdrl" / "physics" / "constants.py"
                if constants_file.exists():
                    result["physics_constants"] = str(constants_file)

                # Check for Gym environment
                if (path / "gdrl" / "envs").exists():
                    result["has_gym_env"] = True

                # Check for trained models
                models_dir = path / "models"
                if models_dir.exists():
                    result["has_trained_models"] = len(list(models_dir.glob("*.pt"))) > 0

                break

        return result

    def _discover_game_bot(self) -> Dict[str, Any]:
        """Discover game-bot repository."""
        result = {
            "found": False,
            "repo_path": None,
            "has_perception_model": False,
            "grid_dimensions": None,
            "state_vector_size": None,
        }

        possible_paths = [
            self.repo_root / "game-bot",
            self.repo_root / "../game-bot",
            Path.home() / "projects" / "game-bot",
        ]

        for path in possible_paths:
            if (path / "main.py").exists() or (path / "setup.py").exists():
                result["found"] = True
                result["repo_path"] = str(path)

                # game-bot uses 24x16x4 occupancy grid
                result["grid_dimensions"] = (24, 16, 4)
                # 19 state variables
                result["state_vector_size"] = 19

                # Check for trained models
                models = list(path.glob("*.pt")) + list(path.glob("models/*.pt"))
                result["has_perception_model"] = len(models) > 0

                break

        return result

    def _discover_gd_wiki(self) -> Dict[str, Any]:
        """Discover GD level metadata (official levels, difficulty ratings)."""
        result = {
            "found": False,
            "official_levels": 22,
            "spinoff_levels": 17,
            "total_verified_clears": 0,
            "mechanics_data": None,
        }

        # Check for local GD mechanics reference
        mechanics_file = self.repo_root / "data" / "mechanics_reference.json"
        if mechanics_file.exists():
            result["found"] = True
            result["mechanics_data"] = str(mechanics_file)

        return result

    def summary(self) -> str:
        """Return human-readable summary of discovered data."""
        lines = ["Data Inventory Summary:"]
        lines.append("")

        gs = self.discovered.get("gdsolver", {})
        lines.append(f"gdsolver: {'✓ Found' if gs.get('found') else '✗ Not found'}")
        if gs.get("found"):
            lines.append(f"  - Dumps: {gs.get('total_dumps')} available")
            lines.append(f"  - Path: {gs.get('dumps_path')}")

        gr = self.discovered.get("geometry_dash_rl", {})
        lines.append(f"geometry-dash-rl: {'✓ Found' if gr.get('found') else '✗ Not found'}")
        if gr.get("found"):
            lines.append(f"  - Physics constants: {gr.get('physics_constants')}")
            lines.append(f"  - Gym env: {gr.get('has_gym_env')}")
            lines.append(f"  - Trained models: {gr.get('has_trained_models')}")

        gb = self.discovered.get("game_bot", {})
        lines.append(f"game-bot: {'✓ Found' if gb.get('found') else '✗ Not found'}")
        if gb.get("found"):
            lines.append(f"  - Grid: {gb.get('grid_dimensions')}")
            lines.append(f"  - State size: {gb.get('state_vector_size')}")
            lines.append(f"  - Trained model: {gb.get('has_perception_model')}")

        gd = self.discovered.get("gd_wiki", {})
        lines.append(f"GD metadata: {'✓ Found' if gd.get('found') else '✗ Not found'}")
        if gd.get("found"):
            lines.append(f"  - Official levels: {gd.get('official_levels')}")
            lines.append(f"  - Spinoff levels: {gd.get('spinoff_levels')}")

        return "\n".join(lines)

    def get_discovered(self) -> Dict[str, Any]:
        """Return raw discovered data."""
        return self.discovered
