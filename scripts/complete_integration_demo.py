#!/usr/bin/env python3
"""Complete Geometry Dash Tier 0 Data Integration Demonstration.

This script demonstrates the full unified data layer with all available sources.
It shows how to:
1. Load metadata from multiple sources
2. Build a curriculum with difficulty clustering
3. Create a behavioral cloning dataset ready for pre-training

Usage:
    python scripts/complete_integration_demo.py
    python scripts/complete_integration_demo.py --with-gdsolver /path/to/gdsolver
    python scripts/complete_integration_demo.py --with-agent /path/to/agent/data
"""

import sys
import argparse
import numpy as np
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from data.unified_trajectory import DataSource, ObservationType
from data.loaders import (
    GDSolverLoader,
    GeometryDashAgentLoader,
    GameBotLoader,
    LevelMetadataLoader,
    HybridLoader,
)
from data.curriculum_builder import CurriculumBuilder, DifficultyMetric
from data.behavioral_cloning_dataset import BehavioralCloningDataset
from data.level_metadata_loader import HardcodedOfficialMetadata


def print_section(title: str) -> None:
    """Print formatted section header."""
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_status(label: str, value: str, icon: str = "✓") -> None:
    """Print formatted status line."""
    print(f"  {icon} {label:<40} {value}")


def main(args):
    """Run complete integration pipeline."""

    print()
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  GEOMETRY DASH RL: COMPLETE TIER 0 INTEGRATION DEMO".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "=" * 68 + "╝")
    print()

    # ===== STEP 1: Load gdsolver trajectories =====
    print_section("STEP 1: Ground Truth (gdsolver TAS Trajectories)")

    gdsolver_trajs = []
    if args.gdsolver_path and Path(args.gdsolver_path).exists():
        try:
            gdsolver_trajs = GDSolverLoader.load_directory(args.gdsolver_path)
            gdsolver_frames = sum(len(t) for t in gdsolver_trajs)
            print_status("gdsolver trajectories", f"{len(gdsolver_trajs)} loaded")
            print_status("Total frames", f"{gdsolver_frames:,}")
            if gdsolver_trajs:
                print_status(
                    "Example",
                    f"{gdsolver_trajs[0].metadata.level_name} "
                    f"({len(gdsolver_trajs[0])} frames)",
                )
        except Exception as e:
            print_status("gdsolver load error", str(e), icon="✗")
    else:
        print_status(
            "gdsolver",
            "Not provided (set --with-gdsolver PATH)",
            icon="⏳",
        )
        print_status(
            "Confidence weighting",
            "1.0 (will use 0.0 if unavailable)",
            icon="ℹ",
        )

    # ===== STEP 2: Load GeometryDashAgent expert frames =====
    print_section("STEP 2: Expert Demonstrations (GeometryDashAgent Frames)")

    agent_trajs = []
    if args.agent_path:
        agent_dir = Path(args.agent_path) / "expert_frames"
        if agent_dir.exists():
            try:
                agent_traj = GeometryDashAgentLoader.load(
                    str(agent_dir),
                    labels_directory=str(
                        Path(args.agent_path) / "yolo_labels"
                        if (Path(args.agent_path) / "yolo_labels").exists()
                        else None
                    ),
                )
                agent_trajs = [agent_traj]
                print_status("Agent trajectories", f"{len(agent_trajs)} loaded")
                print_status("Total frames", f"{len(agent_traj):,}")
                print_status(
                    "Visual observations",
                    "Yes (960×540×3 RGB)",
                )
                print_status(
                    "YOLO labels",
                    "Yes" if agent_traj.metadata.has_yolo_labels else "No",
                )
            except Exception as e:
                print_status("Agent load error", str(e), icon="✗")
        else:
            print_status("Agent frames", "Not found at specified path", icon="⏳")
    else:
        print_status("Agent data", "Not provided (set --with-agent PATH)", icon="⏳")
        print_status(
            "Confidence weighting", "0.9×expert_quality (will use 0.0 if unavailable)",
            icon="ℹ",
        )

    # ===== STEP 3: Load game-bot measured data =====
    print_section("STEP 3: Measured State (game-bot Occupancy Grids + Kinematics)")

    gamebot_trajs = []
    if args.gamebot_path and Path(args.gamebot_path).exists():
        try:
            gamebot_trajs = GameBotLoader.load_batch(
                base_directory=args.gamebot_path, level_name_pattern="level_*"
            )
            gamebot_frames = sum(len(t) for t in gamebot_trajs)
            print_status("game-bot trajectories", f"{len(gamebot_trajs)} loaded")
            print_status("Total frames", f"{gamebot_frames:,}")
            print_status("Occupancy grids", "24×16×4 (height×width×channels)")
            print_status(
                "Kinematic data", "position (x,y), velocity (vx,vy), in_air flag"
            )
        except Exception as e:
            print_status("game-bot load error", str(e), icon="✗")
    else:
        print_status("game-bot data", "Not provided (set --with-gamebot PATH)", icon="⏳")
        print_status(
            "Confidence weighting",
            "0.6×expert_quality (will use 0.0 if unavailable)",
            icon="ℹ",
        )

    # ===== STEP 4: Load level metadata from multiple sources =====
    print_section("STEP 4: Level Metadata & Difficulty Estimation")

    builder = CurriculumBuilder()
    metadata_dict = {}
    metadata_source = "none"

    # Try yusp48 CSV first
    if args.yusp48_path and Path(args.yusp48_path).exists():
        try:
            metadata_dict = LevelMetadataLoader.load_metadata_csv(args.yusp48_path)
            metadata_source = "yusp48 CSV"
        except Exception as e:
            print_status("yusp48 CSV load error", str(e), icon="⚠")

    # Fall back to hardcoded official metadata
    if not metadata_dict:
        metadata_dict = HardcodedOfficialMetadata.get_official_campaign()
        metadata_source = "hardcoded (20 official levels)"

    print_status("Levels loaded", f"{len(metadata_dict)} from {metadata_source}")

    # Add metadata to builder
    for level_name, meta in metadata_dict.items():
        builder.add_level_metadata(level_name, meta)

    # Add success rates from gdsolver
    for traj in gdsolver_trajs:
        builder.add_gdsolver_result(traj.metadata.level_name, traj.metadata.success)

    # Build curriculum clusters
    clusters = builder.build_clusters(metric=DifficultyMetric.STARS)
    print_status("Curriculum clusters", f"{len(clusters)} difficulty tiers")
    print_status(
        "Cluster range",
        f"{min(len(c.level_names) for c in clusters) if clusters else 0}"
        f"-{max(len(c.level_names) for c in clusters) if clusters else 0} levels/tier",
    )

    print()
    print(builder.summary())

    # ===== STEP 5: Create behavioral cloning dataset =====
    print_section("STEP 5: Behavioral Cloning Dataset Assembly")

    bc_dataset = BehavioralCloningDataset(
        observation_type=ObservationType.OCCUPANCY_GRID, window_size=1
    )

    # Add all trajectory sources
    total_added = 0

    for traj in gdsolver_trajs:
        cluster = builder.get_level_cluster(traj.metadata.level_name)
        difficulty = cluster.mean_difficulty if cluster else 0.5
        bc_dataset.add_trajectory(traj, difficulty=difficulty)
        total_added += len(traj)

    for traj in agent_trajs:
        cluster = builder.get_level_cluster(traj.metadata.level_name)
        difficulty = cluster.mean_difficulty if cluster else 0.5
        bc_dataset.add_trajectory(traj, difficulty=difficulty)
        total_added += len(traj)

    for traj in gamebot_trajs:
        cluster = builder.get_level_cluster(traj.metadata.level_name)
        difficulty = cluster.mean_difficulty if cluster else 0.5
        bc_dataset.add_trajectory(traj, difficulty=difficulty)
        total_added += len(traj)

    print_status("Total transitions", f"{len(bc_dataset):,}")
    print_status("Observation type", f"{ObservationType.OCCUPANCY_GRID.value}")

    if len(bc_dataset) > 0:
        print()
        print(bc_dataset.summary())

    # ===== STEP 6: Summary and status =====
    print_section("INTEGRATION STATUS SUMMARY")

    print_status("Tier 0 (Unified Data Layer)", "✓ COMPLETE", icon="✓")

    data_sources = [
        ("gdsolver TAS", gdsolver_trajs, DataSource.GDSOLVER),
        ("GeometryDashAgent expert", agent_trajs, DataSource.GEOMETRY_DASH_AGENT),
        ("game-bot measured", gamebot_trajs, DataSource.GAME_BOT),
    ]

    for name, trajs, source in data_sources:
        if trajs:
            count = sum(len(t) for t in trajs)
            print_status(f"{name}", f"{len(trajs)} trajectories, {count:,} frames", icon="✓")
        else:
            print_status(f"{name}", "NOT LOADED", icon="⏳")

    print_status("Level metadata", f"{len(metadata_dict)} levels", icon="✓")
    print_status("Curriculum clusters", f"{len(clusters)} tiers", icon="✓")
    print_status(
        "BC dataset ready",
        f"{len(bc_dataset)} transitions for pre-training",
        icon="✓" if len(bc_dataset) > 0 else "⏳",
    )

    # ===== Next steps =====
    print_section("NEXT STEPS FOR MAXIMUM MODEL QUALITY")

    print("  Tier 1 (NEXT): Obstacle Understanding Architecture")
    print("    ➜ Train YOLO on GeometryDashAgent labels")
    print("    ➜ Integrate semantic detections into occupancy grid")
    print("    ➜ Validate with game-bot measured state")
    print()
    print("  Tier 2 (THEN): Human-Informed Initialization")
    print("    ➜ Run behavioral cloning pre-training")
    print("    ➜ PPO training with curriculum phases")
    print("    ➜ Transfer learning: Phase 1-3 → Phase 4+")
    print()
    print("  Tier 3 (ADVANCED): Physics-Informed Learning")
    print("    ➜ Calibrate physics model with game-bot kinematics")
    print("    ➜ Learn forward model: state → occupancy_grid")
    print("    ➜ Use physics predictions for auxiliary learning")
    print()
    print("  Tier 4 (FINAL): Full Pipeline Integration")
    print("    ➜ Multi-task learning: BC + RL + physics")
    print("    ➜ Benchmark against speedrunning records")
    print("    ➜ Test on unseen community levels")
    print()

    if not gdsolver_trajs and not agent_trajs and not gamebot_trajs:
        print_section("TO ACTIVATE WITH YOUR DATA")
        print()
        print("  The infrastructure is ready. Provide your data sources:")
        print()
        print("    python scripts/complete_integration_demo.py \\")
        print("      --with-gdsolver /path/to/gdsolver/ \\")
        print("      --with-agent /path/to/agent/data/ \\")
        print("      --with-gamebot /path/to/game_bot/ \\")
        print("      --with-yusp48 /path/to/geometry-dash-levels.csv")
        print()
        print("  Or follow DATA_SOURCE_INTEGRATION.md for step-by-step setup")
        print()

    print()
    print("=" * 70)
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Complete Geometry Dash RL Tier 0 Data Integration Demo"
    )
    parser.add_argument(
        "--with-gdsolver",
        type=Path,
        default=None,
        help="Path to directory with gdsolver trajectory files",
    )
    parser.add_argument(
        "--with-agent",
        type=Path,
        default=None,
        help="Path to GeometryDashAgent data directory (with expert_frames/ subdirectory)",
    )
    parser.add_argument(
        "--with-gamebot",
        type=Path,
        default=None,
        help="Path to game-bot data directory with occupancy grids",
    )
    parser.add_argument(
        "--with-yusp48",
        type=Path,
        default=None,
        help="Path to yusp48 level metadata CSV file",
    )

    args = parser.parse_args()

    # Also check environment variable naming conventions
    if not args.with_gdsolver:
        args.with_gdsolver = Path("/tmp/gdsolver") if Path("/tmp/gdsolver").exists() else None
    if not args.with_agent:
        args.with_agent = (
            Path("/tmp/geometry_dash_agent") if Path("/tmp/geometry_dash_agent").exists() else None
        )
    if not args.with_gamebot:
        args.with_gamebot = Path("/tmp/game_bot") if Path("/tmp/game_bot").exists() else None
    if not args.with_yusp48:
        args.with_yusp48 = (
            Path("/tmp/geometry-dash-levels.csv")
            if Path("/tmp/geometry-dash-levels.csv").exists()
            else None
        )

    # Rename to match function parameter names
    args.gdsolver_path = args.with_gdsolver
    args.agent_path = args.with_agent
    args.gamebot_path = args.with_gamebot
    args.yusp48_path = args.with_yusp48

    main(args)
