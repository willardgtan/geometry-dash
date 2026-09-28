#!/usr/bin/env python
"""Integration example: loading real data sources and merging into unified trajectories.

This script demonstrates Tier 0 (Unified Data Layer) with actual sources:
- gdsolver: TAS trajectories (ground truth)
- GeometryDashAgent: Expert frames with YOLO labels
- yusp48: Level metadata (difficulty, popularity)
- game-bot: [NOT YET INTEGRATED] Measured occupancy grids + kinematics

Usage:
    python scripts/integrate_data_sources.py [--gdsolver-path] [--agent-path]

Output:
    1. Summary of integrated trajectories
    2. Curriculum clusters built from level metadata
    3. Behavioral cloning dataset ready for offline pre-training
"""

import argparse
import numpy as np
from pathlib import Path
from collections import defaultdict

from data.unified_trajectory import DataSource, ObservationType
from data.loaders import (
    GDSolverLoader,
    GeometryDashAgentLoader,
    LevelMetadataLoader,
    HybridLoader,
)
from data.curriculum_builder import CurriculumBuilder, DifficultyMetric
from data.behavioral_cloning_dataset import BehavioralCloningDataset


def main(args):
    """Main integration pipeline."""

    print("=" * 60)
    print("GEOMETRY DASH RL: TIER 0 DATA INTEGRATION")
    print("=" * 60)
    print()

    # ===== STEP 1: Load gdsolver trajectories =====
    print("[1/5] Loading gdsolver TAS trajectories...")
    gdsolver_trajs = []

    if args.gdsolver_path and Path(args.gdsolver_path).exists():
        gdsolver_trajs = GDSolverLoader.load_directory(args.gdsolver_path)
        print(f"✓ Loaded {len(gdsolver_trajs)} gdsolver trajectories")

        # Show examples
        if gdsolver_trajs:
            print(f"  Example: {gdsolver_trajs[0].metadata.level_name} "
                  f"({len(gdsolver_trajs[0])} frames)")
    else:
        print("✗ gdsolver path not provided or not found")
        print("  (Set with --gdsolver-path if you have gdsolver data)")

    print()

    # ===== STEP 2: Load GeometryDashAgent expert frames =====
    print("[2/5] Loading GeometryDashAgent expert frames...")
    agent_trajs = []

    if args.agent_path and Path(args.agent_path / "expert_frames").exists():
        agent_traj = GeometryDashAgentLoader.load(
            str(args.agent_path / "expert_frames"),
            labels_directory=str(args.agent_path / "yolo_labels") if (args.agent_path / "yolo_labels").exists() else None
        )
        agent_trajs = [agent_traj]
        print(f"✓ Loaded {len(agent_trajs)} GeometryDashAgent trajectories")
        print(f"  Frames: {len(agent_traj)}")
        print(f"  YOLO labels: {'Yes' if agent_traj.metadata.has_yolo_labels else 'No'}")
    else:
        print("✗ GeometryDashAgent path not provided or not found")
        print("  Expected: <path>/expert_frames/ with frame_*.jpg files")

    print()

    # ===== STEP 3: Build curriculum from level metadata =====
    print("[3/5] Building curriculum from level metadata...")

    builder = CurriculumBuilder()

    # Try to load yusp48 metadata
    metadata_loaded = False
    for candidate_csv in [
        Path("/tmp/geometry-dash-levels.csv"),
        Path.home() / ".cache" / "geometry-dash-levels.csv",
    ]:
        if candidate_csv.exists():
            try:
                metadata_dict = LevelMetadataLoader.load_metadata_csv(str(candidate_csv))
                print(f"✓ Loaded {len(metadata_dict)} level metadata entries from {candidate_csv.name}")
                metadata_loaded = True

                # Add to builder
                for level_name, meta in metadata_dict.items():
                    builder.add_level_metadata(level_name, meta)
                break
            except Exception as e:
                print(f"  Warning: Could not load {candidate_csv}: {e}")

    if not metadata_loaded:
        print("✗ No yusp48 metadata found")
        print("  Recommendation: Download from https://huggingface.co/datasets/yusp48/geometry-dash-levels")
        # Create dummy metadata for loaded trajectories
        for traj in gdsolver_trajs + agent_trajs:
            builder.add_level_metadata(
                traj.metadata.level_name,
                {'stars': traj.metadata.difficulty_stars or 5}
            )

    # Add gdsolver success rates
    for traj in gdsolver_trajs:
        builder.add_gdsolver_result(traj.metadata.level_name, traj.metadata.success)

    # Build curriculum clusters
    clusters = builder.build_clusters(metric=DifficultyMetric.STARS)
    print()
    print(builder.summary())

    print()

    # ===== STEP 4: Create behavioral cloning dataset =====
    print("[4/5] Creating behavioral cloning dataset...")

    bc_dataset = BehavioralCloningDataset(
        observation_type=ObservationType.OCCUPANCY_GRID,
        window_size=1
    )

    # Add gdsolver trajectories
    for i, traj in enumerate(gdsolver_trajs):
        # Get difficulty from cluster or metadata
        cluster = builder.get_level_cluster(traj.metadata.level_name)
        difficulty = cluster.mean_difficulty if cluster else 0.5
        bc_dataset.add_trajectory(traj, difficulty=difficulty)

    # Add agent trajectories
    for i, traj in enumerate(agent_trajs):
        cluster = builder.get_level_cluster(traj.metadata.level_name)
        difficulty = cluster.mean_difficulty if cluster else 0.5
        bc_dataset.add_trajectory(traj, difficulty=difficulty)

    print(f"✓ Created BC dataset with {len(bc_dataset)} transitions")
    print()
    print(bc_dataset.summary())

    print()

    # ===== STEP 5: Summary and next steps =====
    print("[5/5] Integration summary...")
    print()

    total_frames = sum(len(t) for t in gdsolver_trajs + agent_trajs)

    print("╔════════════════════════════════════════════════╗")
    print("║ TIER 0: UNIFIED DATA LAYER - INTEGRATION STATUS║")
    print("╚════════════════════════════════════════════════╝")
    print()
    print(f"Data Sources Integrated:")
    print(f"  ✓ gdsolver:             {len(gdsolver_trajs)} trajectories, {total_frames if gdsolver_trajs else 0} total frames")
    print(f"  ✓ GeometryDashAgent:    {len(agent_trajs)} trajectories, {sum(len(t) for t in agent_trajs) if agent_trajs else 0} total frames")
    print(f"  ✓ yusp48 metadata:      {'Yes' if metadata_loaded else 'No (recommended)'}")
    print(f"  ✗ game-bot (17,499 attempts): NOT YET LOCATED")
    print()
    print(f"Curriculum:")
    print(f"  Difficulty Clusters:    {len(clusters)}")
    print(f"  Levels per Cluster:     {min(len(c.level_names) for c in clusters) if clusters else 0}-{max(len(c.level_names) for c in clusters) if clusters else 0}")
    print()
    print(f"Behavioral Cloning Dataset:")
    print(f"  Total Transitions:      {len(bc_dataset)}")
    print(f"  Observation Type:       {ObservationType.OCCUPANCY_GRID.value}")
    print()

    # Sample a batch
    if len(bc_dataset) > 0:
        obs, actions, confidences = bc_dataset.get_batch(batch_size=8)
        print(f"Sample Batch (8 transitions):")
        print(f"  Observations:           {obs.shape}")
        print(f"  Actions (0/1):          {actions}")
        print(f"  Mean Confidence:        {confidences.mean():.3f}")
        print()

    print("Next Steps for Maximum Model Quality:")
    print()
    print("  TIER 0 (NOW): ✓ Unified data layer")
    print("    - Load: gdsolver, GeometryDashAgent, yusp48")
    print("    - Missing: game-bot 17,499 attempts with occupancy grids")
    print()
    print("  TIER 1 (NEXT): Obstacle understanding architecture")
    print("    - Train YOLO on GeometryDashAgent labels")
    print("    - Integrate semantic detections into occupancy grid")
    print("    - Validate with game-bot measured state")
    print()
    print("  TIER 2 (THEN): Human-informed initialization")
    print("    - Behavioral cloning pre-training (gdsolver + GeometryDashAgent)")
    print("    - Curriculum initialization with difficulty clustering")
    print("    - Transfer learning: Phase 1-3 → Phase 4+")
    print()
    print("  TIER 3-4: Physics-informed learning + full pipeline")
    print()

    print("📍 Action Required:")
    print()
    print("The unified data layer is ready. To maximize model quality:")
    print()
    print("1. Locate game-bot repository with 17,499 attempts")
    print("   - Contains: 24×16×4 occupancy grids + 19 kinematic scalars")
    print("   - Will integrate immediately with GameBotLoader")
    print()
    print("2. Download yusp48 metadata for curriculum learning")
    print("   - Source: https://huggingface.co/datasets/yusp48/geometry-dash-levels")
    print()
    print("3. Run behavioral cloning pre-training")
    print("   - Foundation for RL agent with expert initialization")
    print()

    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Integrate Geometry Dash RL data sources"
    )
    parser.add_argument(
        "--gdsolver-path",
        type=Path,
        default=None,
        help="Path to directory with gdsolver trajectory files"
    )
    parser.add_argument(
        "--agent-path",
        type=Path,
        default=None,
        help="Path to GeometryDashAgent data directory (with expert_frames/ subdirectory)"
    )

    args = parser.parse_args()
    main(args)
