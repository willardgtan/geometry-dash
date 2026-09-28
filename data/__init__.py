"""Unified data layer for Geometry Dash RL training.

Merges multiple data sources:
- gdsolver trajectories (ground truth TAS solutions)
- GeometryDashAgent expert frames (human demonstrations with visual grounding)
- yusp48 level metadata (difficulty, popularity, version)
- game-bot data (occupancy grids + kinematic state, when available)

All data flows through unified 240-Hz trajectory schema.
"""

from .unified_trajectory import UnifiedTrajectory, TrajectoryMetadata
from .loaders import (
    GDSolverLoader,
    GeometryDashAgentLoader,
    LevelMetadataLoader,
    GameBotLoader,
)
from .curriculum_builder import CurriculumBuilder, DifficultyCluster
from .behavioral_cloning_dataset import BehavioralCloningDataset
from .level_metadata_loader import (
    GDPYLevelMetadataLoader,
    HardcodedOfficialMetadata,
)

__all__ = [
    "UnifiedTrajectory",
    "TrajectoryMetadata",
    "GDSolverLoader",
    "GeometryDashAgentLoader",
    "LevelMetadataLoader",
    "GameBotLoader",
    "CurriculumBuilder",
    "DifficultyCluster",
    "BehavioralCloningDataset",
    "GDPYLevelMetadataLoader",
    "HardcodedOfficialMetadata",
]
