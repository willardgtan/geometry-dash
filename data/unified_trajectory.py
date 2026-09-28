"""Unified 240-Hz trajectory schema for all data sources.

Merges:
- gdsolver (deterministic TAS trajectories, 60-Hz input)
- GeometryDashAgent (visual expert frames, 60-Hz JPEG + YOLO)
- geometry-dash-rl (human demonstrations, 60-Hz JSON)
- game-bot (measured occupancy grids, 60-Hz with kinematic state)

240-Hz schema stores: input decisions, observations, measurements, labels.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
from enum import Enum


class DataSource(Enum):
    """Source of trajectory data."""
    GDSOLVER = "gdsolver"  # Ground truth TAS
    GEOMETRY_DASH_AGENT = "geometry_dash_agent"  # Expert frames + YOLO
    HUMAN_DEMO = "human_demo"  # geometry-dash-rl human plays
    GAME_BOT = "game_bot"  # Measured occupancy grid + kinematics
    MIXED = "mixed"  # Hybrid source


class ObservationType(Enum):
    """Type of observation representation."""
    OCCUPANCY_GRID = "occupancy_grid"  # 24×16×4 grid
    YOLO_DETECTIONS = "yolo_detections"  # Bounding boxes + class
    KINEMATIC_STATE = "kinematic_state"  # Position, velocity, etc.
    RAW_PIXELS = "raw_pixels"  # Game screenshot
    HYBRID = "hybrid"  # Multiple observation types


@dataclass
class FrameObservation:
    """Single 240-Hz frame observation."""

    # Frame timing
    frame_idx: int  # 0-indexed frame number
    timestamp_ms: float  # Milliseconds from episode start

    # Ground truth input
    input_value: int  # 0 (no jump) or 1 (jump), from gdsolver

    # Visual observation (from GeometryDashAgent or raw pixels)
    occupancy_grid: Optional[np.ndarray] = None  # 24×16×4
    yolo_detections: Optional[List[Dict[str, Any]]] = None  # [{class, x, y, w, h, conf}, ...]
    raw_pixels: Optional[np.ndarray] = None  # 960×540×3 RGB (optional)

    # Measured kinematic state (from game-bot)
    player_x: Optional[float] = None  # Player position X
    player_y: Optional[float] = None  # Player position Y
    player_velocity_x: Optional[float] = None
    player_velocity_y: Optional[float] = None
    player_in_air: Optional[bool] = None  # Is player jumping/falling

    # Game state flags
    level_complete: bool = False
    collision_detected: bool = False
    death_flag: bool = False

    # Metadata
    observation_type: ObservationType = ObservationType.OCCUPANCY_GRID
    data_sources_present: List[DataSource] = field(default_factory=list)
    confidence_score: float = 1.0  # How certain is this observation?


@dataclass
class TrajectoryMetadata:
    """Metadata about the entire trajectory."""

    # Required fields (no defaults)
    source: DataSource
    source_file: str  # Path to original data file
    level_name: str  # "Stereo Madness", etc.
    success: bool  # Did the trajectory reach the end/win?
    distance_percent: float  # Percent of level completed (0.0-1.0)
    time_seconds: float  # Total episode duration
    frames_completed: int  # Number of frames
    expert_quality: float  # 0.0-1.0: how expert is this trajectory?
    diversity_score: float  # 0.0-1.0: how different from other trajectories?

    # Optional fields (with defaults)
    level_id: Optional[int] = None  # GD level ID if known
    difficulty_stars: Optional[int] = None  # 1-22 stars
    custom_difficulty_estimate: Optional[float] = None  # 0.0-1.0
    recorded_date: Optional[str] = None  # ISO format
    recorded_by: Optional[str] = None  # gdsolver, human_player_123, etc.
    platform: str = "unknown"  # Windows, macOS, Linux, browser, etc.
    has_visual_data: bool = False  # Visual observations available
    has_kinematic_data: bool = False  # Occupancy grid + kinematic state
    has_yolo_labels: bool = False  # YOLO annotations
    extra: Dict[str, Any] = field(default_factory=dict)  # Custom metadata


@dataclass
class UnifiedTrajectory:
    """Complete trajectory in unified 240-Hz schema.

    Designed to hold:
    1. gdsolver: input decisions only (0/1 per frame)
    2. GeometryDashAgent: visual expert frames + YOLO labels
    3. geometry-dash-rl: human demos with JSON state
    4. game-bot: measured occupancy grids + kinematic state

    Can be queried as: traj[frame_idx] → FrameObservation
    Can be converted to: occupancy_grid, YOLO detections, kinematic_state
    """

    # Core data
    frames: List[FrameObservation]
    metadata: TrajectoryMetadata

    # Efficient lookups
    _frame_index: Dict[int, int] = field(default_factory=dict, init=False)

    def __post_init__(self):
        """Build frame index for O(1) lookups."""
        for i, frame in enumerate(self.frames):
            self._frame_index[frame.frame_idx] = i

    def __len__(self) -> int:
        """Number of frames in trajectory."""
        return len(self.frames)

    def __getitem__(self, idx: int) -> FrameObservation:
        """Get frame by index."""
        if idx in self._frame_index:
            return self.frames[self._frame_index[idx]]
        raise KeyError(f"Frame {idx} not in trajectory")

    def get_observation_slice(
        self,
        start_idx: int,
        end_idx: int,
        obs_type: ObservationType = ObservationType.OCCUPANCY_GRID
    ) -> np.ndarray:
        """Get observation sequence as stacked array.

        Args:
            start_idx: Starting frame index
            end_idx: Ending frame index (exclusive)
            obs_type: Which observation to extract

        Returns:
            Stacked observations (frames, height, width, channels) or (frames, features)
        """
        observations = []

        for frame_idx in range(start_idx, end_idx):
            frame = self[frame_idx]

            if obs_type == ObservationType.OCCUPANCY_GRID:
                if frame.occupancy_grid is not None:
                    observations.append(frame.occupancy_grid)
                else:
                    # Placeholder for missing data
                    observations.append(np.zeros((24, 16, 4), dtype=np.float32))

            elif obs_type == ObservationType.KINEMATIC_STATE:
                # Stack kinematic features: [x, y, vx, vy, in_air]
                state = [
                    frame.player_x or 0.0,
                    frame.player_y or 0.0,
                    frame.player_velocity_x or 0.0,
                    frame.player_velocity_y or 0.0,
                    float(frame.player_in_air or False),
                ]
                observations.append(np.array(state, dtype=np.float32))

            elif obs_type == ObservationType.YOLO_DETECTIONS:
                # Convert YOLO detections to fixed-size feature array
                if frame.yolo_detections:
                    # Up to 10 detections, each with 6 values (x, y, w, h, class, conf)
                    detections = np.zeros((10, 6), dtype=np.float32)
                    for i, det in enumerate(frame.yolo_detections[:10]):
                        detections[i] = [
                            det.get('x', 0),
                            det.get('y', 0),
                            det.get('w', 0),
                            det.get('h', 0),
                            float(det.get('class', 0)),
                            det.get('conf', 0),
                        ]
                    observations.append(detections.flatten())
                else:
                    observations.append(np.zeros(60, dtype=np.float32))

        return np.array(observations, dtype=np.float32)

    def get_input_sequence(
        self,
        start_idx: int,
        end_idx: int
    ) -> np.ndarray:
        """Get input decisions as sequence.

        Returns:
            Array of shape (frames,) with 0/1 values
        """
        inputs = []
        for frame_idx in range(start_idx, end_idx):
            frame = self[frame_idx]
            inputs.append(frame.input_value)
        return np.array(inputs, dtype=np.int32)

    def get_success_flags(self) -> np.ndarray:
        """Get terminal flags for all frames.

        Returns:
            Array of shape (frames,) with True where episode terminates
        """
        terminals = np.zeros(len(self), dtype=bool)

        # Mark collisions as terminal
        for i, frame in enumerate(self.frames):
            if frame.collision_detected or frame.death_flag:
                terminals[i] = True

        # Mark final frame as terminal
        if len(self) > 0:
            terminals[-1] = self.metadata.success

        return terminals

    def resample_to_60hz(self) -> "UnifiedTrajectory":
        """Resample 240-Hz trajectory to 60-Hz (every 4th frame).

        Useful for compatibility with game-bot and geometry-dash-rl data.
        """
        resampled_frames = self.frames[::4]  # Every 4th frame

        resampled_trajectory = UnifiedTrajectory(
            frames=resampled_frames,
            metadata=self.metadata,
        )
        return resampled_trajectory

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            'metadata': {
                'source': self.metadata.source.value,
                'level_name': self.metadata.level_name,
                'difficulty_stars': self.metadata.difficulty_stars,
                'success': self.metadata.success,
                'distance_percent': self.metadata.distance_percent,
                'time_seconds': self.metadata.time_seconds,
                'frames_completed': self.metadata.frames_completed,
            },
            'num_frames': len(self.frames),
            'observations_available': {
                'occupancy_grid': any(f.occupancy_grid is not None for f in self.frames),
                'yolo_detections': any(f.yolo_detections is not None for f in self.frames),
                'kinematic_state': any(f.player_x is not None for f in self.frames),
            },
        }
