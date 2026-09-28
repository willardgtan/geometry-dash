"""Data loaders for all Geometry Dash RL sources.

Converts gdsolver, GeometryDashAgent, yusp48, and game-bot data
into unified UnifiedTrajectory format.
"""

from typing import List, Dict, Any, Optional, Tuple
import numpy as np
import json
from pathlib import Path
import re

from .unified_trajectory import (
    UnifiedTrajectory,
    TrajectoryMetadata,
    FrameObservation,
    DataSource,
    ObservationType,
)


class GDSolverLoader:
    """Load gdsolver TAS trajectories.

    Format: plain text, one line per frame
        input=<tick>,<0|1>

    Example:
        input=0,0
        input=60,1
        input=120,0
    """

    @staticmethod
    def load(trajectory_path: str, level_name: str = "Unknown") -> UnifiedTrajectory:
        """Load gdsolver trajectory file.

        Args:
            trajectory_path: Path to .txt trajectory file
            level_name: Level name for metadata

        Returns:
            UnifiedTrajectory with input decisions (0/1 per frame)
        """
        frames = []
        frame_count = 0
        last_input = 0

        with open(trajectory_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith('input='):
                    continue

                # Parse: input=<tick>,<0|1>
                match = re.match(r'input=(\d+),([01])', line)
                if not match:
                    continue

                tick, input_val = int(match.group(1)), int(match.group(2))

                # Expand frames from last_tick to current_tick
                while frame_count < tick:
                    frame = FrameObservation(
                        frame_idx=frame_count,
                        timestamp_ms=frame_count * (1000.0 / 240.0),  # 240-Hz
                        input_value=last_input,
                        observation_type=ObservationType.OCCUPANCY_GRID,
                        data_sources_present=[DataSource.GDSOLVER],
                    )
                    frames.append(frame)
                    frame_count += 1

                last_input = input_val

        # Final frame
        frame = FrameObservation(
            frame_idx=frame_count,
            timestamp_ms=frame_count * (1000.0 / 240.0),
            input_value=last_input,
            observation_type=ObservationType.OCCUPANCY_GRID,
            data_sources_present=[DataSource.GDSOLVER],
            level_complete=True,
            collision_detected=False,
        )
        frames.append(frame)

        metadata = TrajectoryMetadata(
            source=DataSource.GDSOLVER,
            source_file=str(trajectory_path),
            level_name=level_name,
            success=True,  # gdsolver solutions always succeed
            distance_percent=1.0,
            time_seconds=len(frames) * (1.0 / 240.0),
            frames_completed=len(frames),
            expert_quality=1.0,  # TAS is optimal
            diversity_score=0.0,  # All gdsolver solutions are deterministic
            recorded_by="gdsolver",
        )

        return UnifiedTrajectory(frames=frames, metadata=metadata)

    @staticmethod
    def load_directory(directory: str, pattern: str = "*.txt") -> List[UnifiedTrajectory]:
        """Load all trajectories from directory.

        Args:
            directory: Path to directory containing trajectory files
            pattern: File pattern to match

        Returns:
            List of UnifiedTrajectories
        """
        trajectories = []
        for filepath in Path(directory).glob(pattern):
            # Extract level name from filename
            level_name = filepath.stem
            traj = GDSolverLoader.load(str(filepath), level_name)
            trajectories.append(traj)
        return trajectories


class GeometryDashAgentLoader:
    """Load GeometryDashAgent expert frames and YOLO labels.

    Structure:
    - data/expert_frames/frame_0.jpg, frame_1.jpg, ...
    - Optional: data/yolo_labels/ with detection JSONs
    """

    @staticmethod
    def load(
        frames_directory: str,
        labels_directory: Optional[str] = None,
        level_name: str = "Unknown"
    ) -> UnifiedTrajectory:
        """Load expert frames and YOLO labels.

        Args:
            frames_directory: Path to expert_frames directory
            labels_directory: Path to YOLO labels directory
            level_name: Level name for metadata

        Returns:
            UnifiedTrajectory with visual observations and YOLO labels
        """
        frames_path = Path(frames_directory)
        frame_files = sorted(frames_path.glob("frame_*.jpg"))

        frames = []
        total_frames = len(frame_files)

        for frame_idx, frame_file in enumerate(frame_files):
            # Load YOLO labels if available
            yolo_detections = None
            if labels_directory:
                label_file = Path(labels_directory) / f"frame_{frame_idx}.json"
                if label_file.exists():
                    with open(label_file, 'r') as f:
                        yolo_data = json.load(f)
                        yolo_detections = yolo_data.get('detections', [])

            frame = FrameObservation(
                frame_idx=frame_idx,
                timestamp_ms=frame_idx * (1000.0 / 60.0),  # 60-Hz
                input_value=0,  # Will be inferred or left unknown
                yolo_detections=yolo_detections,
                observation_type=ObservationType.YOLO_DETECTIONS,
                data_sources_present=[DataSource.GEOMETRY_DASH_AGENT],
                confidence_score=0.8,  # Expert frames are high confidence
            )
            frames.append(frame)

        metadata = TrajectoryMetadata(
            source=DataSource.GEOMETRY_DASH_AGENT,
            source_file=str(frames_directory),
            level_name=level_name,
            success=True,  # Expert frames are successful
            distance_percent=1.0,
            time_seconds=len(frames) * (1.0 / 60.0),
            frames_completed=len(frames),
            expert_quality=0.9,  # Expert demonstrations
            diversity_score=0.3,  # Some variation between frames
            recorded_by="geometry_dash_agent_expert",
            has_visual_data=True,
            has_yolo_labels=(labels_directory is not None),
        )

        return UnifiedTrajectory(frames=frames, metadata=metadata)


class LevelMetadataLoader:
    """Load level metadata from yusp48 dataset.

    Provides:
    - Level name, ID
    - Difficulty (stars)
    - Popularity metrics (downloads, likes, version)
    """

    @staticmethod
    def load_metadata_csv(csv_path: str) -> Dict[str, Dict[str, Any]]:
        """Load level metadata from yusp48 CSV.

        Args:
            csv_path: Path to metadata CSV

        Returns:
            Dict mapping level_name → metadata dict
        """
        import csv

        metadata = {}

        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                level_name = row.get('name', 'Unknown')
                metadata[level_name] = {
                    'level_id': row.get('id'),
                    'difficulty_stars': int(row.get('stars', 0)),
                    'downloads': int(row.get('downloads', 0)),
                    'likes': int(row.get('likes', 0)),
                    'version': row.get('version', '1.0'),
                    'upload_date': row.get('upload_date'),
                }

        return metadata

    @staticmethod
    def augment_trajectory(
        trajectory: UnifiedTrajectory,
        metadata_dict: Dict[str, Dict[str, Any]]
    ) -> UnifiedTrajectory:
        """Augment trajectory with level metadata.

        Args:
            trajectory: UnifiedTrajectory to augment
            metadata_dict: Metadata dictionary from load_metadata_csv

        Returns:
            Updated trajectory with metadata fields set
        """
        level_name = trajectory.metadata.level_name

        if level_name in metadata_dict:
            meta = metadata_dict[level_name]
            trajectory.metadata.level_id = meta.get('level_id')
            trajectory.metadata.difficulty_stars = meta.get('difficulty_stars')
            trajectory.metadata.extra['downloads'] = meta.get('downloads')
            trajectory.metadata.extra['likes'] = meta.get('likes')

        return trajectory


class GameBotLoader:
    """Load game-bot measured data.

    Format: 17,499 attempts with occupancy grids + kinematic state

    Expected structure:
    - occupancy_grids/ : 24×16×4 NumPy arrays per frame
    - kinematics.jsonl : Kinematic state per frame
    """

    @staticmethod
    def load(
        occupancy_dir: str,
        kinematics_file: str,
        level_name: str = "Unknown"
    ) -> UnifiedTrajectory:
        """Load game-bot measured data.

        Args:
            occupancy_dir: Directory containing occupancy grid .npy files
            kinematics_file: JSONL file with kinematic state
            level_name: Level name

        Returns:
            UnifiedTrajectory with measured occupancy grids and kinematics
        """
        occupancy_path = Path(occupancy_dir)
        occupancy_files = sorted(occupancy_path.glob("frame_*.npy"))

        # Load kinematics
        kinematics = {}
        if Path(kinematics_file).exists():
            with open(kinematics_file, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    frame_idx = data.get('frame_idx')
                    kinematics[frame_idx] = data

        frames = []
        collision_detected = False

        for frame_idx, grid_file in enumerate(occupancy_files):
            # Load occupancy grid
            occupancy_grid = np.load(grid_file)

            # Load kinematics
            kin = kinematics.get(frame_idx, {})

            frame = FrameObservation(
                frame_idx=frame_idx,
                timestamp_ms=frame_idx * (1000.0 / 60.0),  # 60-Hz
                input_value=kin.get('input', 0),
                occupancy_grid=occupancy_grid,
                player_x=kin.get('player_x'),
                player_y=kin.get('player_y'),
                player_velocity_x=kin.get('player_vx'),
                player_velocity_y=kin.get('player_vy'),
                player_in_air=kin.get('in_air'),
                collision_detected=kin.get('collision', False),
                death_flag=kin.get('death', False),
                observation_type=ObservationType.OCCUPANCY_GRID,
                data_sources_present=[DataSource.GAME_BOT],
            )
            frames.append(frame)

            if frame.collision_detected or frame.death_flag:
                collision_detected = True

        success = not collision_detected and len(frames) > 0

        metadata = TrajectoryMetadata(
            source=DataSource.GAME_BOT,
            source_file=occupancy_dir,
            level_name=level_name,
            success=success,
            distance_percent=1.0 if success else 0.5,
            time_seconds=len(frames) * (1.0 / 60.0),
            frames_completed=len(frames),
            expert_quality=0.5,  # Measured data, not necessarily expert
            diversity_score=0.7,  # Diverse live attempts
            recorded_by="game_bot_agent",
            has_visual_data=False,
            has_kinematic_data=True,
        )

        return UnifiedTrajectory(frames=frames, metadata=metadata)

    @staticmethod
    def load_batch(
        base_directory: str,
        level_name_pattern: str = "*"
    ) -> List[UnifiedTrajectory]:
        """Load all game-bot attempts from directory structure.

        Args:
            base_directory: Root directory containing attempt subdirectories
            level_name_pattern: Pattern for level names

        Returns:
            List of UnifiedTrajectories
        """
        base_path = Path(base_directory)
        trajectories = []

        for level_dir in sorted(base_path.glob(level_name_pattern)):
            if not level_dir.is_dir():
                continue

            occupancy_dir = level_dir / "occupancy_grids"
            kinematics_file = level_dir / "kinematics.jsonl"

            if occupancy_dir.exists() and kinematics_file.exists():
                traj = GameBotLoader.load(
                    str(occupancy_dir),
                    str(kinematics_file),
                    level_name=level_dir.name
                )
                trajectories.append(traj)

        return trajectories


class HybridLoader:
    """Load and merge multiple data sources into single trajectory.

    Useful for combining:
    - gdsolver ground truth input with game-bot measured state
    - GeometryDashAgent visual with game-bot kinematics
    """

    @staticmethod
    def merge(
        trajectories: List[UnifiedTrajectory],
        priority_order: List[DataSource] = None
    ) -> UnifiedTrajectory:
        """Merge multiple trajectories into single unified trajectory.

        Args:
            trajectories: List of UnifiedTrajectories to merge
            priority_order: Priority for which source wins on conflicts

        Returns:
            Single merged UnifiedTrajectory
        """
        if not trajectories:
            raise ValueError("No trajectories to merge")

        if priority_order is None:
            # Default priority: gdsolver ground truth > game-bot > geometry-dash-agent
            priority_order = [
                DataSource.GDSOLVER,
                DataSource.GAME_BOT,
                DataSource.GEOMETRY_DASH_AGENT,
                DataSource.HUMAN_DEMO,
            ]

        # Use first trajectory as base
        base = trajectories[0]
        merged_frames = [frame.__dict__.copy() for frame in base.frames]

        # Merge in priority order
        for traj in trajectories[1:]:
            for i, frame in enumerate(traj.frames):
                if i < len(merged_frames):
                    # Fill in missing data from this trajectory
                    if merged_frames[i]['occupancy_grid'] is None and frame.occupancy_grid is not None:
                        merged_frames[i]['occupancy_grid'] = frame.occupancy_grid
                    if merged_frames[i]['yolo_detections'] is None and frame.yolo_detections is not None:
                        merged_frames[i]['yolo_detections'] = frame.yolo_detections
                    if merged_frames[i]['player_x'] is None and frame.player_x is not None:
                        merged_frames[i]['player_x'] = frame.player_x
                        merged_frames[i]['player_y'] = frame.player_y
                        merged_frames[i]['player_velocity_x'] = frame.player_velocity_x
                        merged_frames[i]['player_velocity_y'] = frame.player_velocity_y
                        merged_frames[i]['player_in_air'] = frame.player_in_air

        # Reconstruct frames
        merged_traj_frames = [
            FrameObservation(**frame_dict) for frame_dict in merged_frames
        ]

        # Update metadata
        merged_metadata = TrajectoryMetadata(
            source=DataSource.MIXED,
            source_file="merged",
            level_name=base.metadata.level_name,
            success=base.metadata.success,
            distance_percent=base.metadata.distance_percent,
            time_seconds=base.metadata.time_seconds,
            frames_completed=len(merged_traj_frames),
            expert_quality=max(t.metadata.expert_quality for t in trajectories),
            diversity_score=sum(t.metadata.diversity_score for t in trajectories) / len(trajectories),
        )

        return UnifiedTrajectory(frames=merged_traj_frames, metadata=merged_metadata)
