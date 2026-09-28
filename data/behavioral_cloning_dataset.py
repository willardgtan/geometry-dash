"""Behavioral cloning dataset combining gdsolver, GeometryDashAgent, and game-bot.

Creates supervised learning dataset for offline behavioral cloning pre-training.
Ingests trajectories from multiple sources and provides sampling with weighting.
"""

from typing import List, Dict, Tuple, Optional, Iterator
import numpy as np
from dataclasses import dataclass

from .unified_trajectory import (
    UnifiedTrajectory,
    DataSource,
    ObservationType,
)


@dataclass
class BCTransition:
    """Single behavioral cloning transition (observation → action)."""

    observation: np.ndarray  # Input observation (24×16×4 grid or other)
    action: int  # 0 or 1 (no jump / jump)
    expert_source: DataSource  # Where this data came from
    confidence: float  # How confident is this label? (0.0-1.0)
    trajectory_id: int  # Which trajectory this came from


class BehavioralCloningDataset:
    """Dataset for offline behavioral cloning with multiple sources.

    Features:
    - Combines gdsolver (deterministic), GeometryDashAgent (expert),
      and game-bot (measured)
    - Provides confidence weighting per transition
    - Supports curriculum sampling (easy → hard)
    """

    def __init__(
        self,
        observation_type: ObservationType = ObservationType.OCCUPANCY_GRID,
        window_size: int = 1,
    ):
        """Initialize BC dataset.

        Args:
            observation_type: Which observation to use (grid, YOLO, kinematic, etc.)
            window_size: How many frames to stack (1 = single frame, 4 = 4 frames)
        """
        self.observation_type = observation_type
        self.window_size = window_size

        self.transitions: List[BCTransition] = []
        self.trajectories: List[UnifiedTrajectory] = []

        # Metadata for curriculum sampling
        self.trajectory_difficulties: List[float] = []  # One per trajectory
        self.source_counts: Dict[DataSource, int] = {}

    def add_trajectory(
        self,
        trajectory: UnifiedTrajectory,
        difficulty: Optional[float] = None
    ) -> int:
        """Add trajectory to dataset.

        Args:
            trajectory: UnifiedTrajectory to add
            difficulty: Difficulty estimate (0.0-1.0), auto-computed if None

        Returns:
            Trajectory ID
        """
        traj_id = len(self.trajectories)
        self.trajectories.append(trajectory)

        # Auto-compute difficulty from metadata
        if difficulty is None:
            stars = trajectory.metadata.difficulty_stars or 1
            difficulty = min(stars / 22.0, 1.0)

        self.trajectory_difficulties.append(difficulty)

        # Extract transitions from trajectory
        for frame_idx in range(len(trajectory) - self.window_size):
            # Get observation(s)
            obs_slice = trajectory.get_observation_slice(
                frame_idx,
                frame_idx + self.window_size,
                self.observation_type
            )

            # Stack frames if window_size > 1
            if self.window_size > 1:
                obs = obs_slice.reshape(obs_slice.shape[0], -1)  # Flatten spatial dims
                obs = obs.reshape(-1)  # Flatten time and space
            else:
                obs = obs_slice[0]

            # Get action
            action = trajectory.frames[frame_idx].input_value

            # Compute confidence
            confidence = self._compute_confidence(trajectory, frame_idx)

            # Create transition
            transition = BCTransition(
                observation=obs,
                action=action,
                expert_source=trajectory.metadata.source,
                confidence=confidence,
                trajectory_id=traj_id,
            )

            self.transitions.append(transition)

        # Update source counts
        source = trajectory.metadata.source
        self.source_counts[source] = self.source_counts.get(source, 0) + 1

        return traj_id

    def _compute_confidence(
        self,
        trajectory: UnifiedTrajectory,
        frame_idx: int
    ) -> float:
        """Compute confidence score for a transition.

        Args:
            trajectory: Trajectory containing this frame
            frame_idx: Frame index

        Returns:
            Confidence score (0.0-1.0)
        """
        source = trajectory.metadata.source
        base_confidence = trajectory.metadata.expert_quality

        # Adjust based on source
        if source == DataSource.GDSOLVER:
            # TAS solutions: full confidence
            return 1.0

        elif source == DataSource.GEOMETRY_DASH_AGENT:
            # Expert frames: high confidence but less than TAS
            return 0.9 * base_confidence

        elif source == DataSource.GAME_BOT:
            # Measured data: medium confidence
            return 0.6 * base_confidence

        elif source == DataSource.HUMAN_DEMO:
            # Human demonstrations: expert quality dependent
            return 0.8 * base_confidence

        else:
            return base_confidence

    def get_batch(
        self,
        batch_size: int = 32,
        curriculum_phase: Optional[float] = None,
        weighted: bool = True,
        random_state: Optional[np.random.RandomState] = None
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Sample a batch with optional curriculum weighting.

        Args:
            batch_size: Batch size
            curriculum_phase: If set (0.0-1.0), sample from trajectories
                             up to this difficulty
            weighted: Use confidence weighting
            random_state: RNG for reproducibility

        Returns:
            (observations, actions, confidences) all as numpy arrays
        """
        if random_state is None:
            random_state = np.random.RandomState()

        # Determine valid trajectories
        valid_indices = np.arange(len(self.transitions))

        if curriculum_phase is not None:
            # Only sample from trajectories up to this difficulty
            valid_mask = []
            for trans in self.transitions:
                traj_diff = self.trajectory_difficulties[trans.trajectory_id]
                valid_mask.append(traj_diff <= curriculum_phase)
            valid_indices = np.where(valid_mask)[0]

        if len(valid_indices) == 0:
            raise ValueError("No valid transitions for this curriculum phase")

        # Compute sampling weights
        if weighted:
            weights = np.array([
                self.transitions[i].confidence for i in valid_indices
            ])
            weights = weights / weights.sum()
        else:
            weights = np.ones(len(valid_indices)) / len(valid_indices)

        # Sample transitions
        sample_indices = random_state.choice(
            valid_indices,
            size=batch_size,
            p=weights,
            replace=True
        )

        # Collect batch
        observations = []
        actions = []
        confidences = []

        for idx in sample_indices:
            trans = self.transitions[idx]
            observations.append(trans.observation)
            actions.append(trans.action)
            confidences.append(trans.confidence)

        return (
            np.array(observations, dtype=np.float32),
            np.array(actions, dtype=np.int32),
            np.array(confidences, dtype=np.float32),
        )

    def get_epoch_iterator(
        self,
        batch_size: int = 32,
        curriculum_phase: Optional[float] = None,
        weighted: bool = True,
        shuffle: bool = True,
        random_state: Optional[np.random.RandomState] = None
    ) -> Iterator[Tuple[np.ndarray, np.ndarray, np.ndarray]]:
        """Iterate through entire dataset one epoch.

        Args:
            batch_size: Batch size
            curriculum_phase: Difficulty cutoff (0.0-1.0)
            weighted: Use confidence weighting
            shuffle: Shuffle transitions before batching
            random_state: RNG for reproducibility

        Yields:
            (observations, actions, confidences) batches
        """
        if random_state is None:
            random_state = np.random.RandomState()

        # Determine valid transitions
        valid_indices = np.arange(len(self.transitions))

        if curriculum_phase is not None:
            valid_mask = []
            for trans in self.transitions:
                traj_diff = self.trajectory_difficulties[trans.trajectory_id]
                valid_mask.append(traj_diff <= curriculum_phase)
            valid_indices = np.where(valid_mask)[0]

        # Shuffle if requested
        if shuffle:
            random_state.shuffle(valid_indices)

        # Batch iteration
        for start_idx in range(0, len(valid_indices), batch_size):
            end_idx = min(start_idx + batch_size, len(valid_indices))
            batch_indices = valid_indices[start_idx:end_idx]

            observations = []
            actions = []
            confidences = []

            for idx in batch_indices:
                trans = self.transitions[idx]
                observations.append(trans.observation)
                actions.append(trans.action)
                confidences.append(trans.confidence)

            yield (
                np.array(observations, dtype=np.float32),
                np.array(actions, dtype=np.int32),
                np.array(confidences, dtype=np.float32),
            )

    def summary(self) -> str:
        """Get human-readable dataset summary.

        Returns:
            Formatted string with dataset statistics
        """
        lines = [
            "=== Behavioral Cloning Dataset ===",
            f"Total Trajectories: {len(self.trajectories)}",
            f"Total Transitions: {len(self.transitions)}",
            "",
            "Source Breakdown:",
        ]

        for source, count in sorted(self.source_counts.items(), key=lambda x: -x[1]):
            pct = 100.0 * count / len(self.trajectories)
            lines.append(f"  {source.value}: {count} ({pct:.1f}%)")

        lines.extend([
            "",
            "Difficulty Distribution:",
            f"  Easy (0-0.33): {sum(1 for d in self.trajectory_difficulties if d < 0.33)}",
            f"  Medium (0.33-0.66): {sum(1 for d in self.trajectory_difficulties if 0.33 <= d < 0.66)}",
            f"  Hard (0.66-1.0): {sum(1 for d in self.trajectory_difficulties if d >= 0.66)}",
        ])

        return "\n".join(lines)

    def __len__(self) -> int:
        """Total number of transitions."""
        return len(self.transitions)

    def __getitem__(self, idx: int) -> BCTransition:
        """Get single transition by index."""
        return self.transitions[idx]
