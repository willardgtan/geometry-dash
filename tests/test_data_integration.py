"""Tests for unified data layer integration.

Verifies that gdsolver, GeometryDashAgent, yusp48, and game-bot
data can be loaded and merged into unified trajectories.
"""

import unittest
from pathlib import Path
import numpy as np
import tempfile
import json

from data.unified_trajectory import (
    UnifiedTrajectory,
    TrajectoryMetadata,
    FrameObservation,
    DataSource,
    ObservationType,
)
from data.loaders import (
    GDSolverLoader,
    GeometryDashAgentLoader,
    LevelMetadataLoader,
    HybridLoader,
)
from data.curriculum_builder import CurriculumBuilder, DifficultyMetric
from data.behavioral_cloning_dataset import BehavioralCloningDataset


class TestUnifiedTrajectory(unittest.TestCase):
    """Test UnifiedTrajectory schema."""

    def test_create_trajectory(self):
        """Test creating a trajectory."""
        frames = [
            FrameObservation(
                frame_idx=i,
                timestamp_ms=i * (1000.0 / 240.0),
                input_value=i % 2,
                observation_type=ObservationType.OCCUPANCY_GRID,
                data_sources_present=[DataSource.GDSOLVER],
            )
            for i in range(100)
        ]

        metadata = TrajectoryMetadata(
            source=DataSource.GDSOLVER,
            source_file="test.txt",
            level_name="Stereo Madness",
            success=True,
            distance_percent=1.0,
            time_seconds=100.0 / 240.0,
            frames_completed=100,
            expert_quality=1.0,
            diversity_score=0.0,
        )

        trajectory = UnifiedTrajectory(frames=frames, metadata=metadata)

        self.assertEqual(len(trajectory), 100)
        self.assertEqual(trajectory[0].input_value, 0)
        self.assertEqual(trajectory[50].input_value, 0)

    def test_get_observation_slice(self):
        """Test slicing observations."""
        frames = [
            FrameObservation(
                frame_idx=i,
                timestamp_ms=i * (1000.0 / 240.0),
                input_value=0,
                occupancy_grid=np.ones((24, 16, 4), dtype=np.float32) * i,
                observation_type=ObservationType.OCCUPANCY_GRID,
                data_sources_present=[DataSource.GDSOLVER],
            )
            for i in range(50)
        ]

        metadata = TrajectoryMetadata(
            source=DataSource.GDSOLVER,
            source_file="test.txt",
            level_name="Test",
            success=True,
            distance_percent=1.0,
            time_seconds=50.0 / 240.0,
            frames_completed=50,
            expert_quality=1.0,
            diversity_score=0.0,
        )

        trajectory = UnifiedTrajectory(frames=frames, metadata=metadata)

        obs = trajectory.get_observation_slice(0, 10, ObservationType.OCCUPANCY_GRID)

        self.assertEqual(obs.shape, (10, 24, 16, 4))
        self.assertTrue(np.allclose(obs[0], 0.0))
        self.assertTrue(np.allclose(obs[9], 9.0))

    def test_get_input_sequence(self):
        """Test extracting input decisions."""
        inputs = [0, 1, 1, 0, 1, 0, 0, 1]
        frames = [
            FrameObservation(
                frame_idx=i,
                timestamp_ms=i * (1000.0 / 240.0),
                input_value=inputs[i],
                observation_type=ObservationType.OCCUPANCY_GRID,
                data_sources_present=[DataSource.GDSOLVER],
            )
            for i in range(len(inputs))
        ]

        metadata = TrajectoryMetadata(
            source=DataSource.GDSOLVER,
            source_file="test.txt",
            level_name="Test",
            success=True,
            distance_percent=1.0,
            time_seconds=len(inputs) / 240.0,
            frames_completed=len(inputs),
            expert_quality=1.0,
            diversity_score=0.0,
        )

        trajectory = UnifiedTrajectory(frames=frames, metadata=metadata)

        seq = trajectory.get_input_sequence(0, len(inputs))

        self.assertTrue(np.array_equal(seq, np.array(inputs)))


class TestGDSolverLoader(unittest.TestCase):
    """Test loading gdsolver trajectories."""

    def test_load_gdsolver_trajectory(self):
        """Test loading a gdsolver trajectory file."""
        # Create temporary trajectory file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("input=0,0\n")
            f.write("input=60,1\n")
            f.write("input=120,0\n")
            f.write("input=180,1\n")
            temp_path = f.name

        try:
            trajectory = GDSolverLoader.load(temp_path, "Test Level")

            # Should have frames from 0 to 180 (inclusive)
            self.assertGreaterEqual(len(trajectory), 180)
            self.assertEqual(trajectory.metadata.source, DataSource.GDSOLVER)
            self.assertEqual(trajectory.metadata.success, True)
            self.assertEqual(trajectory.metadata.expert_quality, 1.0)
        finally:
            Path(temp_path).unlink()

    def test_gdsolver_input_values(self):
        """Test that gdsolver inputs are correctly parsed."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("input=0,0\n")
            f.write("input=50,1\n")
            f.write("input=100,0\n")
            temp_path = f.name

        try:
            trajectory = GDSolverLoader.load(temp_path, "Test")

            # Check specific frame inputs
            self.assertEqual(trajectory[0].input_value, 0)
            self.assertEqual(trajectory[50].input_value, 1)
            self.assertEqual(trajectory[99].input_value, 1)  # Should still be 1
            self.assertEqual(trajectory[100].input_value, 0)
        finally:
            Path(temp_path).unlink()


class TestCurriculumBuilder(unittest.TestCase):
    """Test curriculum building from data."""

    def test_build_curriculum(self):
        """Test building curriculum from level metadata."""
        builder = CurriculumBuilder()

        # Add some level metadata
        levels = [
            ("Easy 1", {'stars': 1, 'downloads': 1000, 'likes': 100}),
            ("Easy 2", {'stars': 2, 'downloads': 900, 'likes': 90}),
            ("Medium 1", {'stars': 10, 'downloads': 500, 'likes': 50}),
            ("Hard 1", {'stars': 20, 'downloads': 100, 'likes': 10}),
        ]

        for level_name, metadata in levels:
            builder.add_level_metadata(level_name, metadata)
            builder.add_gdsolver_result(level_name, True)

        # Build curriculum
        clusters = builder.build_clusters(metric=DifficultyMetric.STARS)

        # Should create multiple clusters
        self.assertGreater(len(clusters), 1)

        # Clusters should be sorted by difficulty
        for i in range(len(clusters) - 1):
            self.assertLess(
                clusters[i].mean_difficulty,
                clusters[i + 1].mean_difficulty
            )

    def test_curriculum_summary(self):
        """Test curriculum summary generation."""
        builder = CurriculumBuilder()

        builder.add_level_metadata("Easy", {'stars': 1})
        builder.add_level_metadata("Hard", {'stars': 20})

        builder.build_clusters()

        summary = builder.summary()

        self.assertIn("Curriculum", summary)
        self.assertIn("Cluster", summary)


class TestBehavioralCloningDataset(unittest.TestCase):
    """Test behavioral cloning dataset."""

    def test_create_bc_dataset(self):
        """Test creating BC dataset."""
        dataset = BehavioralCloningDataset()

        # Create a simple trajectory
        frames = [
            FrameObservation(
                frame_idx=i,
                timestamp_ms=i * (1000.0 / 240.0),
                input_value=i % 2,
                occupancy_grid=np.ones((24, 16, 4), dtype=np.float32),
                observation_type=ObservationType.OCCUPANCY_GRID,
                data_sources_present=[DataSource.GDSOLVER],
            )
            for i in range(100)
        ]

        metadata = TrajectoryMetadata(
            source=DataSource.GDSOLVER,
            source_file="test.txt",
            level_name="Test",
            success=True,
            distance_percent=1.0,
            time_seconds=100.0 / 240.0,
            frames_completed=100,
            expert_quality=1.0,
            diversity_score=0.0,
        )

        trajectory = UnifiedTrajectory(frames=frames, metadata=metadata)

        # Add to dataset
        traj_id = dataset.add_trajectory(trajectory)

        self.assertEqual(traj_id, 0)
        self.assertGreater(len(dataset), 0)

    def test_bc_batch_sampling(self):
        """Test sampling batches from BC dataset."""
        dataset = BehavioralCloningDataset()

        # Create trajectory
        frames = [
            FrameObservation(
                frame_idx=i,
                timestamp_ms=i * (1000.0 / 240.0),
                input_value=i % 2,
                occupancy_grid=np.ones((24, 16, 4), dtype=np.float32) * i,
                observation_type=ObservationType.OCCUPANCY_GRID,
                data_sources_present=[DataSource.GDSOLVER],
            )
            for i in range(100)
        ]

        metadata = TrajectoryMetadata(
            source=DataSource.GDSOLVER,
            source_file="test.txt",
            level_name="Test",
            success=True,
            distance_percent=1.0,
            time_seconds=100.0 / 240.0,
            frames_completed=100,
            expert_quality=1.0,
            diversity_score=0.0,
        )

        trajectory = UnifiedTrajectory(frames=frames, metadata=metadata)
        dataset.add_trajectory(trajectory)

        # Sample batch
        obs, actions, confidences = dataset.get_batch(batch_size=32)

        self.assertEqual(len(obs), 32)
        self.assertEqual(len(actions), 32)
        self.assertEqual(len(confidences), 32)
        self.assertEqual(obs.dtype, np.float32)
        self.assertEqual(actions.dtype, np.int32)

    def test_bc_epoch_iterator(self):
        """Test iterating through dataset epochs."""
        dataset = BehavioralCloningDataset()

        # Create trajectory
        frames = [
            FrameObservation(
                frame_idx=i,
                timestamp_ms=i * (1000.0 / 240.0),
                input_value=0,
                occupancy_grid=np.ones((24, 16, 4), dtype=np.float32),
                observation_type=ObservationType.OCCUPANCY_GRID,
                data_sources_present=[DataSource.GDSOLVER],
            )
            for i in range(100)
        ]

        metadata = TrajectoryMetadata(
            source=DataSource.GDSOLVER,
            source_file="test.txt",
            level_name="Test",
            success=True,
            distance_percent=1.0,
            time_seconds=100.0 / 240.0,
            frames_completed=100,
            expert_quality=1.0,
            diversity_score=0.0,
        )

        trajectory = UnifiedTrajectory(frames=frames, metadata=metadata)
        dataset.add_trajectory(trajectory)

        # Iterate one epoch
        total_samples = 0
        for obs, actions, confidences in dataset.get_epoch_iterator(batch_size=16):
            total_samples += len(obs)

        # Should process roughly the dataset size
        self.assertGreater(total_samples, 0)


class TestHybridLoader(unittest.TestCase):
    """Test merging multiple data sources."""

    def test_merge_trajectories(self):
        """Test merging two trajectories."""
        # Create gdsolver trajectory (input only)
        gdsolver_frames = [
            FrameObservation(
                frame_idx=i,
                timestamp_ms=i * (1000.0 / 240.0),
                input_value=i % 2,
                observation_type=ObservationType.OCCUPANCY_GRID,
                data_sources_present=[DataSource.GDSOLVER],
            )
            for i in range(100)
        ]

        gdsolver_meta = TrajectoryMetadata(
            source=DataSource.GDSOLVER,
            source_file="gdsolver.txt",
            level_name="Test",
            success=True,
            distance_percent=1.0,
            time_seconds=100.0 / 240.0,
            frames_completed=100,
            expert_quality=1.0,
            diversity_score=0.0,
        )

        gdsolver_traj = UnifiedTrajectory(frames=gdsolver_frames, metadata=gdsolver_meta)

        # Create game-bot trajectory (occupancy grid only)
        gamebot_frames = [
            FrameObservation(
                frame_idx=i,
                timestamp_ms=i * (1000.0 / 240.0),
                input_value=0,
                occupancy_grid=np.ones((24, 16, 4), dtype=np.float32) * i,
                observation_type=ObservationType.OCCUPANCY_GRID,
                data_sources_present=[DataSource.GAME_BOT],
            )
            for i in range(100)
        ]

        gamebot_meta = TrajectoryMetadata(
            source=DataSource.GAME_BOT,
            source_file="gamebot/",
            level_name="Test",
            success=True,
            distance_percent=1.0,
            time_seconds=100.0 / 240.0,
            frames_completed=100,
            expert_quality=0.5,
            diversity_score=0.5,
        )

        gamebot_traj = UnifiedTrajectory(frames=gamebot_frames, metadata=gamebot_meta)

        # Merge
        merged = HybridLoader.merge([gdsolver_traj, gamebot_traj])

        self.assertEqual(merged.metadata.source, DataSource.MIXED)
        self.assertEqual(len(merged), 100)

        # Merged should have both inputs and occupancy grids
        self.assertIsNotNone(merged[0].input_value)
        self.assertIsNotNone(merged[0].occupancy_grid)


class TestLevelMetadataLoader(unittest.TestCase):
    """Test level metadata loading from various sources."""

    def test_hardcoded_official_metadata(self):
        """Test hardcoded official campaign metadata."""
        from data.level_metadata_loader import HardcodedOfficialMetadata

        metadata = HardcodedOfficialMetadata.get_official_campaign()

        # Should have 20 core official campaign levels
        self.assertEqual(len(metadata), 20)

        # Check a few specific levels
        self.assertIn("Stereo Madness", metadata)
        self.assertIn("Deadlocked", metadata)

        # Verify metadata structure
        stereo = metadata["Stereo Madness"]
        self.assertEqual(stereo["id"], 1)
        self.assertEqual(stereo["stars"], 1)
        self.assertGreater(stereo["object_count"], 0)

        deadlocked = metadata["Deadlocked"]
        self.assertEqual(deadlocked["id"], 21)
        self.assertEqual(deadlocked["stars"], 21)  # Deadlocked is 21 stars

    def test_hardcoded_curriculum_integration(self):
        """Test integrating hardcoded metadata into curriculum."""
        from data.level_metadata_loader import HardcodedOfficialMetadata

        metadata = HardcodedOfficialMetadata.get_official_campaign()
        builder = CurriculumBuilder()

        for name, meta in metadata.items():
            builder.add_level_metadata(name, meta)

        # Build curriculum
        clusters = builder.build_clusters()

        # Should have multiple clusters (easy/medium/hard)
        self.assertGreater(len(clusters), 1)

        # Clusters should be sorted by difficulty
        for i in range(len(clusters) - 1):
            self.assertLess(
                clusters[i].mean_difficulty, clusters[i + 1].mean_difficulty
            )


if __name__ == '__main__':
    unittest.main()
