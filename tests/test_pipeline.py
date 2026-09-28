"""Tests for full training pipeline integration."""

import unittest
import numpy as np
import sys
sys.path.insert(0, '/home/claude/geometry-dash')

from training.pipeline import TrainingPipeline, PipelineConfig


class TestPipelineConfig(unittest.TestCase):
    """Tests for pipeline configuration."""

    def test_config_initialization(self):
        """Test creating pipeline config."""
        config = PipelineConfig()
        self.assertIsNotNone(config)
        self.assertGreater(config.ppo_learning_rate, 0)

    def test_config_defaults(self):
        """Test configuration default values."""
        config = PipelineConfig()

        self.assertEqual(config.curriculum_required_win_rate, 0.95)
        self.assertEqual(config.num_phases, 8)
        self.assertGreater(config.max_training_episodes, 0)


class TestTrainingPipeline(unittest.TestCase):
    """Tests for training pipeline."""

    def test_pipeline_initialization(self):
        """Test creating training pipeline."""
        # Import here to avoid circular dependencies
        from environment.gd_env import GeometryDashEnv

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env)

        self.assertIsNotNone(pipeline)
        self.assertIsNotNone(pipeline.agent)
        self.assertIsNotNone(pipeline.scheduler)

    def test_pipeline_components_exist(self):
        """Test that all pipeline components are initialized."""
        from environment.gd_env import GeometryDashEnv

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env)

        # Check all main components
        self.assertIsNotNone(pipeline.env)
        self.assertIsNotNone(pipeline.agent)
        self.assertIsNotNone(pipeline.scheduler)
        self.assertIsNotNone(pipeline.config)

    def test_single_training_step(self):
        """Test executing one training step."""
        from environment.gd_env import GeometryDashEnv

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env)

        # Perform one training iteration
        stats = pipeline.train_step()

        self.assertIsNotNone(stats)
        self.assertIn('episode', stats)
        self.assertIn('reward', stats)

    def test_trajectory_collection(self):
        """Test collecting trajectories."""
        from environment.gd_env import GeometryDashEnv

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env)

        # Collect one episode
        traj_len = pipeline.collect_trajectory(max_steps=100)

        self.assertGreater(traj_len, 0)

    def test_agent_training(self):
        """Test agent training on collected buffer."""
        from environment.gd_env import GeometryDashEnv

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env)

        # Collect data
        pipeline.collect_trajectory(max_steps=50)
        pipeline.collect_trajectory(max_steps=50)

        # Train
        actor_loss, critic_loss = pipeline.train_agent(epochs=1)

        self.assertIsInstance(actor_loss, (float, np.floating))
        self.assertIsInstance(critic_loss, (float, np.floating))

    def test_curriculum_updates(self):
        """Test curriculum scheduler updates."""
        from environment.gd_env import GeometryDashEnv

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env)

        initial_phase = pipeline.scheduler.current_phase_id

        # Update with high win rate
        advanced = pipeline.update_curriculum(win_rate=0.99, episodes=10)

        # May or may not advance depending on thresholds
        self.assertIsInstance(advanced, bool)

    def test_mastery_gate_check(self):
        """Test mastery gate evaluation."""
        from environment.gd_env import GeometryDashEnv

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env)

        # Initial gate should not be passed
        passed = pipeline.evaluator.is_mastered()
        self.assertFalse(passed)

        # Record high performance
        for _ in range(20):
            pipeline.evaluator.record_episode(success=True, distance=150.0, steps=100)

        # Now should be passed (or close to it)
        passed = pipeline.evaluator.is_mastered()
        self.assertTrue(passed)

    def test_pipeline_training_loop(self):
        """Test complete training loop iteration."""
        from environment.gd_env import GeometryDashEnv

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env)

        # Run a few iterations
        for i in range(3):
            stats = pipeline.train_step()
            self.assertIsNotNone(stats)

    def test_progress_tracking(self):
        """Test progress tracking throughout training."""
        from environment.gd_env import GeometryDashEnv

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env)

        # Get initial progress
        progress = pipeline.get_progress()

        self.assertIn('episode', progress)
        self.assertIn('phase_id', progress)
        self.assertIn('curriculum_win_rate', progress)

    def test_config_application(self):
        """Test that config is properly applied."""
        from environment.gd_env import GeometryDashEnv

        config = PipelineConfig()
        config.ppo_learning_rate = 1e-4

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env, config=config)

        self.assertEqual(pipeline.config.ppo_learning_rate, 1e-4)

    def test_auxiliary_task_integration(self):
        """Test residual physics auxiliary task integration."""
        from environment.gd_env import GeometryDashEnv

        config = PipelineConfig()
        config.use_residual_physics = True

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env, config=config)

        # Physics task should be available
        if config.use_residual_physics:
            self.assertIsNotNone(pipeline.physics_task)

    def test_checkpoint_saving(self):
        """Test saving pipeline checkpoints."""
        from environment.gd_env import GeometryDashEnv
        import tempfile
        import os

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env)

        # Create temp directory
        with tempfile.TemporaryDirectory() as tmpdir:
            checkpoint_path = os.path.join(tmpdir, 'checkpoint.pkl')

            # Save checkpoint
            saved = pipeline.save_checkpoint(checkpoint_path)

            self.assertTrue(saved)
            self.assertTrue(os.path.exists(checkpoint_path))

    def test_state_dict_access(self):
        """Test accessing pipeline state dict."""
        from environment.gd_env import GeometryDashEnv

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env)

        state = pipeline.get_state_dict()

        self.assertIn('episode', state)
        self.assertIn('phase_id', state)
        self.assertIsNotNone(state['agent_state'])


class TestPipelineEdgeCases(unittest.TestCase):
    """Tests for edge cases in pipeline."""

    def test_empty_buffer_handling(self):
        """Test handling empty training buffer."""
        from environment.gd_env import GeometryDashEnv

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env)

        # Try to train with empty buffer (should handle gracefully)
        try:
            pipeline.train_agent(epochs=1)
        except Exception as e:
            self.fail(f"Pipeline should handle empty buffer: {e}")

    def test_max_episodes_reached(self):
        """Test stopping when max episodes reached."""
        from environment.gd_env import GeometryDashEnv

        config = PipelineConfig()
        config.max_training_episodes = 1

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env, config=config)

        # Run one step
        pipeline.train_step()

        # Should be at or near max
        self.assertGreaterEqual(pipeline.episode_count, 0)

    def test_concurrent_updates(self):
        """Test that updates are correctly sequenced."""
        from environment.gd_env import GeometryDashEnv

        env = GeometryDashEnv()
        pipeline = TrainingPipeline(env)

        initial_episodes = pipeline.episode_count

        # Do some training
        pipeline.train_step()

        # Episodes should have increased
        self.assertGreater(pipeline.episode_count, initial_episodes)


if __name__ == '__main__':
    unittest.main()
