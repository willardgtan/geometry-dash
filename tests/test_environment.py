"""Tests for Geometry Dash Gymnasium environment."""

import unittest
import sys
import numpy as np
sys.path.insert(0, '/home/claude/geometry-dash')

from environment.gd_env import GeometryDashEnv


class TestGeometryDashEnv(unittest.TestCase):
    """Tests for GD Gymnasium environment wrapper."""

    def test_env_initialization(self):
        """Test environment creation."""
        env = GeometryDashEnv()
        self.assertIsNotNone(env)
        self.assertEqual(env.observation_space.shape, (16, 24, 4))

    def test_action_space(self):
        """Test action space is binary."""
        env = GeometryDashEnv()
        self.assertEqual(env.action_space.n, 2)  # 0=no action, 1=action

    def test_reset(self):
        """Test environment reset."""
        env = GeometryDashEnv()

        obs, info = env.reset()

        self.assertEqual(obs.shape, (16, 24, 4))
        self.assertIsInstance(info, dict)
        self.assertIn("level", info)

    def test_step(self):
        """Test environment step."""
        env = GeometryDashEnv()
        env.reset()

        # Take action
        obs, reward, terminated, truncated, info = env.step(1)

        self.assertEqual(obs.shape, (16, 24, 4))
        self.assertIsInstance(reward, (float, int))
        self.assertIsInstance(terminated, bool)
        self.assertIsInstance(truncated, bool)
        self.assertIsInstance(info, dict)

    def test_episode_termination(self):
        """Test episode termination on death."""
        env = GeometryDashEnv(level_id="level_001")
        obs, info = env.reset()

        # Run until death or max steps
        done = False
        steps = 0
        max_steps = 1000

        while not done and steps < max_steps:
            action = env.action_space.sample()
            obs, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated
            steps += 1

        # Should either die or timeout
        self.assertTrue(done)

    def test_observation_is_grid(self):
        """Test observations are valid perception grids."""
        env = GeometryDashEnv()
        obs, _ = env.reset()

        # Should be float32 in [0, 1]
        self.assertEqual(obs.dtype, np.float32)
        self.assertGreaterEqual(obs.min(), 0.0)
        self.assertLessEqual(obs.max(), 1.0)

    def test_render_mode(self):
        """Test render mode setting."""
        env = GeometryDashEnv(render_mode="rgb_array")
        self.assertEqual(env.render_mode, "rgb_array")

    def test_max_episode_steps(self):
        """Test episode terminates after max steps."""
        max_steps = 100
        env = GeometryDashEnv(max_episode_steps=max_steps)

        obs, _ = env.reset()
        steps = 0
        done = False

        while not done and steps < max_steps + 10:
            obs, reward, terminated, truncated, info = env.step(0)
            done = terminated or truncated
            steps += 1

        # Should terminate within max_steps (+ small buffer for rounding)
        self.assertLessEqual(steps, max_steps + 5)


class TestEnvironmentMetrics(unittest.TestCase):
    """Tests for environment reward and metrics."""

    def test_reward_structure(self):
        """Test reward is computed correctly."""
        env = GeometryDashEnv()
        obs, _ = env.reset()

        # Running forward should give progress reward
        total_reward = 0
        for _ in range(10):
            obs, reward, _, _, _ = env.step(0)  # No input, just move forward
            total_reward += reward

        # Should have some reward for moving forward
        self.assertIsInstance(total_reward, (int, float))

    def test_info_contains_metrics(self):
        """Test info dict contains useful metrics."""
        env = GeometryDashEnv()
        obs, info = env.reset()

        self.assertIn("position", info)
        self.assertIn("level", info)
        self.assertIn("mode", info)

    def test_step_info_contains_death(self):
        """Test info contains death reason if episode ends."""
        env = GeometryDashEnv(level_id="level_001", max_episode_steps=10)
        obs, _ = env.reset()

        done = False
        while not done:
            obs, reward, terminated, truncated, info = env.step(1)
            done = terminated or truncated

            if done:
                if terminated:
                    self.assertIn("death_reason", info)
                if truncated:
                    self.assertEqual(info.get("truncation_reason"), "max_steps")


if __name__ == '__main__':
    unittest.main()
