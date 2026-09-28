"""Tests for PPO (Proximal Policy Optimization) agent."""

import unittest
import numpy as np
import sys
sys.path.insert(0, '/home/claude/geometry-dash')

from models.ppo_agent import PPOAgent, PPOBuffer


class TestPPOBuffer(unittest.TestCase):
    """Tests for PPO experience buffer."""

    def test_buffer_initialization(self):
        """Test buffer creation with default capacity."""
        buffer = PPOBuffer(capacity=256)
        self.assertIsNotNone(buffer)
        self.assertEqual(buffer.capacity, 256)

    def test_buffer_add_transition(self):
        """Test adding transitions to buffer."""
        buffer = PPOBuffer(capacity=256)

        obs = np.random.rand(16, 24, 4).astype(np.float32)
        action = 1
        reward = 1.0
        next_obs = np.random.rand(16, 24, 4).astype(np.float32)
        done = False
        value = 0.5
        log_prob = -0.5

        buffer.add(obs, action, reward, next_obs, done, value, log_prob)

        self.assertEqual(buffer.size, 1)

    def test_buffer_get_batch(self):
        """Test retrieving transitions from buffer."""
        buffer = PPOBuffer(capacity=256)

        for i in range(10):
            obs = np.random.rand(16, 24, 4).astype(np.float32)
            action = i % 2
            reward = float(i)
            next_obs = np.random.rand(16, 24, 4).astype(np.float32)
            done = i == 9
            value = 0.5
            log_prob = -0.5

            buffer.add(obs, action, reward, next_obs, done, value, log_prob)

        self.assertEqual(buffer.size, 10)

        batch = buffer.get_all()
        self.assertEqual(len(batch['observations']), 10)
        self.assertEqual(len(batch['actions']), 10)
        self.assertEqual(len(batch['rewards']), 10)

    def test_buffer_clear(self):
        """Test clearing buffer."""
        buffer = PPOBuffer(capacity=256)

        for i in range(5):
            obs = np.random.rand(16, 24, 4).astype(np.float32)
            buffer.add(obs, 0, 1.0, obs, False, 0.5, -0.5)

        self.assertEqual(buffer.size, 5)
        buffer.clear()
        self.assertEqual(buffer.size, 0)

    def test_buffer_compute_advantages(self):
        """Test advantage computation with gamma=0.99."""
        buffer = PPOBuffer(capacity=256)

        # Simple trajectory: rewards = [1, 2, 3]
        for i in range(3):
            obs = np.random.rand(16, 24, 4).astype(np.float32)
            reward = float(i + 1)
            value = 0.5
            log_prob = -0.1

            buffer.add(obs, 0, reward, obs, False, value, log_prob)

        # Add terminal state
        obs_term = np.random.rand(16, 24, 4).astype(np.float32)
        buffer.add(obs_term, 0, 0.0, obs_term, True, 0.0, -0.1)

        # Compute advantages
        batch = buffer.get_all()
        self.assertIn('advantages', batch)
        self.assertIn('returns', batch)
        self.assertEqual(len(batch['advantages']), 4)
        self.assertEqual(len(batch['returns']), 4)


class TestPPOAgent(unittest.TestCase):
    """Tests for PPO agent."""

    def test_agent_initialization(self):
        """Test agent creation."""
        agent = PPOAgent(
            obs_shape=(16, 24, 4),
            action_space_size=2,
            latent_dim=256,
            learning_rate=3e-4
        )
        self.assertIsNotNone(agent)

    def test_agent_predict_action(self):
        """Test action prediction."""
        agent = PPOAgent(
            obs_shape=(16, 24, 4),
            action_space_size=2,
            latent_dim=256
        )

        obs = np.random.rand(1, 16, 24, 4).astype(np.float32)
        action, log_prob, value = agent.predict(obs)

        # Action should be 0 or 1
        self.assertIn(action, [0, 1])

        # Log prob and value should be scalars
        self.assertIsInstance(log_prob, (float, np.floating))
        self.assertIsInstance(value, (float, np.floating))

    def test_agent_batch_predict(self):
        """Test batch action prediction."""
        agent = PPOAgent(
            obs_shape=(16, 24, 4),
            action_space_size=2,
            latent_dim=256
        )

        obs_batch = np.random.rand(8, 16, 24, 4).astype(np.float32)
        actions, log_probs, values = agent.predict_batch(obs_batch)

        self.assertEqual(actions.shape, (8,))
        self.assertEqual(log_probs.shape, (8,))
        self.assertEqual(values.shape, (8,))

    def test_agent_compute_value(self):
        """Test value estimation."""
        agent = PPOAgent(
            obs_shape=(16, 24, 4),
            action_space_size=2,
            latent_dim=256
        )

        obs = np.random.rand(1, 16, 24, 4).astype(np.float32)
        value = agent.compute_value(obs)

        self.assertEqual(value.shape, (1,))
        self.assertIsInstance(value[0], (float, np.floating))

    def test_agent_update_step(self):
        """Test single gradient update."""
        agent = PPOAgent(
            obs_shape=(16, 24, 4),
            action_space_size=2,
            latent_dim=256,
            learning_rate=1e-3
        )

        # Create dummy batch
        batch = {
            'observations': np.random.rand(4, 16, 24, 4).astype(np.float32),
            'actions': np.array([0, 1, 0, 1]),
            'log_probs_old': np.array([-0.5, -0.6, -0.5, -0.7]),
            'advantages': np.array([1.0, -0.5, 0.8, -0.2]),
            'returns': np.array([2.0, 1.5, 2.5, 1.2])
        }

        # Update should not raise
        actor_loss, critic_loss = agent.update_step(batch, epochs=1)

        self.assertIsInstance(actor_loss, (float, np.floating))
        self.assertIsInstance(critic_loss, (float, np.floating))

    def test_agent_collect_trajectory(self):
        """Test trajectory collection interface."""
        agent = PPOAgent(
            obs_shape=(16, 24, 4),
            action_space_size=2,
            latent_dim=256
        )

        # Simulate environment interaction
        obs = np.random.rand(16, 24, 4).astype(np.float32)
        action, log_prob, value = agent.predict(obs.reshape(1, 16, 24, 4))

        # Should produce consistent outputs
        self.assertIsNotNone(action)
        self.assertIsNotNone(log_prob)
        self.assertIsNotNone(value)


class TestPPOTraining(unittest.TestCase):
    """Tests for PPO training loop."""

    def test_training_loop_initialization(self):
        """Test PPO trainer setup."""
        agent = PPOAgent(
            obs_shape=(16, 24, 4),
            action_space_size=2,
            latent_dim=256
        )

        self.assertIsNotNone(agent.cnn_encoder)
        self.assertIsNotNone(agent.policy_head)
        self.assertIsNotNone(agent.value_head)

    def test_agent_deterministic_mode(self):
        """Test agent can run in deterministic mode."""
        agent = PPOAgent(
            obs_shape=(16, 24, 4),
            action_space_size=2,
            latent_dim=256
        )

        obs = np.random.rand(1, 16, 24, 4).astype(np.float32)

        # Get two predictions
        action1, _, _ = agent.predict(obs, deterministic=True)
        action2, _, _ = agent.predict(obs, deterministic=True)

        # In deterministic mode, same obs should give same action
        self.assertEqual(action1, action2)

    def test_agent_stochastic_mode(self):
        """Test agent can sample actions stochastically."""
        agent = PPOAgent(
            obs_shape=(16, 24, 4),
            action_space_size=2,
            latent_dim=256
        )

        obs = np.random.rand(1, 16, 24, 4).astype(np.float32)

        # Get multiple stochastic predictions
        actions = []
        for _ in range(20):
            action, _, _ = agent.predict(obs, deterministic=False)
            actions.append(action)

        # Should have some variance in stochastic mode (with high probability)
        # Each action is 0 or 1, so at least some should be different
        self.assertGreater(len(set(actions)), 1)


if __name__ == '__main__':
    unittest.main()
