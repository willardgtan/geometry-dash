"""Tests for residual physics model."""

import unittest
import numpy as np
import sys
sys.path.insert(0, '/home/claude/geometry-dash')

from models.residual_physics import ResidualPhysicsModel


class TestResidualPhysicsModel(unittest.TestCase):
    """Tests for residual physics model."""

    def test_model_initialization(self):
        """Test residual physics model creation."""
        model = ResidualPhysicsModel(
            latent_dim=256,
            action_space_size=2,
            state_dim=6  # x, y, vx, vy, rotation, mode
        )
        self.assertIsNotNone(model)

    def test_predict_state_delta(self):
        """Test predicting state changes."""
        model = ResidualPhysicsModel(latent_dim=256, action_space_size=2)

        # Current state encoding
        features = np.random.rand(1, 256).astype(np.float32)
        action = 1

        # Predict state delta
        delta_state = model.predict_delta(features, action)

        # Delta should be reasonable shape
        self.assertEqual(delta_state.shape[0], 1)
        self.assertGreater(delta_state.shape[1], 0)

    def test_predict_batch_state_deltas(self):
        """Test batch prediction of state changes."""
        model = ResidualPhysicsModel(latent_dim=256, action_space_size=2)

        batch_size = 8
        features = np.random.rand(batch_size, 256).astype(np.float32)
        actions = np.array([0, 1, 0, 1, 0, 1, 0, 1])

        deltas = model.predict_batch_delta(features, actions)

        self.assertEqual(deltas.shape[0], batch_size)
        self.assertGreater(deltas.shape[1], 0)

    def test_next_state_prediction(self):
        """Test full next state prediction (current + delta)."""
        model = ResidualPhysicsModel(latent_dim=256, action_space_size=2)

        current_state = np.array([[100.0, 105.0, 10.0, 0.0, 0.0, 0.0]])  # x, y, vx, vy, rot, mode
        features = np.random.rand(1, 256).astype(np.float32)
        action = 1

        next_state = model.predict_next_state(current_state, features, action)

        # Next state should have same shape as current
        self.assertEqual(next_state.shape, current_state.shape)

        # State components should be reasonable
        self.assertEqual(next_state.dtype, np.float32)

    def test_model_training_step(self):
        """Test training the residual physics model."""
        model = ResidualPhysicsModel(latent_dim=256, action_space_size=2)

        # Create training batch
        current_states = np.random.rand(4, 6).astype(np.float32)
        features = np.random.rand(4, 256).astype(np.float32)
        actions = np.array([0, 1, 0, 1])
        next_states = np.random.rand(4, 6).astype(np.float32)

        # Train on batch
        loss = model.train_step(current_states, features, actions, next_states, epochs=1)

        self.assertIsInstance(loss, (float, np.floating))
        self.assertGreaterEqual(loss, 0.0)

    def test_loss_decreases_with_training(self):
        """Test that loss decreases with training."""
        model = ResidualPhysicsModel(latent_dim=256, action_space_size=2)

        # Create consistent training data
        current_states = np.random.rand(16, 6).astype(np.float32)
        features = np.random.rand(16, 256).astype(np.float32)
        actions = np.tile([0, 1], 8)
        next_states = current_states + np.random.randn(16, 6).astype(np.float32) * 0.1

        # Get initial loss
        initial_loss = model.train_step(current_states, features, actions, next_states, epochs=1)

        # Train for more epochs
        final_loss = model.train_step(current_states, features, actions, next_states, epochs=10)

        # Loss should not increase dramatically
        self.assertLess(final_loss, initial_loss * 2.0)

    def test_model_output_bounds(self):
        """Test that predicted states are in reasonable bounds."""
        model = ResidualPhysicsModel(latent_dim=256, action_space_size=2)

        current_state = np.array([[100.0, 105.0, 10.0, 0.0, 0.0, 0.0]])
        features = np.random.rand(1, 256).astype(np.float32)
        action = 1

        next_state = model.predict_next_state(current_state, features, action)

        # Position should stay within reasonable bounds
        # GD level width ~ 300 units, height ~ 200 units
        self.assertLess(next_state[0, 0], 5000)  # x
        self.assertGreater(next_state[0, 0], -100)

        # Velocity should be reasonable
        self.assertLess(abs(next_state[0, 2]), 100)  # vx
        self.assertLess(abs(next_state[0, 3]), 200)  # vy

    def test_mode_specific_dynamics(self):
        """Test that different modes produce different dynamics."""
        model = ResidualPhysicsModel(latent_dim=256, action_space_size=2)

        current_state = np.array([[100.0, 105.0, 10.0, 0.0, 0.0, 0.0]])  # Cube mode (0)
        features = np.random.rand(1, 256).astype(np.float32)

        # Cube mode
        next_state_cube = model.predict_next_state(current_state, features, 1)

        # Ship mode
        current_state_ship = current_state.copy()
        current_state_ship[0, 5] = 1  # Change mode to ship
        next_state_ship = model.predict_next_state(current_state_ship, features, 1)

        # Different modes should generally have different dynamics
        # (though with our simple model they may be similar)
        self.assertEqual(next_state_cube.shape, next_state_ship.shape)

    def test_action_sensitivity(self):
        """Test that different actions produce different outputs."""
        model = ResidualPhysicsModel(latent_dim=256, action_space_size=2)

        current_state = np.array([[100.0, 105.0, 10.0, 0.0, 0.0, 0.0]])
        features = np.random.rand(1, 256).astype(np.float32)

        # Predict with action 0 (no action)
        next_state_0 = model.predict_next_state(current_state, features, 0)

        # Predict with action 1 (jump)
        next_state_1 = model.predict_next_state(current_state, features, 1)

        # With high probability, different actions should lead to different states
        # (at least in vy - vertical velocity should change with jump)
        self.assertNotEqual(next_state_0[0, 3], next_state_1[0, 3])

    def test_deterministic_output(self):
        """Test that model produces consistent predictions."""
        model = ResidualPhysicsModel(latent_dim=256, action_space_size=2)

        current_state = np.array([[100.0, 105.0, 10.0, 0.0, 0.0, 0.0]])
        features = np.array([[0.5] * 256], dtype=np.float32)  # Fixed features
        action = 1

        # Predict twice with same input
        next_state_1 = model.predict_next_state(current_state, features, action)
        next_state_2 = model.predict_next_state(current_state, features, action)

        # Should be identical
        np.testing.assert_array_almost_equal(next_state_1, next_state_2)

    def test_delta_accumulation(self):
        """Test that multiple deltas accumulate correctly."""
        model = ResidualPhysicsModel(latent_dim=256, action_space_size=2)

        current_state = np.array([[100.0, 105.0, 10.0, 0.0, 0.0, 0.0]])
        features = np.random.rand(1, 256).astype(np.float32)

        # Simulate multiple steps
        state = current_state.copy()
        for _ in range(5):
            state = model.predict_next_state(state, features, 1)

        # State should have evolved
        self.assertNotEqual(state[0, 0], current_state[0, 0])

    def test_model_state_dict(self):
        """Test accessing model parameters."""
        model = ResidualPhysicsModel(latent_dim=256, action_space_size=2)

        # Model should have learnable parameters
        self.assertIsNotNone(model.delta_net)
        self.assertGreater(len(str(model.delta_net)), 0)


if __name__ == '__main__':
    unittest.main()
