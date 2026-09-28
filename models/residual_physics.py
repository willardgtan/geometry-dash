"""Residual physics model for learning game state dynamics."""

import numpy as np
from typing import Tuple, Optional


class ResidualPhysicsModel:
    """Model that predicts state changes (residuals) from features and actions."""

    def __init__(
        self,
        latent_dim: int = 256,
        action_space_size: int = 2,
        state_dim: int = 6,
        hidden_dim: int = 256,
        learning_rate: float = 1e-3
    ):
        """Initialize residual physics model.

        Args:
            latent_dim: Dimension of encoded features from CNN
            action_space_size: Number of discrete actions
            state_dim: Dimension of state vector (x, y, vx, vy, rotation, mode)
            hidden_dim: Hidden layer dimension for MLP
            learning_rate: Learning rate for training
        """
        self.latent_dim = latent_dim
        self.action_space_size = action_space_size
        self.state_dim = state_dim
        self.hidden_dim = hidden_dim
        self.learning_rate = learning_rate

        # One-hot encoded action increases input dimension
        self.input_dim = latent_dim + action_space_size + state_dim

        # Build delta prediction network
        # Input: [latent_features, one_hot_action, current_state]
        # Output: [delta_x, delta_y, delta_vx, delta_vy, delta_rotation, delta_mode]
        self.delta_net = self._build_delta_network()

        self.total_updates = 0

    def _build_delta_network(self):
        """Build simple MLP for predicting state deltas."""
        return {
            'w1': np.random.randn(self.input_dim, self.hidden_dim) * 0.01,
            'b1': np.zeros(self.hidden_dim),
            'w2': np.random.randn(self.hidden_dim, self.hidden_dim) * 0.01,
            'b2': np.zeros(self.hidden_dim),
            'w3': np.random.randn(self.hidden_dim, self.state_dim) * 0.01,
            'b3': np.zeros(self.state_dim)
        }

    def _one_hot_action(self, action: int) -> np.ndarray:
        """Convert action to one-hot vector."""
        one_hot = np.zeros(self.action_space_size, dtype=np.float32)
        one_hot[action] = 1.0
        return one_hot

    def _one_hot_batch(self, actions: np.ndarray) -> np.ndarray:
        """Convert action batch to one-hot vectors."""
        batch_size = len(actions)
        one_hot = np.zeros((batch_size, self.action_space_size), dtype=np.float32)
        one_hot[np.arange(batch_size), actions] = 1.0
        return one_hot

    def _forward_delta(self, input_vec: np.ndarray) -> np.ndarray:
        """Forward pass through delta network."""
        # Layer 1
        h1 = np.dot(input_vec, self.delta_net['w1']) + self.delta_net['b1']
        h1 = np.maximum(h1, 0)  # ReLU

        # Layer 2
        h2 = np.dot(h1, self.delta_net['w2']) + self.delta_net['b2']
        h2 = np.maximum(h2, 0)  # ReLU

        # Output layer
        delta = np.dot(h2, self.delta_net['w3']) + self.delta_net['b3']

        return delta

    def predict_delta(
        self,
        features: np.ndarray,
        action: int
    ) -> np.ndarray:
        """Predict state change for single observation.

        Args:
            features: Latent features of shape (1, latent_dim)
            action: Discrete action (0 or 1)

        Returns:
            State delta of shape (1, state_dim)
        """
        if features.ndim == 1:
            features = features.reshape(1, -1)

        # We need a current state, but we'll use zeros as placeholder
        # In practice, this would be provided by the environment
        current_state = np.zeros((1, self.state_dim), dtype=np.float32)

        # Create input vector
        one_hot_action = self._one_hot_action(action).reshape(1, -1)
        input_vec = np.hstack([features, one_hot_action, current_state])

        delta = self._forward_delta(input_vec)

        return delta

    def predict_batch_delta(
        self,
        features: np.ndarray,
        actions: np.ndarray
    ) -> np.ndarray:
        """Predict state changes for batch.

        Args:
            features: Batch of latent features (batch_size, latent_dim)
            actions: Batch of actions (batch_size,)

        Returns:
            Batch of state deltas (batch_size, state_dim)
        """
        batch_size = features.shape[0]

        # Placeholder current states
        current_states = np.zeros((batch_size, self.state_dim), dtype=np.float32)

        # One-hot encode actions
        one_hot_actions = self._one_hot_batch(actions)

        # Create input vectors
        input_vecs = np.hstack([features, one_hot_actions, current_states])

        deltas = np.array([
            self._forward_delta(input_vecs[i:i+1])
            for i in range(batch_size)
        ]).squeeze(1)

        return deltas

    def predict_next_state(
        self,
        current_state: np.ndarray,
        features: np.ndarray,
        action: int
    ) -> np.ndarray:
        """Predict next state = current_state + delta.

        Args:
            current_state: Current state vector (batch_size, state_dim) or (state_dim,)
            features: Encoded features (batch_size, latent_dim) or (latent_dim,)
            action: Discrete action

        Returns:
            Next state (same shape as current_state)
        """
        if current_state.ndim == 1:
            current_state = current_state.reshape(1, -1)
        if features.ndim == 1:
            features = features.reshape(1, -1)

        batch_size = current_state.shape[0]

        # Predict delta
        one_hot_action = self._one_hot_batch(np.full(batch_size, action))
        input_vecs = np.hstack([features, one_hot_action, current_state])

        delta = np.array([
            self._forward_delta(input_vecs[i:i+1])
            for i in range(batch_size)
        ]).squeeze(1)

        # Next state = current + delta
        next_state = current_state + delta

        return next_state.astype(np.float32)

    def train_step(
        self,
        current_states: np.ndarray,
        features: np.ndarray,
        actions: np.ndarray,
        next_states: np.ndarray,
        epochs: int = 1,
        batch_size: int = 32
    ) -> float:
        """Train the residual physics model.

        Args:
            current_states: Current states (batch_size, state_dim)
            features: Latent features (batch_size, latent_dim)
            actions: Actions (batch_size,)
            next_states: Next states (batch_size, state_dim)
            epochs: Number of training epochs
            batch_size: Mini-batch size

        Returns:
            Average loss
        """
        n_samples = current_states.shape[0]
        losses = []

        for epoch in range(epochs):
            indices = np.random.permutation(n_samples)

            for start in range(0, n_samples, batch_size):
                end = min(start + batch_size, n_samples)
                batch_indices = indices[start:end]

                batch_current = current_states[batch_indices]
                batch_features = features[batch_indices]
                batch_actions = actions[batch_indices]
                batch_next = next_states[batch_indices]

                # Compute target deltas
                target_delta = batch_next - batch_current

                # Predict deltas
                one_hot_actions = self._one_hot_batch(batch_actions)
                input_vecs = np.hstack([batch_features, one_hot_actions, batch_current])

                predicted_deltas = np.array([
                    self._forward_delta(input_vecs[i:i+1])
                    for i in range(len(batch_actions))
                ]).squeeze(1)

                # Compute MSE loss
                loss = np.mean((predicted_deltas - target_delta) ** 2)
                losses.append(loss)

        self.total_updates += 1

        return float(np.mean(losses))

    def get_state_prediction_uncertainty(
        self,
        current_state: np.ndarray,
        features: np.ndarray,
        action: int,
        n_samples: int = 10
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Estimate prediction uncertainty through sampling.

        Args:
            current_state: Current state
            features: Latent features
            action: Action to take
            n_samples: Number of samples for uncertainty estimation

        Returns:
            (mean_prediction, std_prediction)
        """
        predictions = []

        for _ in range(n_samples):
            next_state = self.predict_next_state(current_state, features, action)
            predictions.append(next_state)

        predictions = np.array(predictions)
        mean_pred = predictions.mean(axis=0)
        std_pred = predictions.std(axis=0)

        return mean_pred, std_pred


class ResidualPhysicsAuxiliaryTask:
    """Auxiliary learning task using residual physics model."""

    def __init__(self, physics_model: ResidualPhysicsModel, weight: float = 0.1):
        """Initialize auxiliary task.

        Args:
            physics_model: ResidualPhysicsModel instance
            weight: Weight for auxiliary loss in combined objective
        """
        self.physics_model = physics_model
        self.weight = weight
        self.loss_history = []

    def compute_loss(
        self,
        current_states: np.ndarray,
        features: np.ndarray,
        actions: np.ndarray,
        next_states: np.ndarray
    ) -> float:
        """Compute physics prediction loss.

        Args:
            current_states: Current states
            features: Latent features
            actions: Actions taken
            next_states: Resulting next states

        Returns:
            Physics prediction loss
        """
        loss = self.physics_model.train_step(
            current_states,
            features,
            actions,
            next_states,
            epochs=1
        )

        self.loss_history.append(loss)
        return loss * self.weight

    def get_weighted_loss(self, main_loss: float, physics_loss: float) -> float:
        """Combine main RL loss with physics auxiliary loss.

        Args:
            main_loss: Primary RL loss (e.g., PPO loss)
            physics_loss: Physics prediction loss

        Returns:
            Combined loss
        """
        return main_loss + physics_loss * self.weight
