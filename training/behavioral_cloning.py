"""Behavioral cloning: train policy to imitate expert demonstrations."""

import math
from typing import List, Tuple, Optional
from data.transition import Transition, TransitionBatch


class BehavioralCloning:
    """
    Train a policy network to imitate expert demonstrations (gdsolver trajectories).

    This is the pre-training phase before RL. The policy learns to:
    - Input: state vector (20 variables: position, velocity, mode, etc.)
    - Output: binary action (1 = jump/press button, 0 = no jump)

    Cross-entropy loss: -[y*log(p) + (1-y)*log(1-p)]
    where y is the expert action, p is the policy's predicted action probability.
    """

    def __init__(
        self,
        state_dim: int = 20,
        action_dim: int = 2,  # Binary: [no-action, action]
        learning_rate: float = 1e-3,
        batch_size: int = 32,
    ):
        """Initialize behavioral cloning trainer."""
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.learning_rate = learning_rate
        self.batch_size = batch_size

        self.total_loss = 0.0
        self.total_batches = 0
        self.training_history = []

    def extract_action(self, transition: Transition) -> int:
        """
        Extract action label from transition.

        Returns:
            0 if no action (button not pressed)
            1 if action (button pressed/held)
        """
        if transition.input_pressed:
            return 1
        elif transition.input_held:
            return 1
        else:
            return 0

    def extract_state_vector(self, transition: Transition) -> List[float]:
        """
        Extract 20-dimensional state vector from transition.

        State vector (20 dims):
        [x, y, vx, vy, rotation, mode_onehot(7), grounded, contact_type_onehot(5),
         gravity_mod, size_mod, speed_scaling]

        Returns:
            State vector as list of floats
        """
        # Position and velocity (4)
        state = [
            transition.x,
            transition.y,
            transition.vx,
            transition.vy,
        ]

        # Rotation (1)
        state.append(transition.rotation)

        # Game mode one-hot (7)
        mode_idx = list([
            "cube", "ship", "ball", "ufo", "wave", "robot", "spider"
        ]).index(transition.mode.value)
        mode_onehot = [1.0 if i == mode_idx else 0.0 for i in range(7)]
        state.extend(mode_onehot)

        # Grounded flag (1)
        state.append(1.0 if transition.grounded else 0.0)

        # Contact type one-hot (5)
        contact_idx = list([
            "platform", "spike", "orb", "pad", "air"
        ]).index(transition.contact_type.value)
        contact_onehot = [1.0 if i == contact_idx else 0.0 for i in range(5)]
        state.extend(contact_onehot)

        # Game state modifiers (3)
        state.extend([transition.gravity_mod, transition.size_mod, transition.speed_scaling])

        assert len(state) == 20, f"Expected state dim 20, got {len(state)}"
        return state

    def prepare_demonstrations(
        self,
        batches: List[TransitionBatch],
    ) -> Tuple[List[List[float]], List[int]]:
        """
        Prepare demonstrations for training.

        Args:
            batches: List of TransitionBatch objects (e.g., from gdsolver dumps)

        Returns:
            (states, actions) where:
            - states: list of state vectors
            - actions: list of action labels (0 or 1)
        """
        states = []
        actions = []

        for batch in batches:
            for transition in batch.transitions:
                state = self.extract_state_vector(transition)
                action = self.extract_action(transition)

                states.append(state)
                actions.append(action)

        return states, actions

    def train_epoch(
        self,
        states: List[List[float]],
        actions: List[int],
        num_epochs: int = 1,
    ) -> float:
        """
        Train for num_epochs.

        Args:
            states: List of state vectors
            actions: List of action labels
            num_epochs: Number of training epochs

        Returns:
            Average loss over all batches
        """
        total_loss = 0.0
        total_samples = 0

        for epoch in range(num_epochs):
            epoch_loss = 0.0
            epoch_samples = 0

            # Process in batches
            for i in range(0, len(states), self.batch_size):
                batch_states = states[i:i+self.batch_size]
                batch_actions = actions[i:i+self.batch_size]

                # Cross-entropy loss calculation (simplified)
                batch_loss = self._compute_batch_loss(batch_states, batch_actions)

                epoch_loss += batch_loss * len(batch_states)
                epoch_samples += len(batch_states)

            avg_epoch_loss = epoch_loss / epoch_samples if epoch_samples > 0 else 0.0
            self.training_history.append(avg_epoch_loss)

            total_loss += epoch_loss
            total_samples += epoch_samples

        avg_loss = total_loss / total_samples if total_samples > 0 else 0.0
        return avg_loss

    def _compute_batch_loss(
        self,
        batch_states: List[List[float]],
        batch_actions: List[int],
    ) -> float:
        """
        Compute cross-entropy loss for a batch.

        Simplified: assumes policy predicts action probability.
        In practice, would use PyTorch/TensorFlow for actual gradients.
        """
        batch_loss = 0.0
        epsilon = 1e-7  # Prevent log(0)

        for state, action in zip(batch_states, batch_actions):
            # Simplified: predict action from state
            # In practice: p = model(state)
            # For testing, just use a dummy prediction
            p = 0.5  # Dummy prediction

            # Cross-entropy: -[y*log(p) + (1-y)*log(1-p)]
            if action == 1:
                loss = -math.log(p + epsilon)
            else:
                loss = -math.log(1 - p + epsilon)

            batch_loss += loss

        return batch_loss / len(batch_states)

    def info(self):
        """Print training info."""
        print(f"BehavioralCloning:")
        print(f"  State dim: {self.state_dim}")
        print(f"  Action dim: {self.action_dim}")
        print(f"  Learning rate: {self.learning_rate}")
        print(f"  Batch size: {self.batch_size}")
        if self.training_history:
            print(f"  Training history: {len(self.training_history)} epochs")
            print(f"  Latest loss: {self.training_history[-1]:.4f}")
