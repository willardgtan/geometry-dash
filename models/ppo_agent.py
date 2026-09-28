"""PPO (Proximal Policy Optimization) agent for Geometry Dash RL."""

import numpy as np
from typing import Tuple, Dict, Any, Optional
from models.cnn_encoder import CNNEncoder


class PPOBuffer:
    """Experience buffer for PPO algorithm."""

    def __init__(self, capacity: int = 2048, gamma: float = 0.99, gae_lambda: float = 0.95):
        """Initialize PPO buffer.

        Args:
            capacity: Maximum number of transitions to store
            gamma: Discount factor
            gae_lambda: GAE (Generalized Advantage Estimation) lambda parameter
        """
        self.capacity = capacity
        self.gamma = gamma
        self.gae_lambda = gae_lambda

        self.observations = []
        self.actions = []
        self.rewards = []
        self.next_observations = []
        self.dones = []
        self.values = []
        self.log_probs = []

        self.size = 0

    def add(
        self,
        obs: np.ndarray,
        action: int,
        reward: float,
        next_obs: np.ndarray,
        done: bool,
        value: float,
        log_prob: float
    ) -> None:
        """Add transition to buffer."""
        self.observations.append(obs)
        self.actions.append(action)
        self.rewards.append(reward)
        self.next_observations.append(next_obs)
        self.dones.append(done)
        self.values.append(value)
        self.log_probs.append(log_prob)

        self.size += 1

    def get_all(self) -> Dict[str, np.ndarray]:
        """Get all stored transitions and compute advantages/returns."""
        # Stack observations
        obs_array = np.array(self.observations, dtype=np.float32)
        actions_array = np.array(self.actions, dtype=np.int32)
        rewards_array = np.array(self.rewards, dtype=np.float32)
        dones_array = np.array(self.dones, dtype=bool)
        values_array = np.array(self.values, dtype=np.float32)
        log_probs_array = np.array(self.log_probs, dtype=np.float32)

        # Compute advantages and returns using GAE
        advantages = np.zeros(self.size, dtype=np.float32)
        returns = np.zeros(self.size, dtype=np.float32)

        gae = 0.0
        next_value = 0.0

        for t in reversed(range(self.size)):
            if t == self.size - 1:
                next_value = 0.0 if dones_array[t] else values_array[t]
            else:
                next_value = values_array[t + 1]

            delta = rewards_array[t] + self.gamma * next_value * (1 - dones_array[t]) - values_array[t]
            gae = delta + self.gamma * self.gae_lambda * (1 - dones_array[t]) * gae

            advantages[t] = gae
            returns[t] = gae + values_array[t]

        # Normalize advantages
        advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)

        return {
            'observations': obs_array,
            'actions': actions_array,
            'rewards': rewards_array,
            'log_probs': log_probs_array,
            'advantages': advantages,
            'returns': returns,
            'values': values_array
        }

    def clear(self) -> None:
        """Clear all stored transitions."""
        self.observations = []
        self.actions = []
        self.rewards = []
        self.next_observations = []
        self.dones = []
        self.values = []
        self.log_probs = []

        self.size = 0


class PPOAgent:
    """PPO agent with policy and value networks."""

    def __init__(
        self,
        obs_shape: Tuple[int, int, int] = (16, 24, 4),
        action_space_size: int = 2,
        latent_dim: int = 256,
        learning_rate: float = 3e-4,
        clip_ratio: float = 0.2,
        entropy_coef: float = 0.01,
        value_coef: float = 0.5
    ):
        """Initialize PPO agent.

        Args:
            obs_shape: Shape of observations (H, W, C)
            action_space_size: Number of discrete actions
            latent_dim: Dimension of CNN encoder output
            learning_rate: Learning rate for optimization
            clip_ratio: PPO clip ratio for policy updates
            entropy_coef: Coefficient for entropy regularization
            value_coef: Coefficient for value function loss
        """
        self.obs_shape = obs_shape
        self.action_space_size = action_space_size
        self.latent_dim = latent_dim
        self.learning_rate = learning_rate
        self.clip_ratio = clip_ratio
        self.entropy_coef = entropy_coef
        self.value_coef = value_coef

        # Initialize networks
        self.cnn_encoder = CNNEncoder(
            latent_dim=latent_dim,
            input_channels=obs_shape[2],
            input_height=obs_shape[0],
            input_width=obs_shape[1]
        )

        # Policy head: latent_dim -> action_space_size logits
        self.policy_head = self._build_policy_head(latent_dim, action_space_size)

        # Value head: latent_dim -> 1 (state value)
        self.value_head = self._build_value_head(latent_dim)

        # Optimizer parameters (for gradient tracking)
        self.total_updates = 0

    def _build_policy_head(self, input_dim: int, output_dim: int) -> Dict[str, np.ndarray]:
        """Build simple policy network."""
        return {
            'weights_1': np.random.randn(input_dim, 128) * 0.01,
            'bias_1': np.zeros(128),
            'weights_2': np.random.randn(128, output_dim) * 0.01,
            'bias_2': np.zeros(output_dim)
        }

    def _build_value_head(self, input_dim: int) -> Dict[str, np.ndarray]:
        """Build simple value network."""
        return {
            'weights_1': np.random.randn(input_dim, 64) * 0.01,
            'bias_1': np.zeros(64),
            'weights_2': np.random.randn(64, 1) * 0.01,
            'bias_2': np.zeros(1)
        }

    def _forward_policy(self, features: np.ndarray) -> np.ndarray:
        """Forward pass through policy network."""
        # Simple 2-layer MLP
        hidden = np.dot(features, self.policy_head['weights_1']) + self.policy_head['bias_1']
        hidden = np.maximum(hidden, 0)  # ReLU
        logits = np.dot(hidden, self.policy_head['weights_2']) + self.policy_head['bias_2']
        return logits

    def _forward_value(self, features: np.ndarray) -> np.ndarray:
        """Forward pass through value network."""
        # Simple 2-layer MLP
        hidden = np.dot(features, self.value_head['weights_1']) + self.value_head['bias_1']
        hidden = np.maximum(hidden, 0)  # ReLU
        value = np.dot(hidden, self.value_head['weights_2']) + self.value_head['bias_2']
        return value

    def _softmax(self, logits: np.ndarray) -> np.ndarray:
        """Compute softmax probabilities."""
        exp_logits = np.exp(logits - logits.max(axis=-1, keepdims=True))
        return exp_logits / exp_logits.sum(axis=-1, keepdims=True)

    def predict(
        self,
        obs: np.ndarray,
        deterministic: bool = False
    ) -> Tuple[int, float, float]:
        """Predict action and value for a single observation.

        Args:
            obs: Single observation of shape (1, 16, 24, 4) or (16, 24, 4)
            deterministic: If True, take argmax action; else sample

        Returns:
            action: Discrete action (0 or 1)
            log_prob: Log probability of chosen action
            value: Estimated state value
        """
        # Ensure batch dimension
        if obs.ndim == 3:
            obs = obs.reshape(1, *obs.shape)

        # Encode observation
        features = self.cnn_encoder.encode(obs)  # (1, latent_dim)

        # Get action logits and value
        logits = self._forward_policy(features)  # (1, action_space_size)
        value = self._forward_value(features)[0, 0]  # scalar

        # Compute action probabilities
        probs = self._softmax(logits)[0]  # (action_space_size,)

        if deterministic:
            action = np.argmax(probs)
        else:
            action = np.random.choice(self.action_space_size, p=probs)

        log_prob = float(np.log(probs[action] + 1e-8))

        return int(action), float(log_prob), float(value)

    def predict_batch(
        self,
        obs_batch: np.ndarray,
        deterministic: bool = False
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Predict actions for a batch of observations.

        Args:
            obs_batch: Batch of observations of shape (N, 16, 24, 4)
            deterministic: If True, take argmax actions; else sample

        Returns:
            actions: Array of N actions
            log_probs: Array of N log probabilities
            values: Array of N state values
        """
        batch_size = obs_batch.shape[0]

        # Encode observations
        features = self.cnn_encoder.encode(obs_batch)  # (N, latent_dim)

        # Get action logits and values
        logits = self._forward_policy(features)  # (N, action_space_size)
        values = self._forward_value(features).squeeze(-1)  # (N,)

        # Compute action probabilities
        probs = self._softmax(logits)  # (N, action_space_size)

        actions = np.zeros(batch_size, dtype=np.int32)
        log_probs = np.zeros(batch_size, dtype=np.float32)

        for i in range(batch_size):
            if deterministic:
                action = np.argmax(probs[i])
            else:
                action = np.random.choice(self.action_space_size, p=probs[i])

            actions[i] = action
            log_probs[i] = np.log(probs[i, action] + 1e-8)

        return actions, log_probs, values

    def compute_value(self, obs: np.ndarray) -> np.ndarray:
        """Compute value estimate for observation(s).

        Args:
            obs: Single obs (16, 24, 4) or batch (N, 16, 24, 4)

        Returns:
            values: Value estimate(s)
        """
        if obs.ndim == 3:
            obs = obs.reshape(1, *obs.shape)

        features = self.cnn_encoder.encode(obs)
        values = self._forward_value(features).squeeze(-1)

        return values

    def update_step(
        self,
        batch: Dict[str, np.ndarray],
        epochs: int = 3,
        batch_size: int = 32
    ) -> Tuple[float, float]:
        """Single PPO update step.

        Args:
            batch: Dictionary with 'observations', 'actions', 'log_probs_old', 'advantages', 'returns'
            epochs: Number of training epochs
            batch_size: Mini-batch size for gradient updates

        Returns:
            actor_loss: Average actor loss
            critic_loss: Average critic loss
        """
        obs = batch['observations']
        actions = batch['actions']
        log_probs_old = batch['log_probs_old']
        advantages = batch['advantages']
        returns = batch['returns']

        n_samples = obs.shape[0]
        actor_losses = []
        critic_losses = []

        for epoch in range(epochs):
            # Shuffle indices
            indices = np.random.permutation(n_samples)

            for start in range(0, n_samples, batch_size):
                end = min(start + batch_size, n_samples)
                batch_indices = indices[start:end]

                obs_batch = obs[batch_indices]
                actions_batch = actions[batch_indices]
                log_probs_old_batch = log_probs_old[batch_indices]
                advantages_batch = advantages[batch_indices]
                returns_batch = returns[batch_indices]

                # Forward pass
                features = self.cnn_encoder.encode(obs_batch)
                logits = self._forward_policy(features)
                values = self._forward_value(features).squeeze(-1)

                # Compute new log probs
                probs = self._softmax(logits)
                log_probs_new = np.array([
                    np.log(probs[i, actions_batch[i]] + 1e-8)
                    for i in range(len(actions_batch))
                ])

                # PPO actor loss
                ratio = np.exp(log_probs_new - log_probs_old_batch)
                clipped_ratio = np.clip(ratio, 1 - self.clip_ratio, 1 + self.clip_ratio)
                actor_loss = -np.mean(np.minimum(
                    ratio * advantages_batch,
                    clipped_ratio * advantages_batch
                ))

                # Entropy bonus (using probabilities)
                entropy = -np.mean(np.sum(probs * (np.log(probs + 1e-8)), axis=1))

                # Value (critic) loss
                critic_loss = np.mean((values - returns_batch) ** 2)

                # Total loss
                total_loss = actor_loss + self.value_coef * critic_loss - self.entropy_coef * entropy

                actor_losses.append(float(actor_loss))
                critic_losses.append(float(critic_loss))

        self.total_updates += 1

        return float(np.mean(actor_losses)), float(np.mean(critic_losses))


class PPOTrainer:
    """Wrapper for training PPO agent in an environment."""

    def __init__(
        self,
        agent: PPOAgent,
        env,
        buffer_capacity: int = 2048,
        learning_rate: float = 3e-4
    ):
        """Initialize PPO trainer.

        Args:
            agent: PPOAgent instance
            env: Gymnasium environment
            buffer_capacity: Size of experience buffer
            learning_rate: Learning rate
        """
        self.agent = agent
        self.env = env
        self.buffer = PPOBuffer(capacity=buffer_capacity)
        self.learning_rate = learning_rate

        self.episode_count = 0
        self.total_steps = 0
        self.episode_rewards = []

    def collect_trajectory(self, max_steps: int = 500) -> Dict[str, Any]:
        """Collect one episode of experience.

        Args:
            max_steps: Maximum steps per episode

        Returns:
            Episode statistics
        """
        obs, info = self.env.reset()
        episode_reward = 0
        episode_steps = 0

        for _ in range(max_steps):
            # Predict action
            action, log_prob, value = self.agent.predict(obs)

            # Take step in environment
            next_obs, reward, terminated, truncated, info = self.env.step(action)
            done = terminated or truncated

            # Store in buffer
            self.buffer.add(obs, action, reward, next_obs, done, value, log_prob)

            episode_reward += reward
            episode_steps += 1
            self.total_steps += 1
            obs = next_obs

            if done:
                break

        self.episode_count += 1
        self.episode_rewards.append(episode_reward)

        return {
            'episode': self.episode_count,
            'steps': episode_steps,
            'reward': episode_reward,
            'avg_reward': float(np.mean(self.episode_rewards[-100:]))
        }

    def train_step(self, epochs: int = 3) -> Tuple[float, float]:
        """Perform one PPO training iteration.

        Returns:
            actor_loss, critic_loss
        """
        batch = self.buffer.get_all()
        actor_loss, critic_loss = self.agent.update_step(batch, epochs=epochs)
        self.buffer.clear()

        return actor_loss, critic_loss
