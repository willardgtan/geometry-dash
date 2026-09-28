"""Full training pipeline integration for RL agent."""

from dataclasses import dataclass, field
from typing import Dict, Optional, Any
import pickle
import os

from environment.gd_env import GeometryDashEnv
from models.ppo_agent import PPOAgent, PPOBuffer
from models.residual_physics import ResidualPhysicsModel, ResidualPhysicsAuxiliaryTask
from training.curriculum_scheduler import CurriculumScheduler
from training.phase1_mastery import Phase1MasteryEvaluator


@dataclass
class PipelineConfig:
    """Configuration for training pipeline."""

    # PPO parameters
    ppo_learning_rate: float = 3e-4
    ppo_entropy_coef: float = 0.01
    ppo_clip_ratio: float = 0.2

    # Curriculum parameters
    curriculum_required_win_rate: float = 0.95
    num_phases: int = 8
    curriculum_update_frequency: int = 10

    # Training parameters
    max_training_episodes: int = 100000
    trajectory_buffer_size: int = 2000
    training_batch_size: int = 64
    training_epochs: int = 4

    # Physics model parameters
    use_residual_physics: bool = False
    physics_model_weight: float = 0.1

    # Evaluation parameters
    mastery_min_episodes: int = 20
    mastery_gate_threshold: float = 0.95

    # Other
    checkpoint_frequency: int = 100
    log_frequency: int = 10


class TrainingPipeline:
    """Integrated training pipeline combining all components."""

    def __init__(self, env: GeometryDashEnv, config: Optional[PipelineConfig] = None):
        """Initialize training pipeline.

        Args:
            env: Geometry Dash environment
            config: Pipeline configuration (uses defaults if None)
        """
        self.env = env
        self.config = config or PipelineConfig()

        # Initialize components
        self.agent = PPOAgent(
            obs_shape=(16, 24, 4),
            action_space_size=2,
            learning_rate=self.config.ppo_learning_rate,
            entropy_coef=self.config.ppo_entropy_coef,
            clip_ratio=self.config.ppo_clip_ratio
        )

        self.scheduler = CurriculumScheduler()

        self.evaluator = Phase1MasteryEvaluator(
            required_win_rate=self.config.mastery_gate_threshold,
            min_episodes=self.config.mastery_min_episodes
        )

        # Experience buffer
        self.buffer = PPOBuffer(capacity=self.config.trajectory_buffer_size)

        # Optional residual physics auxiliary task
        self.physics_task = None
        if self.config.use_residual_physics:
            physics_model = ResidualPhysicsModel(
                latent_dim=256,
                action_space_size=2,
                state_dim=6
            )
            self.physics_task = ResidualPhysicsAuxiliaryTask(
                physics_model,
                weight=self.config.physics_model_weight
            )

        # Training state
        self.episode_count = 0
        self.total_steps = 0
        self.phase_wins = 0
        self.phase_episodes = 0

    def train_step(self) -> Dict[str, Any]:
        """Execute one training iteration.

        Returns:
            Dictionary with training statistics
        """
        # Collect one trajectory
        traj_len = self.collect_trajectory()

        # Train agent if buffer has enough data
        if self.buffer.size > 0:
            actor_loss, critic_loss = self.train_agent(epochs=self.config.training_epochs)
        else:
            actor_loss, critic_loss = 0.0, 0.0

        # Update curriculum if needed
        win_rate = self.phase_wins / max(self.phase_episodes, 1)
        if self.phase_episodes % self.config.curriculum_update_frequency == 0:
            self.update_curriculum(win_rate, self.phase_episodes)

        stats = {
            'episode': self.episode_count,
            'reward': float(self.buffer.rewards[-1]) if len(self.buffer.rewards) > 0 else 0.0,
            'actor_loss': actor_loss,
            'critic_loss': critic_loss,
            'trajectory_length': traj_len,
            'phase_id': self.scheduler.current_phase_id,
            'curriculum_win_rate': win_rate
        }

        return stats

    def collect_trajectory(self, max_steps: int = 500) -> int:
        """Collect one trajectory (episode).

        Args:
            max_steps: Maximum steps per episode

        Returns:
            Length of trajectory collected
        """
        obs, _ = self.env.reset()
        done = False
        steps = 0
        episode_reward = 0.0

        while not done and steps < max_steps:
            # Get action from agent
            action, log_prob, value = self.agent.predict(obs)

            # Step environment
            next_obs, reward, terminated, truncated, info = self.env.step(action)
            done = terminated or truncated

            # Store in buffer
            self.buffer.add(obs, action, reward, next_obs, done, value, log_prob)

            episode_reward += reward
            obs = next_obs
            steps += 1

        self.episode_count += 1
        self.total_steps += steps
        self.phase_episodes += 1

        # Update evaluator with episode result
        success = episode_reward > 100.0  # Threshold for success
        distance = float(info.get('distance', 0.0))
        self.evaluator.record_episode(success=success, distance=distance, steps=steps)

        if success:
            self.phase_wins += 1

        return steps

    def train_agent(self, epochs: int = 4) -> tuple:
        """Train agent on collected trajectories.

        Args:
            epochs: Number of training epochs

        Returns:
            (actor_loss, critic_loss) tuple
        """
        # Get data from buffer
        if self.buffer.size == 0:
            return 0.0, 0.0

        # Get all data and compute advantages
        batch = self.buffer.get_all()

        # Rename log_probs to log_probs_old for update_step
        batch['log_probs_old'] = batch.pop('log_probs')

        # Train agent - update_step expects batch dict with specific keys
        actor_loss, critic_loss = self.agent.update_step(
            batch=batch,
            epochs=epochs,
            batch_size=self.config.training_batch_size
        )

        # Clear buffer after training
        self.buffer.clear()

        return actor_loss, critic_loss

    def update_curriculum(self, win_rate: float, episodes: int) -> bool:
        """Update curriculum based on performance.

        Args:
            win_rate: Current phase win rate
            episodes: Number of episodes in phase

        Returns:
            True if phase advanced, False otherwise
        """
        # Check if we should advance phase
        advanced = False
        if win_rate >= self.config.curriculum_required_win_rate and episodes >= self.config.mastery_min_episodes:
            if self.scheduler.current_phase_id < self.config.num_phases - 1:
                self.scheduler.advance_phase()
                advanced = True
                # Reset phase counters
                self.phase_wins = 0
                self.phase_episodes = 0
                self.evaluator.reset()

        return advanced

    def get_progress(self) -> Dict[str, Any]:
        """Get current training progress.

        Returns:
            Dictionary with progress information
        """
        win_rate = self.phase_wins / max(self.phase_episodes, 1)

        return {
            'episode': self.episode_count,
            'total_steps': self.total_steps,
            'phase_id': self.scheduler.current_phase_id,
            'curriculum_win_rate': win_rate,
            'phase_episodes': self.phase_episodes,
            'phase_wins': self.phase_wins
        }

    def save_checkpoint(self, path: str) -> bool:
        """Save pipeline checkpoint.

        Args:
            path: Path to save checkpoint

        Returns:
            True if successful
        """
        try:
            checkpoint = {
                'episode_count': self.episode_count,
                'total_steps': self.total_steps,
                'phase_id': self.scheduler.current_phase_id,
                'phase_wins': self.phase_wins,
                'phase_episodes': self.phase_episodes,
                'config': self.config
            }

            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'wb') as f:
                pickle.dump(checkpoint, f)

            return True
        except Exception:
            return False

    def get_state_dict(self) -> Dict[str, Any]:
        """Get pipeline state dictionary.

        Returns:
            Dictionary containing pipeline state
        """
        return {
            'episode': self.episode_count,
            'total_steps': self.total_steps,
            'phase_id': self.scheduler.current_phase_id,
            'phase_wins': self.phase_wins,
            'phase_episodes': self.phase_episodes,
            'agent_state': {
                'encoder': 'cnn',
                'policy_head': 'actor',
                'value_head': 'critic'
            }
        }
