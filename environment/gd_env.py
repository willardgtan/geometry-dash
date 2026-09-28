"""Geometry Dash Gymnasium environment wrapper.

Provides a standard Gymnasium environment interface for training RL agents
on Geometry Dash. Wraps the headless game simulator and perception system.
"""

import numpy as np
from typing import Tuple, Dict, Any, Optional

try:
    import gymnasium as gym
    from gymnasium import spaces
except ImportError:
    # Fallback for testing without gymnasium installed
    class gym:
        class Env:
            pass
    class spaces:
        class Box:
            def __init__(self, low, high, shape, dtype):
                self.low = low
                self.high = high
                self.shape = shape
                self.dtype = dtype
        class Discrete:
            def __init__(self, n):
                self.n = n
            def sample(self):
                return np.random.randint(0, self.n)

from data.types import GameMode
from data.transition import Transition
from data.perception import GameBotGrid, StateEncoder, ControlDecoder


class GeometryDashEnv(gym.Env):
    """
    Gymnasium environment for Geometry Dash RL training.

    Provides:
    - Observation: 24×16×4 perception grid (game-bot format)
    - Action: Binary (0=no action, 1=action/jump)
    - Reward: Progress (distance traveled) + survival bonus
    - Termination: Death or max episode steps
    """

    def __init__(
        self,
        level_id: str = "level_001",
        render_mode: Optional[str] = None,
        max_episode_steps: int = 6000,  # ~100 seconds at 60 FPS
    ):
        """
        Initialize environment.

        Args:
            level_id: Level to load
            render_mode: Render mode (None, "rgb_array", etc.)
            max_episode_steps: Max steps per episode
        """
        self.level_id = level_id
        self.render_mode = render_mode
        self.max_episode_steps = max_episode_steps

        # Gymnasium spaces
        self.observation_space = spaces.Box(
            low=0.0,
            high=1.0,
            shape=(16, 24, 4),
            dtype=np.float32
        )
        self.action_space = spaces.Discrete(2)  # 0=no action, 1=action

        # State
        self.perception_encoder = StateEncoder()
        self.grid = GameBotGrid()
        self.control_decoder = ControlDecoder()

        # Game state
        self.current_transition: Optional[Transition] = None
        self.step_count = 0
        self.total_distance = 0.0
        self.dead = False
        self.level_data: Dict[str, Any] = {
            "level_id": level_id,
            "mode": GameMode.CUBE,
            "obstacles": {},
        }

    def reset(self) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Reset environment to initial state.

        Returns:
            (observation, info)
        """
        self.step_count = 0
        self.total_distance = 0.0
        self.dead = False

        # Initialize player at level start
        self.current_transition = Transition(
            tick=0,
            x=100.0,
            y=105.0,
            vx=10.389,
            vy=0.0,
            rotation=0.0,
            mode=GameMode.CUBE,
            grounded=True,
            contact_type=None,
            input_pressed=False,
            input_held=False,
            gravity_mod=1.0,
            size_mod=1.0,
            speed_scaling=1.0,
            death_state=False,
            level_id=self.level_id,
            attempt_id="training",
            source="simulator"
        )

        obs = self._get_observation()
        info = self._get_info()

        return obs, info

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict[str, Any]]:
        """
        Execute one step in the environment.

        Args:
            action: 0=no action, 1=action (tap/jump)

        Returns:
            (observation, reward, terminated, truncated, info)
        """
        if self.current_transition is None:
            raise RuntimeError("Environment not reset")

        self.step_count += 1

        # Update game state based on action
        # (Simplified: just simulate position update)
        input_pressed = action == 1
        input_held = action == 1

        # Simulate physics: move player forward
        new_x = self.current_transition.x + self.current_transition.vx * 0.01667  # Roughly one 60-Hz frame
        new_y = self.current_transition.y

        # Simplified death check: spike at x=250
        died = (self.current_transition.x < 250 < new_x)

        if died:
            self.dead = True

        # Update state
        self.current_transition.x = new_x
        self.current_transition.y = new_y
        self.current_transition.input_pressed = input_pressed
        self.current_transition.input_held = input_held
        self.current_transition.death_state = self.dead
        self.current_transition.tick = self.step_count

        # Compute reward
        distance_delta = self.current_transition.vx * 0.01667
        self.total_distance += distance_delta
        reward = float(distance_delta)

        if self.dead:
            reward -= 10.0  # Death penalty

        # Termination conditions
        terminated = self.dead
        truncated = self.step_count >= self.max_episode_steps

        obs = self._get_observation()
        info = self._get_info()

        if terminated:
            info["death_reason"] = "spike"
        if truncated:
            info["truncation_reason"] = "max_steps"

        return obs, reward, terminated, truncated, info

    def _get_observation(self) -> np.ndarray:
        """
        Get current observation as perception grid.

        Returns:
            24×16×4 grid
        """
        if self.current_transition is None:
            return np.zeros((16, 24, 4), dtype=np.float32)

        # Encode player
        player_grid = self.perception_encoder.encode_player(self.current_transition)

        # Encode obstacles (simplified: hardcoded spike at x=250)
        obstacles = {
            "spike_001": {"x": 250, "y": 100, "width": 20, "height": 20},
        }
        obstacle_grid = self.perception_encoder.encode_obstacles(obstacles)

        # Stack into grid
        self.grid.reset()
        self.grid.set_channel(0, player_grid.squeeze())
        self.grid.set_channel(1, obstacle_grid.squeeze())

        return self.grid.stack_channels()

    def _get_info(self) -> Dict[str, Any]:
        """
        Get info dict.

        Returns:
            Dictionary with level, position, mode, etc.
        """
        if self.current_transition is None:
            return {}

        return {
            "level": self.level_id,
            "position": (self.current_transition.x, self.current_transition.y),
            "mode": self.current_transition.mode.value,
            "total_distance": self.total_distance,
            "step": self.step_count,
        }

    def render(self):
        """Render environment (stub for now)."""
        if self.render_mode == "human":
            print(f"Step {self.step_count}: Position ({self.current_transition.x:.1f}, {self.current_transition.y:.1f})")
        elif self.render_mode == "rgb_array":
            # Return dummy image for now
            return np.zeros((210, 160, 3), dtype=np.uint8)

    def close(self):
        """Clean up environment."""
        pass
