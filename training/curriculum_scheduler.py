"""Curriculum learning scheduler for empirical 8-phase progression."""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional
import json


@dataclass
class CurriculumPhase:
    """Definition of a single curriculum phase."""

    phase_id: int
    name: str
    star_range: Tuple[int, int]  # (min_stars, max_stars) for level selection
    gate_threshold: float  # Win rate required to advance (0.0-1.0)
    obstacle_density: float  # Fraction of level with obstacles (0.0-1.0)
    spike_density: float  # Fraction of obstacles that are spikes (0.0-1.0)

    # Optional properties
    reward_scale: float = 1.0  # Reward multiplier for this phase
    max_steps: int = 6000  # Max steps in environment per episode (100s at 60Hz)
    episodes_completed: int = field(default=0)  # Cumulative episodes in this phase
    peak_win_rate: float = field(default=0.0)  # Best win rate achieved in phase


class CurriculumScheduler:
    """Empirical 8-phase curriculum grounded in official GD level difficulty."""

    def __init__(self):
        """Initialize curriculum with 8 phases based on official GD difficulty."""
        # Gate thresholds decrease as phases progress (easier to advance in harder phases)
        # Based on official GD difficulty progression: 1★ to 22★
        self.phases: List[CurriculumPhase] = [
            # Phase 0: Basics (1-3★)
            # Focus: Learn jump timing, basic forward movement
            CurriculumPhase(
                phase_id=0,
                name="Phase 0: Basics (1-3★)",
                star_range=(1, 3),
                gate_threshold=0.95,
                obstacle_density=0.05,
                spike_density=0.20,
                reward_scale=1.0,
                max_steps=6000
            ),
            # Phase 1: Simple Patterns (3-6★)
            # Focus: Consistent jump execution, simple obstacles
            CurriculumPhase(
                phase_id=1,
                name="Phase 1: Simple Patterns (3-6★)",
                star_range=(3, 6),
                gate_threshold=0.93,
                obstacle_density=0.10,
                spike_density=0.25,
                reward_scale=1.0,
                max_steps=6000
            ),
            # Phase 2: Intermediate (6-10★)
            # Focus: Rhythm patterns, varied obstacle types
            CurriculumPhase(
                phase_id=2,
                name="Phase 2: Intermediate (6-10★)",
                star_range=(6, 10),
                gate_threshold=0.90,
                obstacle_density=0.15,
                spike_density=0.30,
                reward_scale=1.0,
                max_steps=6000
            ),
            # Phase 3: Challenging (10-13★)
            # Focus: Dense patterns, precision timing
            CurriculumPhase(
                phase_id=3,
                name="Phase 3: Challenging (10-13★)",
                star_range=(10, 13),
                gate_threshold=0.85,
                obstacle_density=0.25,
                spike_density=0.35,
                reward_scale=1.0,
                max_steps=6000
            ),
            # Phase 4: Hard (13-16★)
            # Focus: Complex sequences, speed requirements
            CurriculumPhase(
                phase_id=4,
                name="Phase 4: Hard (13-16★)",
                star_range=(13, 16),
                gate_threshold=0.80,
                obstacle_density=0.35,
                spike_density=0.40,
                reward_scale=0.95,
                max_steps=6000
            ),
            # Phase 5: Harder (16-19★)
            # Focus: Extreme patterns, high-speed sections
            CurriculumPhase(
                phase_id=5,
                name="Phase 5: Harder (16-19★)",
                star_range=(16, 19),
                gate_threshold=0.78,
                obstacle_density=0.45,
                spike_density=0.45,
                reward_scale=0.90,
                max_steps=6000
            ),
            # Phase 6: Extreme (19-21★)
            # Focus: Optimal routing, minimal margin for error
            CurriculumPhase(
                phase_id=6,
                name="Phase 6: Extreme (19-21★)",
                star_range=(19, 21),
                gate_threshold=0.75,
                obstacle_density=0.55,
                spike_density=0.50,
                reward_scale=0.85,
                max_steps=6000
            ),
            # Phase 7: Insane (21-22★)
            # Focus: Perfect execution, zero tolerance
            CurriculumPhase(
                phase_id=7,
                name="Phase 7: Insane (21-22★)",
                star_range=(21, 22),
                gate_threshold=0.70,
                obstacle_density=0.65,
                spike_density=0.55,
                reward_scale=0.80,
                max_steps=6000
            ),
        ]

        self.current_phase_id = 0
        self.history: List[Dict] = []  # Performance history for analysis

    def get_current_phase(self) -> CurriculumPhase:
        """Get the current curriculum phase."""
        return self.phases[self.current_phase_id]

    def update_performance(self, win_rate: float, episodes: int = 1) -> bool:
        """Update performance metrics and potentially advance phase.

        Args:
            win_rate: Fraction of successful episodes (0.0-1.0)
            episodes: Number of episodes to count for this update

        Returns:
            True if phase advanced, False otherwise
        """
        phase = self.get_current_phase()

        # Update phase metrics
        phase.episodes_completed += episodes
        phase.peak_win_rate = max(phase.peak_win_rate, win_rate)

        # Record history
        self.history.append({
            'phase_id': self.current_phase_id,
            'win_rate': win_rate,
            'episodes': episodes,
            'total_episodes_in_phase': phase.episodes_completed
        })

        # Check if we should advance
        advanced = False
        if win_rate >= phase.gate_threshold and self.current_phase_id < len(self.phases) - 1:
            self.current_phase_id += 1
            advanced = True

        return advanced

    def get_level_selection_config(self) -> Dict:
        """Get configuration for selecting levels in current phase.

        Returns:
            Dictionary with star_range, max_obstacles, and obstacle_types
        """
        phase = self.get_current_phase()

        # Estimate max obstacles based on density
        # Typical GD level: ~300 game units width
        # Each obstacle ~20 units wide
        max_obstacles = int(300 / 20 * phase.obstacle_density) + 1

        return {
            'star_range': phase.star_range,
            'max_obstacles': max_obstacles,
            'obstacle_density': phase.obstacle_density,
            'spike_density': phase.spike_density,
            'obstacle_types': self._get_obstacle_types_for_phase(),
            'reward_scale': phase.reward_scale,
            'max_steps': phase.max_steps
        }

    def _get_obstacle_types_for_phase(self) -> List[str]:
        """Get available obstacle types for current phase."""
        phase = self.get_current_phase()

        # Introduce obstacles progressively
        if phase.phase_id < 1:
            # Early phases: just spikes and blocks
            return ['spike', 'block']
        elif phase.phase_id < 3:
            # Mid phases: add orbs and pads
            return ['spike', 'block', 'orb', 'pad']
        elif phase.phase_id < 5:
            # Later phases: add moving obstacles
            return ['spike', 'block', 'orb', 'pad', 'moving_block']
        else:
            # Final phases: all types available
            return ['spike', 'block', 'orb', 'pad', 'moving_block', 'portal']

    def reset(self) -> None:
        """Reset scheduler to initial state."""
        self.current_phase_id = 0
        for phase in self.phases:
            phase.episodes_completed = 0
            phase.peak_win_rate = 0.0
        self.history = []

    def get_progress(self) -> Dict:
        """Get curriculum progress statistics.

        Returns:
            Dictionary with phase info, win rates, episode counts
        """
        return {
            'current_phase_id': self.current_phase_id,
            'current_phase_name': self.get_current_phase().name,
            'phases_completed': self.current_phase_id,
            'total_phases': len(self.phases),
            'current_phase_episodes': self.get_current_phase().episodes_completed,
            'current_phase_peak_win_rate': self.get_current_phase().peak_win_rate,
            'phase_gate_threshold': self.get_current_phase().gate_threshold,
            'history_length': len(self.history)
        }

    def to_json(self) -> str:
        """Serialize curriculum state to JSON."""
        progress = self.get_progress()
        return json.dumps(progress, indent=2)

    def get_phase_summary(self) -> str:
        """Get human-readable phase summary."""
        phase = self.get_current_phase()
        progress = self.get_progress()

        lines = [
            f"=== Curriculum Progress ===",
            f"Phase: {progress['current_phase_name']}",
            f"Progress: {progress['phases_completed']}/{progress['total_phases'] - 1}",
            f"Episodes in phase: {progress['current_phase_episodes']}",
            f"Peak win rate: {progress['current_phase_peak_win_rate']:.1%}",
            f"Gate threshold: {progress['phase_gate_threshold']:.1%}",
            f"Level difficulty: {phase.star_range[0]}-{phase.star_range[1]}★",
            f"Obstacle density: {phase.obstacle_density:.1%}",
        ]

        return "\n".join(lines)


class CurriculumEnv:
    """Wrapper that applies curriculum to an environment."""

    def __init__(self, base_env, scheduler: CurriculumScheduler):
        """Initialize curriculum-wrapped environment.

        Args:
            base_env: Underlying Gymnasium environment
            scheduler: CurriculumScheduler instance
        """
        self.base_env = base_env
        self.scheduler = scheduler
        self.current_max_steps = 0

    def reset(self):
        """Reset environment with current curriculum config."""
        config = self.scheduler.get_level_selection_config()
        self.current_max_steps = config['max_steps']

        # Reset base environment (would select level from star_range in real impl)
        return self.base_env.reset()

    def step(self, action):
        """Step environment and apply curriculum reward scaling."""
        obs, reward, terminated, truncated, info = self.base_env.step(action)

        # Apply reward scaling from curriculum phase
        config = self.scheduler.get_level_selection_config()
        reward *= config['reward_scale']

        return obs, reward, terminated, truncated, info

    def update_curriculum(self, win_rate: float, episodes: int = 1) -> bool:
        """Update curriculum and check if phase advanced."""
        return self.scheduler.update_performance(win_rate, episodes)

    def get_progress(self) -> Dict:
        """Get curriculum progress."""
        return self.scheduler.get_progress()
