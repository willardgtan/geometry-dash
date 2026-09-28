"""Phase 1 mastery evaluation and gatekeeping."""

from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
import numpy as np
from scipy import stats


@dataclass
class EpisodeRecord:
    """Record of a single evaluation episode."""

    episode_id: int
    success: bool
    distance: float
    steps: int
    timestamp: Optional[float] = None
    reward: Optional[float] = None


class Phase1MasteryEvaluator:
    """Evaluates Phase 1 mastery for curriculum progression gating."""

    def __init__(
        self,
        required_win_rate: float = 0.95,
        min_episodes: int = 20,
        phase_name: str = "Phase 0: Basics (1-3★)"
    ):
        """Initialize mastery evaluator.

        Args:
            required_win_rate: Win rate threshold for mastery (0.0-1.0)
            min_episodes: Minimum episodes before considering mastery
            phase_name: Name of the phase being evaluated
        """
        self.required_win_rate = required_win_rate
        self.min_episodes = min_episodes
        self.phase_name = phase_name

        self.total_episodes = 0
        self.successful_episodes = 0

        self.episode_history: List[EpisodeRecord] = []
        self.distances: List[float] = []
        self.steps: List[int] = []

    def record_episode(
        self,
        success: bool,
        distance: float,
        steps: int,
        reward: Optional[float] = None
    ) -> None:
        """Record a single evaluation episode.

        Args:
            success: Whether the episode was successful
            distance: Distance traveled in the level
            steps: Number of steps taken
            reward: Optional accumulated reward
        """
        self.total_episodes += 1
        if success:
            self.successful_episodes += 1

        record = EpisodeRecord(
            episode_id=self.total_episodes,
            success=success,
            distance=distance,
            steps=steps,
            reward=reward
        )

        self.episode_history.append(record)
        self.distances.append(distance)
        self.steps.append(steps)

    def get_win_rate(self) -> float:
        """Get current win rate.

        Returns:
            Win rate (0.0-1.0), or 0.0 if no episodes recorded
        """
        if self.total_episodes == 0:
            return 0.0

        return self.successful_episodes / self.total_episodes

    def is_mastered(self) -> bool:
        """Check if Phase 1 mastery gate is satisfied.

        Returns:
            True if win_rate >= required_win_rate AND episodes >= min_episodes
        """
        if self.total_episodes < self.min_episodes:
            return False

        return self.get_win_rate() >= self.required_win_rate

    def get_average_distance(self) -> float:
        """Get average distance traveled per episode.

        Returns:
            Average distance, or 0.0 if no episodes
        """
        if len(self.distances) == 0:
            return 0.0

        return float(np.mean(self.distances))

    def get_total_distance(self) -> float:
        """Get total distance across all episodes."""
        return float(np.sum(self.distances))

    def get_average_steps(self) -> float:
        """Get average steps per episode."""
        if len(self.steps) == 0:
            return 0.0

        return float(np.mean(self.steps))

    def get_statistics(self) -> Dict:
        """Get comprehensive statistics.

        Returns:
            Dictionary with episode counts, win rate, distances, etc.
        """
        return {
            'phase_name': self.phase_name,
            'total_episodes': self.total_episodes,
            'successful_episodes': self.successful_episodes,
            'failed_episodes': self.total_episodes - self.successful_episodes,
            'win_rate': self.get_win_rate(),
            'average_distance': self.get_average_distance(),
            'total_distance': self.get_total_distance(),
            'average_steps': self.get_average_steps(),
            'mastery_achieved': self.is_mastered(),
            'min_episodes_required': self.min_episodes,
            'required_win_rate': self.required_win_rate
        }

    def get_recent_performance(self, window: int = 10) -> Dict:
        """Get performance over recent episodes.

        Args:
            window: Number of recent episodes to analyze

        Returns:
            Statistics for recent episode window
        """
        if len(self.episode_history) == 0:
            return {
                'recent_win_rate': 0.0,
                'recent_episodes': 0,
                'recent_distance': 0.0
            }

        recent_episodes = self.episode_history[-window:]
        recent_successes = sum(1 for e in recent_episodes if e.success)
        recent_distances = [e.distance for e in recent_episodes]

        return {
            'recent_episodes': len(recent_episodes),
            'recent_win_rate': recent_successes / len(recent_episodes) if recent_episodes else 0.0,
            'recent_distance': float(np.mean(recent_distances)) if recent_distances else 0.0,
            'recent_success_count': recent_successes
        }

    def get_episode_history(self) -> List[Dict]:
        """Get full episode history.

        Returns:
            List of episode records as dictionaries
        """
        return [
            {
                'episode_id': e.episode_id,
                'success': e.success,
                'distance': e.distance,
                'steps': e.steps,
                'reward': e.reward
            }
            for e in self.episode_history
        ]

    def get_confidence_interval(
        self,
        confidence: float = 0.95
    ) -> Tuple[float, float]:
        """Get confidence interval for win rate.

        Args:
            confidence: Confidence level (0.0-1.0)

        Returns:
            (lower_bound, upper_bound) for win rate
        """
        if self.total_episodes == 0:
            return (0.0, 1.0)

        win_rate = self.get_win_rate()

        # Use normal approximation for confidence interval
        # CI = p ± z * sqrt(p(1-p)/n)
        z = stats.norm.ppf((1 + confidence) / 2)
        margin = z * np.sqrt(win_rate * (1 - win_rate) / self.total_episodes)

        lower = max(0.0, win_rate - margin)
        upper = min(1.0, win_rate + margin)

        return (lower, upper)

    def reset(self) -> None:
        """Reset evaluator to initial state."""
        self.total_episodes = 0
        self.successful_episodes = 0
        self.episode_history = []
        self.distances = []
        self.steps = []

    def get_progress_summary(self) -> str:
        """Get human-readable progress summary."""
        stats = self.get_statistics()
        recent = self.get_recent_performance(window=10)
        mastery_status = "✓ MASTERED" if self.is_mastered() else "✗ Not Yet"

        lines = [
            f"=== Phase 1 Mastery Evaluation ===",
            f"Status: {mastery_status}",
            f"Episodes: {stats['total_episodes']}/{self.min_episodes}",
            f"Win Rate: {stats['win_rate']:.1%} (required: {self.required_win_rate:.1%})",
            f"Successes: {stats['successful_episodes']}/{stats['total_episodes']}",
            f"Avg Distance: {stats['average_distance']:.1f}",
            f"Recent (10ep): {recent['recent_win_rate']:.1%}",
        ]

        return "\n".join(lines)

    def should_continue_evaluation(self) -> bool:
        """Check if evaluation should continue.

        Returns:
            True if should continue, False if can stop evaluation
        """
        # Stop if mastery achieved
        if self.is_mastered():
            return False

        # Stop if too many failed attempts (performance converged to below gate)
        if self.total_episodes > self.min_episodes * 5:
            recent = self.get_recent_performance(window=self.min_episodes)
            if recent['recent_win_rate'] < 0.5:  # Very low recent performance
                return False

        return True


class CurriculumGate:
    """Gating mechanism for curriculum progression based on mastery."""

    def __init__(self, evaluator: Phase1MasteryEvaluator):
        """Initialize curriculum gate.

        Args:
            evaluator: Phase1MasteryEvaluator instance
        """
        self.evaluator = evaluator
        self.attempts = 0
        self.max_attempts = 100  # Prevent infinite loops
        self.gate_passed = False

    def update(self, success: bool, distance: float, steps: int) -> bool:
        """Update gate with episode result.

        Args:
            success: Episode success
            distance: Distance traveled
            steps: Steps taken

        Returns:
            True if gate has now been passed
        """
        self.evaluator.record_episode(success, distance, steps)
        self.attempts += 1

        if self.evaluator.is_mastered():
            self.gate_passed = True

        return self.gate_passed

    def get_status(self) -> Dict:
        """Get current gate status.

        Returns:
            Status dictionary
        """
        return {
            'gate_passed': self.gate_passed,
            'attempts': self.attempts,
            'max_attempts': self.max_attempts,
            'mastery_achieved': self.evaluator.is_mastered(),
            'win_rate': self.evaluator.get_win_rate(),
            'required_win_rate': self.evaluator.required_win_rate,
            'episodes': self.evaluator.total_episodes,
            'min_episodes': self.evaluator.min_episodes
        }

    def can_advance(self) -> bool:
        """Check if training can advance past this gate.

        Returns:
            True if gate is passed and advancement is allowed
        """
        if self.attempts >= self.max_attempts:
            return False  # Exceeded attempts

        return self.gate_passed

    def reset(self) -> None:
        """Reset gate state."""
        self.evaluator.reset()
        self.attempts = 0
        self.gate_passed = False
