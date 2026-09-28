"""Tests for Phase 1 mastery evaluation."""

import unittest
import numpy as np
import sys
sys.path.insert(0, '/home/claude/geometry-dash')

from training.phase1_mastery import Phase1MasteryEvaluator


class TestPhase1MasteryEvaluator(unittest.TestCase):
    """Tests for Phase 1 mastery evaluation."""

    def test_evaluator_initialization(self):
        """Test creating mastery evaluator."""
        evaluator = Phase1MasteryEvaluator(
            required_win_rate=0.95,
            min_episodes=10
        )
        self.assertIsNotNone(evaluator)
        self.assertEqual(evaluator.required_win_rate, 0.95)

    def test_evaluate_single_episode(self):
        """Test recording single episode result."""
        evaluator = Phase1MasteryEvaluator(required_win_rate=0.95, min_episodes=5)

        # Episode success
        evaluator.record_episode(success=True, distance=150.0, steps=100)

        self.assertEqual(evaluator.total_episodes, 1)
        self.assertEqual(evaluator.successful_episodes, 1)

    def test_win_rate_calculation(self):
        """Test win rate calculation."""
        evaluator = Phase1MasteryEvaluator(required_win_rate=0.95, min_episodes=10)

        # Record 10 episodes: 9 successes, 1 failure
        for i in range(9):
            evaluator.record_episode(success=True, distance=150.0, steps=100)
        evaluator.record_episode(success=False, distance=75.0, steps=50)

        win_rate = evaluator.get_win_rate()
        self.assertEqual(win_rate, 0.9)

    def test_mastery_achieved(self):
        """Test mastery achieved condition."""
        evaluator = Phase1MasteryEvaluator(required_win_rate=0.95, min_episodes=10)

        # Record 20 episodes: 19 successes (95%)
        for i in range(19):
            evaluator.record_episode(success=True, distance=150.0, steps=100)
        evaluator.record_episode(success=False, distance=75.0, steps=50)

        is_mastered = evaluator.is_mastered()
        self.assertTrue(is_mastered)

    def test_mastery_not_achieved(self):
        """Test mastery not achieved condition."""
        evaluator = Phase1MasteryEvaluator(required_win_rate=0.95, min_episodes=10)

        # Record 10 episodes: 8 successes (80%, below 95%)
        for i in range(8):
            evaluator.record_episode(success=True, distance=150.0, steps=100)
        for i in range(2):
            evaluator.record_episode(success=False, distance=75.0, steps=50)

        is_mastered = evaluator.is_mastered()
        self.assertFalse(is_mastered)

    def test_min_episodes_requirement(self):
        """Test minimum episodes requirement."""
        evaluator = Phase1MasteryEvaluator(required_win_rate=0.95, min_episodes=20)

        # Record only 10 episodes with perfect score
        for i in range(10):
            evaluator.record_episode(success=True, distance=150.0, steps=100)

        # Should not be mastered even with 100% win rate
        is_mastered = evaluator.is_mastered()
        self.assertFalse(is_mastered)

        # Record 10 more episodes
        for i in range(10):
            evaluator.record_episode(success=True, distance=150.0, steps=100)

        # Now should be mastered
        is_mastered = evaluator.is_mastered()
        self.assertTrue(is_mastered)

    def test_average_distance_tracking(self):
        """Test tracking average distance per episode."""
        evaluator = Phase1MasteryEvaluator(required_win_rate=0.95, min_episodes=5)

        distances = [100.0, 120.0, 140.0, 150.0, 130.0]
        for d in distances:
            evaluator.record_episode(success=True, distance=d, steps=int(d))

        avg_distance = evaluator.get_average_distance()
        expected_avg = np.mean(distances)

        self.assertAlmostEqual(avg_distance, expected_avg, places=1)

    def test_statistics_tracking(self):
        """Test comprehensive statistics tracking."""
        evaluator = Phase1MasteryEvaluator(required_win_rate=0.95, min_episodes=10)

        for i in range(15):
            success = i < 14  # 14 successes, 1 failure
            evaluator.record_episode(success=success, distance=140.0 + i, steps=100 + i)

        stats = evaluator.get_statistics()

        self.assertIn('total_episodes', stats)
        self.assertIn('successful_episodes', stats)
        self.assertIn('win_rate', stats)
        self.assertIn('average_distance', stats)
        self.assertIn('total_distance', stats)
        self.assertEqual(stats['total_episodes'], 15)
        self.assertEqual(stats['successful_episodes'], 14)

    def test_reset_evaluator(self):
        """Test resetting evaluator."""
        evaluator = Phase1MasteryEvaluator(required_win_rate=0.95, min_episodes=5)

        # Record some episodes
        for i in range(5):
            evaluator.record_episode(success=True, distance=150.0, steps=100)

        self.assertEqual(evaluator.total_episodes, 5)

        # Reset
        evaluator.reset()

        self.assertEqual(evaluator.total_episodes, 0)
        self.assertEqual(evaluator.successful_episodes, 0)

    def test_recent_performance(self):
        """Test recent performance window."""
        evaluator = Phase1MasteryEvaluator(required_win_rate=0.95, min_episodes=5)

        # Record 20 episodes
        for i in range(20):
            success = i >= 10  # First 10 failures, last 10 successes
            evaluator.record_episode(success=success, distance=150.0, steps=100)

        # Recent performance should focus on last episodes
        recent_stats = evaluator.get_recent_performance(window=10)
        self.assertEqual(recent_stats['recent_win_rate'], 1.0)

    def test_episode_sequence_logging(self):
        """Test logging episode sequence."""
        evaluator = Phase1MasteryEvaluator(required_win_rate=0.95, min_episodes=5)

        for i in range(5):
            success = i % 2 == 0  # Alternating success/failure
            evaluator.record_episode(success=success, distance=150.0 - i*10, steps=100)

        history = evaluator.get_episode_history()

        self.assertEqual(len(history), 5)
        self.assertTrue(history[0]['success'])
        self.assertFalse(history[1]['success'])

    def test_confidence_interval(self):
        """Test calculating win rate confidence interval."""
        evaluator = Phase1MasteryEvaluator(required_win_rate=0.95, min_episodes=10)

        # 95 successes out of 100 episodes
        for i in range(95):
            evaluator.record_episode(success=True, distance=150.0, steps=100)
        for i in range(5):
            evaluator.record_episode(success=False, distance=75.0, steps=50)

        win_rate = evaluator.get_win_rate()
        ci = evaluator.get_confidence_interval(confidence=0.95)

        # Win rate should be within confidence interval
        self.assertGreaterEqual(win_rate, ci[0])
        self.assertLessEqual(win_rate, ci[1])

    def test_convergence_detection(self):
        """Test detecting performance convergence."""
        evaluator = Phase1MasteryEvaluator(required_win_rate=0.90, min_episodes=20)

        # Simulate improving performance: 20 episodes with 18+ successes = 90%+
        for i in range(20):
            success = i >= 2  # First 2 failures, then all successes = 18/20 = 90%
            evaluator.record_episode(success=success, distance=150.0, steps=100)

        # Should eventually converge to mastery
        self.assertTrue(evaluator.is_mastered())

    def test_phase1_specific_metrics(self):
        """Test Phase 1 specific metrics (1-3★ levels)."""
        evaluator = Phase1MasteryEvaluator(
            required_win_rate=0.95,
            min_episodes=20,
            phase_name="Phase 0: Basics (1-3★)"
        )

        self.assertEqual(evaluator.phase_name, "Phase 0: Basics (1-3★)")

        # Phase 1 specific: should handle short distances (easy levels)
        for i in range(20):
            evaluator.record_episode(success=True, distance=100.0, steps=80)

        avg_distance = evaluator.get_average_distance()
        self.assertLess(avg_distance, 150)  # Phase 1 levels are shorter


class TestMasteryGatekeeping(unittest.TestCase):
    """Tests for mastery gatekeeping in training pipeline."""

    def test_gate_prevents_premature_advance(self):
        """Test that gate prevents advancing with low performance."""
        evaluator = Phase1MasteryEvaluator(required_win_rate=0.95, min_episodes=10)

        # Record low performance
        for i in range(10):
            success = i < 7  # 70% win rate
            evaluator.record_episode(success=success, distance=140.0, steps=100)

        # Should not pass gate
        can_advance = evaluator.is_mastered()
        self.assertFalse(can_advance)

    def test_gate_allows_sufficient_performance(self):
        """Test that gate allows advance with sufficient performance."""
        evaluator = Phase1MasteryEvaluator(required_win_rate=0.95, min_episodes=10)

        # Record high performance
        for i in range(10):
            success = i < 10  # 100% win rate
            evaluator.record_episode(success=success, distance=150.0, steps=100)

        # Should pass gate
        can_advance = evaluator.is_mastered()
        self.assertTrue(can_advance)

    def test_early_stopping_criteria(self):
        """Test early stopping if performance degrades."""
        evaluator = Phase1MasteryEvaluator(required_win_rate=0.95, min_episodes=20)

        # Initial good performance
        for i in range(10):
            evaluator.record_episode(success=True, distance=150.0, steps=100)

        # Then degradation
        for i in range(10):
            success = i < 5  # 50% win rate on recent episodes
            evaluator.record_episode(success=success, distance=75.0, steps=50)

        recent_stats = evaluator.get_recent_performance(window=10)

        # Should detect performance degradation
        self.assertLess(recent_stats['recent_win_rate'], evaluator.required_win_rate)


if __name__ == '__main__':
    unittest.main()
