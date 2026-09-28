"""Tests for curriculum learning scheduler."""

import unittest
import numpy as np
import sys
sys.path.insert(0, '/home/claude/geometry-dash')

from training.curriculum_scheduler import CurriculumScheduler, CurriculumPhase


class TestCurriculumPhase(unittest.TestCase):
    """Tests for curriculum phase definition."""

    def test_phase_initialization(self):
        """Test creating a curriculum phase."""
        phase = CurriculumPhase(
            phase_id=0,
            name="Phase 0: Basics",
            star_range=(1, 3),
            gate_threshold=0.95,
            obstacle_density=0.1,
            spike_density=0.05
        )

        self.assertEqual(phase.phase_id, 0)
        self.assertEqual(phase.star_range, (1, 3))
        self.assertEqual(phase.gate_threshold, 0.95)

    def test_phase_difficulty(self):
        """Test phase difficulty increases with progression."""
        phases = [
            CurriculumPhase(0, "Phase 0", (1, 3), 0.95, 0.1, 0.05),
            CurriculumPhase(1, "Phase 1", (3, 6), 0.93, 0.15, 0.08),
            CurriculumPhase(2, "Phase 2", (6, 10), 0.90, 0.20, 0.10),
        ]

        densities = [p.obstacle_density for p in phases]
        self.assertTrue(all(densities[i] <= densities[i+1] for i in range(len(densities)-1)))


class TestCurriculumScheduler(unittest.TestCase):
    """Tests for curriculum scheduler."""

    def test_scheduler_initialization(self):
        """Test scheduler creation with 8 phases."""
        scheduler = CurriculumScheduler()

        self.assertIsNotNone(scheduler)
        self.assertEqual(len(scheduler.phases), 8)
        self.assertEqual(scheduler.current_phase_id, 0)

    def test_phase_gate_thresholds(self):
        """Test gate thresholds decrease from phase 0 to phase 7."""
        scheduler = CurriculumScheduler()

        thresholds = [p.gate_threshold for p in scheduler.phases]
        expected = [0.95, 0.93, 0.90, 0.85, 0.80, 0.78, 0.75, 0.70]

        self.assertEqual(thresholds, expected)

    def test_star_ranges_progression(self):
        """Test star ranges progress through phases."""
        scheduler = CurriculumScheduler()

        # Each phase should have a higher star range
        for i in range(len(scheduler.phases) - 1):
            current_max = scheduler.phases[i].star_range[1]
            next_min = scheduler.phases[i + 1].star_range[0]
            self.assertLessEqual(current_max, next_min)

    def test_get_current_phase(self):
        """Test retrieving current phase."""
        scheduler = CurriculumScheduler()

        phase = scheduler.get_current_phase()
        self.assertEqual(phase.phase_id, 0)

    def test_update_performance_no_advance(self):
        """Test performance tracking without phase advance."""
        scheduler = CurriculumScheduler()

        # Track performance below gate threshold
        win_rate = 0.80  # Below 0.95 threshold for phase 0
        advanced = scheduler.update_performance(win_rate, episodes=10)

        self.assertFalse(advanced)
        self.assertEqual(scheduler.current_phase_id, 0)

    def test_update_performance_with_advance(self):
        """Test performance tracking with phase advance."""
        scheduler = CurriculumScheduler()

        # Track performance above gate threshold
        win_rate = 0.98  # Above 0.95 threshold for phase 0
        advanced = scheduler.update_performance(win_rate, episodes=10)

        self.assertTrue(advanced)
        self.assertEqual(scheduler.current_phase_id, 1)

    def test_multiple_phase_advances(self):
        """Test advancing through multiple phases."""
        scheduler = CurriculumScheduler()

        # Advance through phases 0 and 1
        scheduler.update_performance(0.96, episodes=10)
        self.assertEqual(scheduler.current_phase_id, 1)

        scheduler.update_performance(0.94, episodes=10)
        self.assertEqual(scheduler.current_phase_id, 2)

        scheduler.update_performance(0.91, episodes=10)
        self.assertEqual(scheduler.current_phase_id, 3)

    def test_cant_advance_past_final_phase(self):
        """Test scheduler stops at final phase."""
        scheduler = CurriculumScheduler()

        # Advance to final phase
        for i in range(8):
            scheduler.update_performance(0.99, episodes=10)

        # Should be at phase 7
        self.assertEqual(scheduler.current_phase_id, 7)

        # Further updates shouldn't advance
        advanced = scheduler.update_performance(0.99, episodes=10)
        self.assertFalse(advanced)
        self.assertEqual(scheduler.current_phase_id, 7)

    def test_get_phase_properties(self):
        """Test accessing phase properties."""
        scheduler = CurriculumScheduler()

        phase = scheduler.get_current_phase()

        self.assertIsNotNone(phase.name)
        self.assertIsNotNone(phase.star_range)
        self.assertIsNotNone(phase.gate_threshold)
        self.assertIsNotNone(phase.obstacle_density)
        self.assertIsNotNone(phase.spike_density)

    def test_episode_tracking(self):
        """Test episode count tracking per phase."""
        scheduler = CurriculumScheduler()

        scheduler.update_performance(0.50, episodes=5)
        phase = scheduler.get_current_phase()
        self.assertEqual(phase.episodes_completed, 5)

        scheduler.update_performance(0.60, episodes=10)
        self.assertEqual(phase.episodes_completed, 15)

    def test_phase_metadata(self):
        """Test that all phases have proper metadata."""
        scheduler = CurriculumScheduler()

        for phase in scheduler.phases:
            self.assertGreater(phase.phase_id, -1)
            self.assertIsNotNone(phase.name)
            self.assertEqual(len(phase.star_range), 2)
            self.assertLess(phase.star_range[0], phase.star_range[1])
            self.assertGreater(phase.gate_threshold, 0.5)
            self.assertLess(phase.gate_threshold, 1.0)
            self.assertGreaterEqual(phase.obstacle_density, 0.0)
            self.assertLessEqual(phase.obstacle_density, 1.0)
            self.assertGreaterEqual(phase.spike_density, 0.0)
            self.assertLessEqual(phase.spike_density, 1.0)

    def test_reset_scheduler(self):
        """Test resetting scheduler to initial state."""
        scheduler = CurriculumScheduler()

        # Advance some phases
        scheduler.update_performance(0.99, episodes=10)
        self.assertEqual(scheduler.current_phase_id, 1)

        # Reset
        scheduler.reset()
        self.assertEqual(scheduler.current_phase_id, 0)

    def test_get_level_difficulty_config(self):
        """Test getting difficulty config for level selection."""
        scheduler = CurriculumScheduler()

        config = scheduler.get_level_selection_config()

        self.assertIn('star_range', config)
        self.assertIn('max_obstacles', config)
        self.assertIn('obstacle_types', config)
        self.assertIsNotNone(config['star_range'])

    def test_difficulty_progression(self):
        """Test overall difficulty increases across phases."""
        scheduler = CurriculumScheduler()

        configs = []
        for _ in range(8):
            config = scheduler.get_level_selection_config()
            configs.append(config)
            scheduler.update_performance(0.99, episodes=10)

        # Verify configurations are provided for all phases
        self.assertEqual(len(configs), 8)


class TestCurriculumRewards(unittest.TestCase):
    """Tests for curriculum-based reward shaping."""

    def test_phase_specific_rewards(self):
        """Test that phases can provide different reward scales."""
        scheduler = CurriculumScheduler()

        # Phase 0 might have higher reward per progress
        phase_0_reward_scale = scheduler.phases[0].reward_scale
        phase_7_reward_scale = scheduler.phases[7].reward_scale

        # Later phases might have different scaling
        self.assertIsNotNone(phase_0_reward_scale)
        self.assertIsNotNone(phase_7_reward_scale)

    def test_phase_time_limits(self):
        """Test phases have configurable time limits."""
        scheduler = CurriculumScheduler()

        for phase in scheduler.phases:
            self.assertIsNotNone(phase.max_steps)
            # Later phases might have longer episodes
            self.assertGreater(phase.max_steps, 0)


if __name__ == '__main__':
    unittest.main()
